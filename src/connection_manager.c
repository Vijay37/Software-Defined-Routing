/**
 * @vijayaha_assignment3
 * @author  Vijaya harshavardhan Palla <vijayaha@buffalo.edu>
 * @version 1.0
 *
 * @section LICENSE
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details at
 * http://www.gnu.org/copyleft/gpl.html
 *
 * @section DESCRIPTION
 *
 *
 */

/**
 *
 */
#include <sys/select.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include<arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include "../include/connection_manager.h"
#include "../include/global.h"
#include "../include/network_util.h"
#include "../include/control_handler.h"
#include "../include/control_header_lib.h"
fd_set master_list, watch_list;
int head_fd;
int static_timer=1000;
struct timeval tv,start_time;
char buffer[1000];
struct sockaddr_storage src_addr;
socklen_t src_addr_len;
int to_sock_fd=0;
bool file_opened=FALSE;
FILE *to_file;
void main_loop()
{
    int selret, sock_index, fdaccept;
    while(TRUE) {
        watch_list = master_list;
        selret = select(head_fd + 1, &watch_list, NULL, NULL, &tv);
        if (selret < 0) ERROR("select failed.");
        if (selret == 0) {
            printf("Timer interrupt occurred\n");
            //timer interrupt occurred
            sendRouterUpdates();
            tv.tv_sec = static_timer;
            tv.tv_usec = 0;
        }
        /* Loop through file descriptors to check which ones are ready */
        for (sock_index = 0; sock_index <= head_fd; sock_index += 1) {

            if (FD_ISSET(sock_index, &watch_list)) {

                /* control_socket */
                if (sock_index == control_socket) {
                    fdaccept = new_control_conn(sock_index);

                    /* Add to watched socket list */
                    FD_SET(fdaccept, &master_list);
                    if (fdaccept > head_fd) head_fd = fdaccept;
                }

                    /* router_socket */
                else if (sock_index == router_socket) {
                    //call handler that will call recvfrom() .....
                    printf("200: Routing update received\n");

                    src_addr_len = sizeof(src_addr);
                    recvfrom(sock_index, buffer, sizeof(buffer), 0, (struct sockaddr *) &src_addr,
                             &src_addr_len);
                    extract_Routing_Update(buffer);
                }

                    /* data_socket */
                else if (sock_index == data_socket) {
                    printf("200: TCP Connection received at data socket\n");
                    fdaccept = new_data_conn(sock_index);
                    FD_SET(fdaccept, &master_list);
                    if (fdaccept > head_fd) head_fd = fdaccept;
                }

                    /* Existing connection */
                else {
                    if (isControl(sock_index)) {
                        if (!control_recv_hook(sock_index)) FD_CLR(sock_index, &master_list);
                    } else if (isData(sock_index)) {
                        receive_data_message(sock_index);
                    } else ERROR("Unknown socket index");
                }
            }

        }


    }
}

void receive_data_message(int sock_index){
    int nbytes;
    char *recv_buffer=(char *)malloc(1036);
    char *payload=(char *)malloc(1024);
    nbytes=recvALL(sock_index,recv_buffer,1036);
    if(nbytes<0){
        FD_CLR(sock_index, &master_list);
        return;
    }
    uint32_t dest_addr,fin_bit;
    uint16_t seq_no;
    uint8_t ttl,t_id;
    memcpy(&dest_addr,recv_buffer,4);
    memcpy(&t_id,recv_buffer+4,1);
    memcpy(&ttl,recv_buffer+5,1);
    memcpy(&seq_no,recv_buffer+6,2);
    memcpy(&fin_bit,recv_buffer+8,4);
    memcpy(payload,recv_buffer+12,1024);
    if(ttl==0)
        return;
    ttl--;
    if(ttl==0)
        return;
    struct INIT_STRUCT router_info=get_rout_details(dest_addr);
    if(is_dest_host(dest_addr)==1){
        relay_file(router_info.ip_addr,t_id,ttl,seq_no,router_info.data_port,dest_addr,payload,fin_bit);
    }
    else {

        if(!file_opened){
            char file[100] = "file-";
            char ext[100];
            sprintf(ext,"%u",t_id);
            strcat(file,ext);
            to_file = fopen(file, "a");
            file_opened=TRUE;
        }
        fwrite(payload, 1024, 1, to_file);
        if((fin_bit)!=0) {
            fclose(to_file);
            file_opened=FALSE;
        }
    }
    update_stats(t_id,ttl,ntohs(seq_no),(fin_bit));
    uint16_t padding=0;
    update_last_pkt(dest_addr,t_id, ttl,seq_no,fin_bit,payload);
    free(payload);
    free(recv_buffer);


}
void relay_file(uint32_t ip_addr, uint8_t t_id, uint8_t ttl, uint16_t seq_no,uint16_t port,uint32_t dest_addr,char *pay_buff,uint32_t fin_bit){
    char *toaddr=convert_ip(ip_addr);
    char toport[100];
    sprintf(toport,"%lu",port);
    struct addrinfo hints;
    memset(&hints,0,sizeof(hints));
    hints.ai_family=AF_UNSPEC;
    hints.ai_socktype=SOCK_STREAM;
    hints.ai_protocol=0;
    hints.ai_flags=AI_ADDRCONFIG;
    struct addrinfo* res=0;
    if(to_sock_fd==0) {
        int err = getaddrinfo(toaddr, toport, &hints, &res);
        if (err != 0) {
            printf("401: failed to resolve remote socket address (err=%d)\n", err);
        }
        to_sock_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (to_sock_fd == -1) {
            printf("401: Failed to create socket\n");
        }
        if (connect(to_sock_fd, res->ai_addr, res->ai_addrlen) == -1) {
            printf("401: Failed to connect\n");
        }
        freeaddrinfo(res);
    }
        char *send_buffer = (char *) malloc(1036);
        memcpy(send_buffer, &dest_addr, 4);
        memcpy(send_buffer + 4, &t_id, 1);
        memcpy(send_buffer + 5, &ttl, 1);
        memcpy(send_buffer + 6, &seq_no, 2);
        memcpy(send_buffer + 8, &fin_bit, 4);
        memcpy(send_buffer + 12, pay_buff, 1024);
        sendALL(to_sock_fd, send_buffer, 1036);
        free(send_buffer);
        if(ntohl(fin_bit)!=0) {
            close(to_sock_fd);
            to_sock_fd = 0;
            printf("202: Closing socket connection\n");
        }


}
void init()
{
    control_socket = create_control_sock();

    //router_socket and data_socket will be initialized after INIT from controller

    FD_ZERO(&master_list);
    FD_ZERO(&watch_list);
    printf("202: Version 1.0\n");
    /* Register the control socket */
    FD_SET(control_socket, &master_list);
    head_fd = control_socket;
    gettimeofday(&start_time,NULL);
    tv.tv_sec=static_timer;
    tv.tv_usec=0;
    main_loop();
}
void addRouterSocketToList(){
    FD_SET(router_socket, &master_list);
    if(router_socket > head_fd) head_fd = router_socket;
}
void addDataSocketToList(){
    FD_SET(data_socket, &master_list);
    if(data_socket > head_fd) head_fd = data_socket;
}
void setTimerValue(int timervalue){
    static_timer=timervalue;
    tv.tv_sec=static_timer;
    tv.tv_usec=0;
}

