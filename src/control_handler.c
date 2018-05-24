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

#include <sys/socket.h>
#include <netinet/in.h>
#include <strings.h>
#include <sys/queue.h>
#include <unistd.h>
#include<arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include "../include/global.h"
#include "../include/network_util.h"
#include "../include/connection_manager.h"
#include "../include/control_header_lib.h"
#include "../include/author.h"

#ifndef PACKET_USING_STRUCT
#define CNTRL_CONTROL_CODE_OFFSET 0x04
#define CNTRL_PAYLOAD_LEN_OFFSET 0x06
#endif

/* Linked List for active control connections */
uint16_t timerValue,tot_routers;
struct ROUTING_TABLE routingTable;
struct INIT_STRUCT rout_details[5];
struct HOST_DETAILS host_info;
struct NEIG_DETAILS neig_details[5];
struct STATS_PACKET stats_details[5];
int no_of_files=0;
int noOfNeighbors=0;
char *pen_pkt;
char *last_pkt;
struct ControlConn
{
    int sockfd;
    LIST_ENTRY(ControlConn) next;
}*connection, *conn_temp;
LIST_HEAD(ControlConnsHead, ControlConn) control_conn_list,data_conn_list;

int create_control_sock()
{
    int sock;
    struct sockaddr_in control_addr;
    socklen_t addrlen = sizeof(control_addr);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0)
    ERROR("socket() failed");

    /* Make socket re-usable */
    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (int[]){1}, sizeof(int)) < 0)
    ERROR("setsockopt() failed");

    bzero(&control_addr, sizeof(control_addr));

    control_addr.sin_family = AF_INET;
    control_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    control_addr.sin_port = htons(CONTROL_PORT);

    if(bind(sock, (struct sockaddr *)&control_addr, sizeof(control_addr)) < 0)
    ERROR("bind() failed");

    if(listen(sock, 5) < 0)
    ERROR("listen() failed");

    LIST_INIT(&control_conn_list);

    return sock;
}
int create_data_sock()
{
    int sock;
    struct sockaddr_in control_addr;
    socklen_t addrlen = sizeof(control_addr);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0)
    ERROR("socket() failed");

    /* Make socket re-usable */
    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (int[]){1}, sizeof(int)) < 0)
    ERROR("setsockopt() failed");

    bzero(&control_addr, sizeof(control_addr));

    control_addr.sin_family = AF_INET;
    control_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    control_addr.sin_port = htons(host_info.data_port);

    if(bind(sock, (struct sockaddr *)&control_addr, sizeof(control_addr)) < 0) {
        ERROR("bind() failed");
        exit(0);
    }
    else
    printf("200: Data socket created\n");
    if(listen(sock, 5) < 0)
    ERROR("listen() failed");

    LIST_INIT(&data_conn_list);

    return sock;
}

int new_control_conn(int sock_index)
{
    int fdaccept, caddr_len;
    struct sockaddr_in remote_controller_addr;

    caddr_len = sizeof(remote_controller_addr);
    fdaccept = accept(sock_index, (struct sockaddr *)&remote_controller_addr, &caddr_len);
    if(fdaccept < 0)
    ERROR("accept() failed");

    /* Insert into list of active control connections */
    connection = malloc(sizeof(struct ControlConn));
    connection->sockfd = fdaccept;
    LIST_INSERT_HEAD(&control_conn_list, connection, next);

    return fdaccept;
}
int new_data_conn(int sock_index)
{
    int fdaccept, caddr_len;
    struct sockaddr_in remote_controller_addr;

    caddr_len = sizeof(remote_controller_addr);
    fdaccept = accept(sock_index, (struct sockaddr *)&remote_controller_addr, &caddr_len);
    if(fdaccept < 0)
    ERROR("accept() failed");

    /* Insert into list of active control connections */
    connection = malloc(sizeof(struct ControlConn));
    connection->sockfd = fdaccept;
    LIST_INSERT_HEAD(&data_conn_list, connection, next);

    return fdaccept;
}

void remove_control_conn(int sock_index)
{
    LIST_FOREACH(connection, &control_conn_list, next) {
        if(connection->sockfd == sock_index) LIST_REMOVE(connection, next); // this may be unsafe?
        free(connection);
    }

    close(sock_index);
}
bool isControl(int sock_index)
{
    LIST_FOREACH(connection, &control_conn_list, next)
        if(connection->sockfd == sock_index) return TRUE;

    return FALSE;
}
bool isData(int sock_index)
{
    LIST_FOREACH(connection, &data_conn_list, next)
        if(connection->sockfd == sock_index) return TRUE;

    return FALSE;
}
bool control_recv_hook(int sock_index)
{
    char *cntrl_header, *cntrl_payload;
    uint8_t control_code;
    uint16_t payload_len;

    /* Get control header */
    cntrl_header = (char *) malloc(sizeof(char)*CNTRL_HEADER_SIZE);
    bzero(cntrl_header, CNTRL_HEADER_SIZE);

    if(recvALL(sock_index, cntrl_header, CNTRL_HEADER_SIZE) < 0){
        remove_control_conn(sock_index);
        free(cntrl_header);
        return FALSE;
    }

        /* Get control code and payload length from the header */
#ifdef PACKET_USING_STRUCT
    /** ASSERT(sizeof(struct CONTROL_HEADER) == 8)
      * This is not really necessary with the __packed__ directive supplied during declaration (see control_header_lib.h).
      * If this fails, comment #define PACKET_USING_STRUCT in control_header_lib.h
      */
    BUILD_BUG_ON(sizeof(struct CONTROL_HEADER) != CNTRL_HEADER_SIZE); // This will FAIL during compilation itself; See comment above.

    struct CONTROL_HEADER *header = (struct CONTROL_HEADER *) cntrl_header;
    control_code = header->control_code;
    payload_len = ntohs(header->payload_len);
#endif
#ifndef PACKET_USING_STRUCT
    memcpy(&control_code, cntrl_header+CNTRL_CONTROL_CODE_OFFSET, sizeof(control_code));
        memcpy(&payload_len, cntrl_header+CNTRL_PAYLOAD_LEN_OFFSET, sizeof(payload_len));
        payload_len = ntohs(payload_len);
#endif

    free(cntrl_header);

    /* Get control payload */
    if(payload_len != 0){
        cntrl_payload = (char *) malloc(sizeof(char)*payload_len);
        bzero(cntrl_payload, payload_len);

        if(recvALL(sock_index, cntrl_payload, payload_len) < 0){
            remove_control_conn(sock_index);
            free(cntrl_payload);
            return FALSE;
        }

    }

    /* Triage on control_code */
    switch(control_code){
        case 0: author_response(sock_index);
            break;


        case 1: init_response(sock_index, cntrl_payload);
            break;

        case 2: routTable_response(sock_index);
            break;

        case 3: update_response(sock_index,cntrl_payload);
            break;

        case 4: crash_response(sock_index);
            break;

        case 5: send_file_response(sock_index,cntrl_payload,payload_len);
             break;

        case 6: send_stats_response(sock_index,cntrl_payload);
            break;
        case 7: send_last_pkt_response(sock_index);
            break;
        case 8: send_pen_pkt_response(sock_index);
            break;
    }

    if(payload_len != 0) free(cntrl_payload);
    return TRUE;
}
void send_last_pkt_response(int sock_index){
    uint16_t payload_len, response_len;
    char *cntrl_response_header, *cntrl_response_payload, *cntrl_response;

    payload_len = 1036;
    cntrl_response_payload = (char *) malloc(payload_len);
    memcpy(cntrl_response_payload, last_pkt, payload_len);
    cntrl_response_header = create_response_header(sock_index, 7, 0, payload_len);
    response_len = CNTRL_RESP_HEADER_SIZE+payload_len;
    cntrl_response = (char *) malloc(response_len);
    /* Copy Header */
    memcpy(cntrl_response, cntrl_response_header, CNTRL_RESP_HEADER_SIZE);
    free(cntrl_response_header);
    /* Copy Payload */
    memcpy(cntrl_response+CNTRL_RESP_HEADER_SIZE, cntrl_response_payload, payload_len);
    free(cntrl_response_payload);

    sendALL(sock_index, cntrl_response, response_len);
    free(cntrl_response);
}
void send_pen_pkt_response(int sock_index){
    uint16_t payload_len, response_len;
    char *cntrl_response_header, *cntrl_response_payload, *cntrl_response;

    payload_len = 1036;
    cntrl_response_payload = (char *) malloc(payload_len);
    memcpy(cntrl_response_payload, pen_pkt, payload_len);
    cntrl_response_header = create_response_header(sock_index, 8, 0, payload_len);
    response_len = CNTRL_RESP_HEADER_SIZE+payload_len;
    cntrl_response = (char *) malloc(response_len);
    /* Copy Header */
    memcpy(cntrl_response, cntrl_response_header, CNTRL_RESP_HEADER_SIZE);
    free(cntrl_response_header);
    /* Copy Payload */
    memcpy(cntrl_response+CNTRL_RESP_HEADER_SIZE, cntrl_response_payload, payload_len);
    free(cntrl_response_payload);

    sendALL(sock_index, cntrl_response, response_len);
    free(cntrl_response);
}
void send_stats_response(int sock_index,char *cntrl_payload){
    uint8_t t_id,ttl;
    int id_index;
    bool id_found=FALSE;
    memcpy(&t_id,cntrl_payload,1);
    uint16_t start_seq,end_seq,padding=0,seq_no;
    for(int index=0;index<no_of_files;index++){
        if(stats_details[index].t_id==t_id){
            start_seq=stats_details[index].start_seq_number;
            end_seq=stats_details[index].end_seq_number;
            ttl=stats_details[index].ttl;
            id_index=index;
            id_found=TRUE;
            break;
        }
    }
    uint16_t payload_len, response_len;
    char *cntrl_response_header, *cntrl_response_payload, *cntrl_response,*payload;
    if(id_found) {
        payload = (char *) malloc(4 + (end_seq + 1 - start_seq) * 2);
        padding = htons(padding);
        memcpy(payload, &t_id, 1);
        memcpy(payload + 1, &ttl, 1);
        memcpy(payload + 2, &padding, 2);
        int add = 0x04;
        for (int index = 0; index <= (end_seq - start_seq); index++) {
            seq_no = stats_details[id_index].seq_nos[index];
            seq_no = htons(seq_no);
            memcpy(payload + add + (index) * 2, &seq_no, 2);
        }
        memcpy(&seq_no, payload + add + (end_seq - start_seq) * 2, 2);
        payload_len = 4+(end_seq+1-start_seq)*2;
    }
    else {
        payload_len = 0;
        payload="";
    }
    cntrl_response_payload = (char *) malloc(payload_len);
    memcpy(cntrl_response_payload, payload, payload_len);
    cntrl_response_header = create_response_header(sock_index, 6, 0, payload_len);
    response_len = CNTRL_RESP_HEADER_SIZE+payload_len;
    cntrl_response = (char *) malloc(response_len);
    /* Copy Header */
    memcpy(cntrl_response, cntrl_response_header, CNTRL_RESP_HEADER_SIZE);
    free(cntrl_response_header);
    /* Copy Payload */
    memcpy(cntrl_response+CNTRL_RESP_HEADER_SIZE, cntrl_response_payload, payload_len);
    free(cntrl_response_payload);

    sendALL(sock_index, cntrl_response, response_len);
    free(payload);
    free(cntrl_response);


}
void send_file_response(int sock_index, char *cntrl_payload,uint16_t payload_len){
    struct SEND_CONTROL_PAYLOAD *packet = (struct SEND_CONTROL_PAYLOAD *) cntrl_payload;
    uint32_t ip_addr=packet->ip_addr;
    uint8_t t_id=packet->t_id;
    uint8_t ttl=packet->ttl;
    uint16_t seq_no=packet->seq_number;
    char file_name[100];
    strcpy(file_name,cntrl_payload+8);
    file_name[payload_len-8]='\0';
    uint16_t next_hop_id,port;
    uint32_t next_hop_addr;
    int sock_id;
    seq_no=ntohs(seq_no);
    for(int index=0;index<tot_routers;index++){
        if(rout_details[index].ip_addr==ip_addr){
            next_hop_id=rout_details[index].next_hop_id;
            break;
        }
    }
    for(int index=0;index<tot_routers;index++){
        if(rout_details[index].router_Id==next_hop_id){
            next_hop_addr=rout_details[index].ip_addr;
            port = rout_details[index].data_port;
            break;
        }
    }
    send_file(next_hop_addr,t_id,ttl,seq_no,file_name,port,ip_addr);
    control_response(sock_index,5);
}
void send_file(uint32_t ip_addr, uint8_t t_id, uint8_t ttl, uint16_t seq_no,char *filename, uint16_t port,uint32_t dest_addr){
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
    int err=getaddrinfo(toaddr,toport,&hints,&res);
    if (err!=0) {
        printf("401: failed to resolve remote socket address (err=%d)\n",err);
    }
    int fd=socket(res->ai_family,res->ai_socktype,res->ai_protocol);
    if (fd==-1) {
        printf("401: Failed to create socket\n");
    }
    if (connect(fd,res->ai_addr,res->ai_addrlen)==-1) {
        printf("401: Failed to connect\n");
    }
    freeaddrinfo(res);
    printf("200: Connection established");
    transfer_file(fd,filename,  t_id,  ttl,  seq_no,dest_addr);
}
void transfer_file(int sockfd,char *filename, uint8_t t_id, uint8_t ttl, uint16_t seq_no,uint32_t dest_addr){
    FILE *fileptr;
    char *buffer;
    long filelen;
    int buff_size=1024;
    fileptr = fopen(filename, "rb");
    if(fileptr==NULL)
        return;
    //https://stackoverflow.com/questions/22059189/read-a-file-as-byte-array
    //Reason: Reaches the end of the file to find the length of the file
    fseek(fileptr, 0, SEEK_END);          // Jump to the end of the file
    filelen = ftell(fileptr);             // Get the current byte offset in the file
    rewind(fileptr);                      // Jump back to the beginning of the file
    printf("202: File size:%li\n",filelen);
    buffer = (char *)malloc((filelen+1)*sizeof(char)); // Enough memory for file + \0
    fread(buffer, filelen, 1, fileptr); // Read in the entire file
    char *send_buffer=(char *)malloc(1024+12);


    int loop_size=filelen/buff_size;
    int index;
    uint32_t fin_bit;
    fin_bit=0;
    fin_bit=htons(fin_bit);
    uint16_t send_seq;
    stats_details[no_of_files].t_id=t_id;
    stats_details[no_of_files].ttl=ttl;
    stats_details[no_of_files].start_seq_number=seq_no;
    for(int index=0;index<loop_size;index++){
        stats_details[no_of_files].seq_nos[index]=seq_no;
        send_seq=htons(seq_no);
        seq_no++;
        memcpy(send_buffer,&dest_addr,4);
        memcpy(send_buffer+4,&t_id,1);
        memcpy(send_buffer+5,&ttl,1);
        memcpy(send_buffer+6,&send_seq,2);
        if(index==loop_size-1){
            fin_bit = 1;
            fin_bit=fin_bit<<31;
        }
        memcpy(send_buffer+8,&fin_bit,4);
        memcpy(send_buffer+12,buffer+(1024*index),1024);
        sendALL(sockfd,send_buffer,1036);
        update_last_pkt(dest_addr,t_id, ttl,send_seq,fin_bit,buffer+(1024*index));
    }
    stats_details[no_of_files].end_seq_number=seq_no-1;
    no_of_files++;
    free(send_buffer);
    free(buffer);
    printf("202: File sent\n");
    fclose(fileptr); // Close the file

}
// source: https://stackoverflow.com/questions/5328070/how-to-convert-string-to-ip-address-and-vice-versa
// Reason: To convert unsigned ip address to a ip address of format xx.xx.xx
char *convert_ip(uint32_t ip){
    struct in_addr ip_addr;
    ip_addr.s_addr = ip;
    char *host_addr;
    host_addr=inet_ntoa(ip_addr);
    return host_addr;
}
void crash_response(int sock_index){
    control_response(sock_index,4);
    exit(0);
}
void control_response(int sock_index,int control_response_code){
    uint16_t payload_len, response_len;
    char *cntrl_response_header,*cntrl_response;
    payload_len = 0; // Discount the NULL chararcter
    cntrl_response_header = create_response_header(sock_index, control_response_code, 0, payload_len);
    response_len = CNTRL_RESP_HEADER_SIZE;
    cntrl_response = (char *) malloc(response_len);
    /* Copy Header */
    memcpy(cntrl_response, cntrl_response_header, CNTRL_RESP_HEADER_SIZE);
    free(cntrl_response_header);
    sendALL(sock_index, cntrl_response, response_len);
    free(cntrl_response);
}
void update_response(int sock_index, char *cntrl_payload){
    uint16_t rId,rCost;
    memcpy(&rId,cntrl_payload,2);
    memcpy(&rCost,cntrl_payload+2,2);
    rId=ntohs(rId);
    rCost=ntohs(rCost);
    update_link_cost(rId, rCost);
    control_response(sock_index,3);
}
void update_link_cost(uint16_t rId, uint16_t cost){
    printf("202: Update link cost of %u to %u\n",rId,cost);
    uint32_t prev_cost,tot_cost,id,curr_cost,dv_id;
    int recv_index;

    for(int index=0;index<noOfNeighbors;index++){
        if(neig_details[index].router_Id==rId){
            prev_cost=neig_details[index].cost;
            neig_details[index].cost=cost;
            recv_index=index;
            break;
        }
    }
    for(int index=0;index<tot_routers;index++){
        if(rout_details[index].router_Id==rId){
            rout_details[index].next_hop_id=rId;
            rout_details[index].link_cost=cost;
        }
    }
        for(int index=0;index<tot_routers;index++){
            id=rout_details[index].router_Id;
            curr_cost=rout_details[index].link_cost;
            if(id!=host_info.router_Id){
                for(int index2=0;index2<tot_routers;index2++){
                    if(id==neig_details[recv_index].dv_det[index2].router_Id){
                        if(cost==INFINITY && rout_details[index].next_hop_id==rId){
                            rout_details[index].next_hop_id==INFINITY;
                            rout_details[index].link_cost=INFINITY;
                        }
                        else {
                            tot_cost = cost + neig_details[recv_index].dv_det[index2].cost;
                            if (tot_cost < curr_cost || rout_details[index].next_hop_id == rId) {
                                rout_details[index].link_cost = tot_cost;
                                rout_details[index].next_hop_id = rId;
                            }
                        }
                        break;
                    }
                }
            }
        }
}
void init_response(int sock_index, char *cntrl_payload){
    printf("1: Received INIT control message\n");
    memcpy(&tot_routers,cntrl_payload,2);
    memcpy(&timerValue,cntrl_payload+0x02,2);
    tot_routers=ntohs(tot_routers);
    timerValue=ntohs(timerValue);
    setTimerValue(timerValue);
    create_RoutingTable(cntrl_payload);
    control_response(sock_index,1);

}
void create_RoutingTable(char *cntrl_payload){
    int add=0x04;
    for(int index=0;index<tot_routers;index++){
        memcpy(&rout_details[index].router_Id,cntrl_payload+add,2);
        rout_details[index].router_Id=ntohs(rout_details[index].router_Id);
        add=add+2;
        memcpy(&rout_details[index].rout_port,cntrl_payload+add,2);
        rout_details[index].rout_port=ntohs(rout_details[index].rout_port);
        add=add+2;
        memcpy(&rout_details[index].data_port,cntrl_payload+add,2);
        rout_details[index].data_port=ntohs(rout_details[index].data_port);
        add=add+2;
        memcpy(&rout_details[index].link_cost,cntrl_payload+add,2);
        rout_details[index].link_cost=ntohs(rout_details[index].link_cost);
        add=add+2;
        memcpy(&rout_details[index].ip_addr,cntrl_payload+add,4);
        if(rout_details[index].link_cost==0){
            host_info.router_Id=rout_details[index].router_Id;
            host_info.rout_port=rout_details[index].rout_port;
            host_info.data_port=rout_details[index].data_port;
            host_info.ip_addr=rout_details[index].ip_addr;
            rout_details[index].next_hop_id=rout_details[index].router_Id;
        }
        else if(rout_details[index].link_cost!=INFINITY){
            neig_details[noOfNeighbors].router_Id=rout_details[index].router_Id;
            neig_details[noOfNeighbors].rout_port=rout_details[index].rout_port;
            neig_details[noOfNeighbors].data_port=rout_details[index].data_port;
            neig_details[noOfNeighbors].ip_addr=rout_details[index].ip_addr;
            neig_details[noOfNeighbors].cost=rout_details[index].link_cost;
            printf("202: Neighbor ID:%u\n",neig_details[noOfNeighbors].router_Id);
            rout_details[index].next_hop_id=rout_details[index].router_Id;
            noOfNeighbors++;
        }
        else
            rout_details[index].next_hop_id=INFINITY;
        add=add+4;
    }
    createRouterSocket();
    data_socket=create_data_sock();
    addDataSocketToList();
}
// Source:http://www.binarytides.com/programming-udp-sockets-c-linux/
// Reason: To bind a socket to router port and create a router socket on which udp messages are received
void createRouterSocket(){
    struct sockaddr_in si_me, si_other;

    int i, slen = sizeof(si_other) , recv_len;

    //create a UDP socket
    if ((router_socket=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        printf("404: Unable to create UDP socket\n");
    }

    // zero out the structure
    memset((char *) &si_me, 0, sizeof(si_me));

    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(host_info.rout_port);
    si_me.sin_addr.s_addr = htonl(INADDR_ANY);

    //bind socket to port
    if( bind(router_socket, (struct sockaddr*)&si_me, sizeof(si_me) ) == -1)
    {
        printf("404: Unable to bind UDP socket\n");
        exit(0);
    }
    addRouterSocketToList();
}
//Source: Till here

void routTable_response(int sock_index){
    struct ROUTING_TABLE rout_table[tot_routers];
    for(int index=0;index<tot_routers;index++){
        rout_table[index].router_Id=htons(rout_details[index].router_Id);
        rout_table[index].cost=htons(rout_details[index].link_cost);
        rout_table[index].padding=htons(0);
        rout_table[index].next_HopId=htons(rout_details[index].next_hop_id);
    }
    uint16_t payload_len, response_len;
    char *cntrl_response_header, *cntrl_response_payload, *cntrl_response;

    payload_len = sizeof(rout_table);
    cntrl_response_payload = (char *) malloc(payload_len);
    memcpy(cntrl_response_payload, rout_table, payload_len);
    cntrl_response_header = create_response_header(sock_index, 2, 0, payload_len);
    response_len = CNTRL_RESP_HEADER_SIZE+payload_len;
    cntrl_response = (char *) malloc(response_len);
    /* Copy Header */
    memcpy(cntrl_response, cntrl_response_header, CNTRL_RESP_HEADER_SIZE);
    free(cntrl_response_header);
    /* Copy Payload */
    memcpy(cntrl_response+CNTRL_RESP_HEADER_SIZE, cntrl_response_payload, payload_len);
    free(cntrl_response_payload);

    sendALL(sock_index, cntrl_response, response_len);

    free(cntrl_response);
}
void sendRouterUpdates(){
    struct timeval tv1;
    gettimeofday(&tv1,NULL);
    printf("202: Sending router updates at:%u\n",tv1.tv_sec);
    uint16_t routerID,routerPort;
    uint32_t routerAddr;
    int fd;
    struct ROUTING_PACKET_COMPLETE router_packet=create_rout_packet();
    const char* host_addr;
    char* port_name;
    struct addrinfo hints;
    struct addrinfo* res=0;
    char temp[40];
    memset(&hints,0,sizeof(hints));
    hints.ai_family=AF_UNSPEC;
    hints.ai_socktype=SOCK_DGRAM;
    hints.ai_protocol=0;
    hints.ai_flags=AI_ADDRCONFIG;
    for(int index=0;index<noOfNeighbors;index++){
        routerAddr = neig_details[index].ip_addr;
        routerPort = neig_details[index].rout_port;
        sprintf(temp,"%lu",routerPort);
        port_name=temp;
        host_addr=convert_ip(routerAddr);
        printf("202: Sending update to : %s\n",host_addr);
        int err=getaddrinfo(host_addr,port_name,&hints,&res);
        if (err!=0) {
            printf("404: Failed to resolve remote socket address (err=%d)\n",err);
        }
        fd=socket(res->ai_family,res->ai_socktype,res->ai_protocol);
        if (sendto(fd,&router_packet,(8+tot_routers*12),0,res->ai_addr,res->ai_addrlen)==-1) {
            printf("404: Error sending UDP message\n");
        }
    }
}
struct ROUTING_PACKET_COMPLETE create_rout_packet(){
    struct ROUTING_PACKET_ROUTER router_info[5];
    struct ROUTING_PACKET_COMPLETE rout_packet;
    uint16_t tot_entries,padding;
    tot_entries=htons(tot_routers);
    rout_packet.tot_updates=tot_entries;
    rout_packet.ip_addr=(host_info.ip_addr);
    rout_packet.rout_port=htons(host_info.rout_port);
    for(int index=0;index<tot_routers;index++){
        padding=htons(0);
        rout_packet.rout_details[index].rout_port=htons(rout_details[index].rout_port);
        rout_packet.rout_details[index].ip_addr=(rout_details[index].ip_addr);
        rout_packet.rout_details[index].padding=padding;
        rout_packet.rout_details[index].link_cost=htons(rout_details[index].link_cost);
        rout_packet.rout_details[index].rout_id=htons(rout_details[index].router_Id);
    }
    return rout_packet;
}

void extract_Routing_Update(char *rout_update_info){
    struct ROUTING_PACKET_COMPLETE *packet = (struct ROUTING_PACKET_COMPLETE *) rout_update_info;
    printf("202: Extracting routing update\n");
    uint16_t totalUpdates,src_rout_port,recv_id,id;
    uint32_t curr_cost,tot_cost,nh_id,sender_cost;
    uint32_t src_addr,addr;
    uint16_t costMatrix[5][2];
    int recv_index;
    totalUpdates=ntohs(packet->tot_updates);
    src_addr=packet->ip_addr;
    for(int index=0;index<noOfNeighbors;index++){
        if(neig_details[index].ip_addr==src_addr){
            recv_id=neig_details[index].router_Id;
            recv_index=index;
            sender_cost=neig_details[index].cost;
            break;
        }
    }

    for(int index=0;index<totalUpdates;index++){
        id=packet->rout_details[index].rout_id;
        id=ntohs(id);
        costMatrix[index][0]=id;
        costMatrix[index][1]=packet->rout_details[index].link_cost;
        costMatrix[index][1]=ntohs(costMatrix[index][1]);
        neig_details[recv_index].dv_det[index].router_Id=id;
        neig_details[recv_index].dv_det[index].cost=costMatrix[index][1];
    }

    for(int index=0;index<tot_routers;index++){
        id=rout_details[index].router_Id;
        if(id==host_info.router_Id)
            continue;
        else{
            curr_cost=rout_details[index].link_cost;
            for(int dvIndex=0;dvIndex<totalUpdates;dvIndex++){
                if(id==neig_details[recv_index].dv_det[dvIndex].router_Id){
                    tot_cost=sender_cost+neig_details[recv_index].dv_det[dvIndex].cost;
                    if(tot_cost<=curr_cost){
                        rout_details[index].link_cost=tot_cost;
                        rout_details[index].next_hop_id=recv_id;
                    }
                }
            }
        }
    }
}

int is_dest_host(uint32_t ip_addr){
    if(host_info.ip_addr==ip_addr){
        return 0;
    }
    return 1;
}

struct INIT_STRUCT get_rout_details(uint32_t ip_addr){
    struct INIT_STRUCT router_info;
    uint16_t next_hop_id;
    for(int index=0;index<tot_routers;index++){
        if(rout_details[index].ip_addr==ip_addr){
            next_hop_id=rout_details[index].next_hop_id;
            break;
        }
    }
    for(int index=0;index<noOfNeighbors;index++){
        if(neig_details[index].router_Id==next_hop_id){
            router_info.ip_addr=neig_details[index].ip_addr;
            router_info.data_port=neig_details[index].data_port;
            return router_info;
        }
    }
}
void update_stats(uint8_t t_id,uint8_t ttl,uint16_t seq_no,uint32_t fin_bit){
    for(int index=0;index<no_of_files;index++){
        if(stats_details[index].t_id=t_id){
            if(fin_bit!=0) {
                stats_details[index].end_seq_number = seq_no;
            }
            stats_details[index].seq_nos[seq_no-stats_details[index].start_seq_number]=seq_no;
            return;
        }
    }
    stats_details[no_of_files].ttl=ttl;
    stats_details[no_of_files].start_seq_number=seq_no;
    stats_details[no_of_files].seq_nos[0]=seq_no;
    stats_details[no_of_files].t_id=t_id;
    no_of_files++;
    return;
}
void update_last_pkt(uint32_t dest_addr,uint8_t t_id,uint8_t ttl,uint16_t seq_no,uint32_t fin_bit,char *data){
    if((fin_bit)!=0) {
        fin_bit=1;
        fin_bit=fin_bit<<31;
        fin_bit=htonl(fin_bit);
        last_pkt=(char *)malloc(1036);
        memcpy(last_pkt,&dest_addr,4);
        memcpy(last_pkt+4,&t_id,1);
        memcpy(last_pkt+5,&ttl,1);
        memcpy(last_pkt+6,&seq_no,2);
        memcpy(last_pkt+8,&fin_bit,4);
        memcpy(last_pkt+12,data,1024);
    }
    else{
        pen_pkt=(char *)malloc(1036);
        memcpy(pen_pkt,&dest_addr,4);
        memcpy(pen_pkt+4,&t_id,1);
        memcpy(pen_pkt+5,&ttl,1);
        memcpy(pen_pkt+6,&seq_no,2);
        memcpy(pen_pkt+8,&fin_bit,4);
        memcpy(pen_pkt+12,data,1024);
    }
}
