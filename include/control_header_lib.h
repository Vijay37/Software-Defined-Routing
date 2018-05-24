#ifndef CONTROL_HANDLER_LIB_H_
#define CONTROL_HANDLER_LIB_H_

#define CNTRL_HEADER_SIZE 8
#define CNTRL_RESP_HEADER_SIZE 8
#define INFINITY 65535
#define PACKET_USING_STRUCT // Comment this out to use alternate packet crafting technique

#ifdef PACKET_USING_STRUCT
    struct __attribute__((__packed__)) eCONTROL_HEADER
    {
        uint32_t dest_ip_addr;
        uint8_t control_code;
        uint8_t response_time;
        uint16_t payload_len;
    };

    struct __attribute__((__packed__)) CONTROL_RESPONSE_HEADER
    {
        uint32_t controller_ip_addr;
        uint8_t control_code;
        uint8_t response_code;
        uint16_t payload_len;
    };
    struct __attribute__((__packed__)) CONTROL_PAYLOAD{
        uint16_t router_Id;
        uint16_t router_Port;
        uint16_t data_Port;
        uint16_t link_Cost;
        uint32_t router_Addr;
    };
    struct __attribute__((__packed__)) INIT_STRUCT
    {
        uint16_t router_Id;
        uint16_t rout_port;
        uint16_t data_port;
        uint16_t link_cost;
        uint32_t ip_addr;
        uint16_t next_hop_id;
    };
    struct __attribute__((__packed__)) HOST_DETAILS
    {
        uint16_t router_Id;
        uint16_t rout_port;
        uint16_t data_port;
        uint32_t ip_addr;
    };
    struct __attribute__((__packed__)) NEIGH_DV
    {
        uint16_t router_Id;
        uint16_t cost;
    };
    struct __attribute__((__packed__)) NEIG_DETAILS
    {
        uint16_t router_Id;
        uint16_t rout_port;
        uint16_t data_port;
        uint32_t ip_addr;
        uint16_t cost;
        int sock_id;
        struct NEIGH_DV dv_det[5];
    };
    struct __attribute__((__packed__)) ROUTING_TABLE
    {
        uint16_t router_Id;
        uint16_t padding;
        uint16_t next_HopId;
        uint16_t cost;
    };
    struct __attribute__((__packed__)) ROUTING_PACKET_ROUTER
    {
        uint32_t ip_addr;
        uint16_t rout_port;
        uint16_t padding;
        uint16_t rout_id;
        uint16_t link_cost;
    };
    struct __attribute__((__packed__)) ROUTING_PACKET_COMPLETE
    {
        uint16_t tot_updates;
        uint16_t rout_port;
        uint32_t ip_addr;
        struct ROUTING_PACKET_ROUTER rout_details[5];
    };
    struct __attribute__((__packed__)) SEND_CONTROL_PAYLOAD
    {
        uint32_t ip_addr;
        uint8_t ttl;
        uint8_t t_id;
        uint16_t seq_number;
        char file[100];
    };
    struct __attribute__((__packed__)) SEND_FILE_PACKET
    {
        uint32_t ip_addr;
        uint8_t ttl;
        uint8_t t_id;
        uint16_t seq_number;
        uint16_t fin_bit;
        uint16_t padding;
        char payload[1024];
    };
    struct __attribute__((__packed__)) STATS_PACKET
    {
        uint8_t t_id;
        uint8_t ttl;
        uint16_t start_seq_number;
        uint16_t seq_nos[10485760];
        uint16_t end_seq_number;
    };
#endif
char* create_response_header(int sock_index, uint8_t control_code, uint8_t response_code, uint16_t payload_len);
char* createRouterUpdate();
void success_response(int sock_index,int control_code);
void update_response(int sock_index, char *cntrl_payload);
void update_link_cost(uint16_t rId, uint16_t cost);
void crash_response(int sock_index);
void control_response(int sock_index,int control_response_code);
int create_data_sock();
void send_file(uint32_t ip_addr, uint8_t t_id, uint8_t ttl, uint16_t seq_no,char *filename, uint16_t port,uint32_t dest_addr);
char *convert_ip(uint32_t ip);
void send_file(uint32_t ip_addr, uint8_t t_id, uint8_t ttl, uint16_t seq_no,char *filename, uint16_t port,uint32_t dest_addr);
bool isData(int sock_index);
void transfer_file(int sockfd,char *filename, uint8_t t_id, uint8_t ttl, uint16_t seq_no,uint32_t dest_addr);
struct INIT_STRUCT get_rout_details(uint32_t ip_addr);
int is_dest_host(uint32_t ip_addr);
void update_stats(uint8_t t_id,uint8_t ttl,uint16_t seq_no,uint32_t fin_bit);
void send_stats_response(int sock_index,char *cntrl_payload);
void update_last_pkt(uint32_t dest_addr,uint8_t t_id,uint8_t ttl,uint16_t seq_no,uint32_t fin_bit,char *data);
void send_pen_pkt_response(int sock_index);
void send_last_pkt_response(int sock_index)
#endif