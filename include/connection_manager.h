#ifndef CONNECTION_MANAGER_H_
#define CONNECTION_MANAGER_H_
int control_socket, router_socket, data_socket;
void init();
void addRouterSocketToList();
void sendRouterUpdates();
void setTimerValue(int timervalue);
void extract_Routing_Update(char *rout_update_info);

void update_rcall_miss_info(uint16_t router_id);
void initialize_routerids_count(uint16_t neighbors[5],int noofneighbors);
void reset_router_rcall_count(uint16_t router_id,int time);
void handle_timer_interrupt();
void addDataSocketToList();
int new_data_conn(int sock_index);
void calc_new_timer_value();
void receive_data_message(int sock_index);
void relay_file(uint32_t ip_addr, uint8_t t_id, uint8_t ttl, uint16_t seq_no,uint16_t port,uint32_t dest_addr,char *pay_buff,uint32_t fin_bit);
void remove_data_conn(int sock_index);
#endif