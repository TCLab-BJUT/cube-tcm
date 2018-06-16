#ifndef VTCM_TCP_CLIENT_H
#define VTCM_TCP_CLIENT_H

int vtcm_tcp_client_init(void * sub_proc,void * para);
int vtcm_tcp_client_start(void * sub_proc,void * para);

struct tcp_init_para
{
	char * tcp_addr;
	int tcp_port;	
	char * channel_name;
}__attribute__((packed));

#endif
