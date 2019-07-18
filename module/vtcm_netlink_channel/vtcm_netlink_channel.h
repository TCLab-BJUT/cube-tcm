#ifndef VTCM_NETLINK_CHANNEL_H
#define VTCM_NETLINK_CHANNEL_H

enum proc_conn_state
{
	PROC_CONN_START=0x1000,
	PROC_CONN_SYNC,
	PROC_CONN_ACKSEND,
	PROC_CONN_ACKRECV,
	PROC_CONN_CHANNELBUILD,
	PROC_CONN_FAIL,
};

static NAME2VALUE conn_state_list[]=
{
	{"start",PROC_CONN_START},
	{"sync",PROC_CONN_SYNC},
	{"acksend",PROC_CONN_ACKSEND},
	{"ackrecv",PROC_CONN_ACKRECV},
	{"channelbuild",PROC_CONN_CHANNELBUILD},
	{"fail",PROC_CONN_FAIL},
	{NULL,0}
};

int proc_conn_start(void * this_proc,void * para);
int proc_conn_accept(void * this_proc,void * msg,void * conn);
int proc_conn_sync(void * this_proc,void * msg,void * conn);
int proc_conn_acksend(void * this_proc,void * msg,void * conn);
int proc_conn_channelbuild(void * this_proc,void * msg,void * conn);

int vtcm_netlink_channel_init(void * sub_proc,void * para);
int vtcm_netlink_channel_start(void * sub_proc,void * para);

struct netlink_init_para
{
	char * channel_name;
}__attribute__((packed));
#endif
