#ifndef CONNECTOR_PROCESS_FUNC_H
#define CONNECTOR_PROCESS_FUNC_H


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

static char * connector_process_state_name[]=
{
	"start",
	"sync",
	"acksend",
	"ackrecv",
	"channelbuild",
	NULL
};
static char * connector_process_func_name[]=
{
	"start",
	"accept",
	"sync",
	"acksend",
	"channelbuild",
	NULL
};

static NAME2POINTER conn_func_list[]=
{
	{"start",&proc_conn_start},
	{"accept",&proc_conn_accept},
	{"sync",&proc_conn_sync},
	{"acksend",&proc_conn_acksend},
	{"channelbuild",&proc_conn_channelbuild},
	{NULL,0}
};

static struct timeval time_val={0,50*1000};
#endif
