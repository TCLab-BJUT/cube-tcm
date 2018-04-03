#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <dirent.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "data_type.h"
#include "errno.h"
#include "alloc.h"
#include "list.h"
#include "attrlist.h"
#include "memfunc.h"
#include "basefunc.h"
#include "struct_deal.h"
#include "crypto_func.h"
#include "memdb.h"
#include "message.h"
#include "ex_module.h"
#include "sys_func.h"

#include "tcm_constants.h"
#include "app_struct.h"
#include "vtcm_struct.h"
#include "vtcm_manager.h"



int proc_vtcmutils_start(void * sub_proc,void * para);

// proceed the vtcm command 
int vtcmutils_transmit(int in_len,BYTE * in, int *  out_len, BYTE * out);

BYTE Buf[256];

int vtcm_manager_init(void * sub_proc,void * para)
{
	struct manager_vtcm_buffer * vtcm_buffer;
	vtcm_buffer=Talloc0(sizeof(*vtcm_buffer));

	if(vtcm_buffer==NULL)
	{
		return -ENOMEM;		
	}
	
	vtcm_buffer->instance_num=0;
	INIT_LIST_HEAD(&vtcm_buffer->msg_buffer.list);
	vtcm_buffer->vtcm_list.vtcm_copy_num=2;
	vtcm_buffer->vtcm_list.vtcm_copy=Talloc0(sizeof(struct vtcm_copy)*vtcm_buffer->vtcm_list.vtcm_copy_num);	

	ex_module_setpointer(sub_proc,vtcm_buffer);
	return 0;
}

int vtcm_manager_start(void * sub_proc,void * para)
{
	int ret;
	int retval;
	void * recv_msg;
	void * send_msg;
	void * context;
	void * sock;
	BYTE uuid[DIGEST_SIZE];
	int i;
	int type;
	int subtype;

	while(1)
	{
		usleep(time_val.tv_usec);
		ret=ex_module_recvmsg(sub_proc,&recv_msg);
		if(ret<0)
			continue;
		if(recv_msg==NULL)
			continue;

 		type=message_get_type(recv_msg);
		subtype=message_get_subtype(recv_msg);
		ret=proc_vtcm_msgqueue(sub_proc,recv_msg);		
		if(ret<0)
			break;
		proc_vtcm_dispatch(sub_proc);
	}
	return 0;
};


int proc_vtcm_msgqueue(void * sub_proc,void * recv_msg)
{
	int ret = 0;
	int i=0;
	MSG_EXPAND * define_expand;
	struct uuid_record * uuid_rec;
	ret=message_remove_expand(recv_msg,DTYPE_MESSAGE,SUBTYPE_UUID_RECORD,&define_expand);
	if(ret<0)
		return ret;
	if(define_expand==NULL)
		return 0;
	uuid_rec=define_expand->expand;

	ret=vtcm_add_msg(sub_proc,recv_msg,uuid_rec->uuid);

	return ret;
}
int proc_vtcm_dispatch(void * sub_proc)
{
	vtcm_select_copy(sub_proc);
	vtcm_dispatch(sub_proc);
	return 0;
}
