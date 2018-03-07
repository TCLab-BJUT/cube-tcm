#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <dirent.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include "data_type.h"
#include "errno.h"
#include "alloc.h"
#include "string.h"
#include "basefunc.h"
#include "struct_deal.h"
#include "crypto_func.h"
#include "memdb.h"
#include "message.h"
#include "sys_func.h"
#include "ex_module.h"
#include "file_struct.h"
#include "tesi_key.h"
#include "tesi_aik_struct.h"
#include "vtcm_switch.h"
#include "app_struct.h"
#include "tcm_global.h"
#include "tcm_error.h"
#include "sm2.h"
#include "sm3.h"
#include "vtcm_struct.h"
#include "tcm_iolib.h"

struct vtcm_switch_scene* key_scenes;
static BYTE Buf[DIGEST_SIZE*128];
int proc_vtcm_init(void* sub_proc, void* recv_msg);
int proc_vtcm_import(void* sub_proc, void* recv_msg);
int proc_vtcm_export(void* sub_proc, void* recv_msg);

int vtcm_switch_init(void* sub_proc, void* para)
{
    printf("vtcm_switch_init :\n");
    tcm_state_t* tcm_instances = proc_share_data_getpointer();

 // ex_module_setpointer(sub_proc, key_scenes);
    return 0;
}

int vtcm_switch_start(void* sub_proc, void* para)
{
    int ret;
    void* recv_msg ;
    int type, subtype;
    BYTE uuid[DIGEST_SIZE];

    printf("vtcm_switch module start!\n");

    while(1){
        usleep(time_val.tv_usec);
        ret = ex_module_recvmsg(sub_proc, &recv_msg);
        if (ret < 0 || recv_msg == NULL)
            continue;

        type = message_get_type(recv_msg);
        subtype = message_get_subtype(recv_msg);

        if ((type == DTYPE_VTCM_CTRL_IN) && (subtype == VTCM_CTRL_INIT)) {
            proc_vtcm_init(sub_proc,recv_msg);
        }
        else if ((type == DTYPE_VTCM_CTRL_IN) && (subtype == VTCM_CTRL_EXPORT)) {
            proc_vtcm_export(sub_proc,recv_msg);
        }
        else if ((type == DTYPE_VTCM_CTRL_IN) && (subtype == VTCM_CTRL_IMPORT)) {
            proc_vtcm_import(sub_proc,recv_msg);
        }
    }
    return 0;
}

int proc_vtcm_init(void* sub_proc, void* recv_msg)
{
    int ret = 0;
    int i = 0;
    int offset=0;
    int keylen;
    int datalen;
    struct vtcm_init_cmd_in * vtcm_in;
    struct vtcm_init_cmd_out * vtcm_out;
    void *vtcm_template;
    uint32_t returnCode=0;

    printf("proc_vtcm_init : Start\n");
    ret = message_get_record(recv_msg, (void **)&vtcm_in, 0); // get structure 
    if(ret < 0) 
        return ret;
    if(vtcm_in == NULL)
        return -EINVAL;
    
    tcm_state_t * tcm_state = proc_share_data_getpointer();

    tcm_state_t * curr_tcm=&tcm_state[vtcm_in->cmd_head.vtcm_no];
    returnCode=0;

vtcm_init_out:

    vtcm_out=Talloc0(sizeof(*vtcm_out));
    if(vtcm_out==NULL)
	return -ENOMEM;
    vtcm_out->return_head.tag=TCM_TAG_RSP_MANAGE_COMMAND;
    vtcm_out->return_head.returnCode=returnCode;
    vtcm_out->return_head.paramSize=sizeof(*vtcm_out);
    vtcm_out->return_head.vtcm_no=vtcm_in->cmd_head.vtcm_no;

    vtcm_template=memdb_get_template(DTYPE_VTCM_CTRL_OUT,VTCM_CTRL_INIT);
    if(vtcm_template==NULL)
	return -EINVAL;
			
    void *send_msg = message_create(DTYPE_VTCM_CTRL_OUT ,VTCM_CTRL_INIT ,recv_msg);
    if(send_msg == NULL)
    {
        printf("send_msg == NULL\n");
        return -EINVAL;      
    }
    message_add_record(send_msg, vtcm_out);
    ret = ex_module_sendmsg(sub_proc, send_msg);
    return ret;
}
int proc_vtcm_import(void* sub_proc, void* recv_msg)
{

}

int proc_vtcm_export(void* sub_proc, void* recv_msg)
{
    int ret = 0;
    int i = 0;
    int offset=0;
    int keylen;
    int datalen;
    struct vtcm_export_cmd_in * vtcm_in;
    struct vtcm_export_cmd_out * vtcm_out;
    void *vtcm_template;
    uint32_t returnCode=0;

    printf("proc_vtcm_init : Start\n");
    ret = message_get_record(recv_msg, (void **)&vtcm_in, 0); // get structure 
    if(ret < 0) 
        return ret;
    if(vtcm_in == NULL)
        return -EINVAL;
    
    tcm_state_t * tcm_state = proc_share_data_getpointer();

    tcm_state_t * curr_tcm=&tcm_state[vtcm_in->cmd_head.vtcm_no];
    returnCode=0;

    //  process ctrl command
    ret=vtcm_instance_export(curr_tcm,Buf,vtcm_in->type);
 
    if(ret<0)
	return -EINVAL;

vtcm_export_out:

    vtcm_out=Talloc0(sizeof(*vtcm_out));
    if(vtcm_out==NULL)
	return -ENOMEM;
    vtcm_out->return_head.tag=TCM_TAG_RSP_MANAGE_COMMAND;
    vtcm_out->return_head.returnCode=returnCode;
    vtcm_out->type=VTCM_IO_STATIC;
    if(ret>vtcm_in->max_size)
    {
         vtcm_out->data_size=0;
	 vtcm_out->data=NULL;
    }	
    else
    {
    	vtcm_out->data_size=ret;
    	vtcm_out->data=Talloc0(ret);
	Memcpy(vtcm_out->data,Buf,vtcm_out->data_size);
    }	
    vtcm_out->return_head.paramSize=sizeof(*vtcm_out)-sizeof(BYTE *)+vtcm_out->data_size;
    vtcm_out->return_head.vtcm_no=vtcm_in->cmd_head.vtcm_no;

    void *send_msg = message_create(DTYPE_VTCM_CTRL_OUT ,VTCM_CTRL_EXPORT,recv_msg);
    if(send_msg == NULL)
    {
        printf("send_msg == NULL\n");
        return -EINVAL;      
    }
    message_add_record(send_msg, vtcm_out);
    ret = ex_module_sendmsg(sub_proc, send_msg);
    return ret;
}

