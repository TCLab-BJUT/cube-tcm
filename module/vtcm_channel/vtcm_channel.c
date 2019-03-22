#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include "data_type.h"
#include "alloc.h"
#include "memfunc.h"
#include "json.h"
#include "struct_deal.h"
#include "crypto_func.h"
#include "basefunc.h"
#include "memdb.h"
#include "message.h"
#include "connector.h"
#include "ex_module.h"
#include "channel.h"
#include "sys_func.h"

#include "app_struct.h"
#include "vtcm_struct.h"
#include "vtcm_channel.h"

#define MAX_LINE_LEN 1024

static unsigned char Buf[DIGEST_SIZE*128];
static BYTE * ReadBuf=Buf;
static int readbuf_len=0;
static BYTE * WriteBuf=Buf+DIGEST_SIZE*64;
static int write_len=0;

static int index = 0;
static char errorbuf[1024];
static unsigned char sendbuf[4096];
static CHANNEL * vtcm_channel;
static void * extend_template;

int tcm_get_type_bytag(int tag)
{
	int ret;
	switch(tag)
	{
		case 0xc100:
			ret=DTYPE_VTCM_IN;
			break;
		case 0xc200:
			ret=DTYPE_VTCM_IN_AUTH1;
			break;
		case 0xc300:
			ret=DTYPE_VTCM_IN_AUTH2;
			break;
		default:
			ret= -EINVAL;
	}
	return ret;
}

int vtcm_channel_init(void * sub_proc,void * para)
{
    int ret;
    struct vtcm_channel_init_para * init_para=para;
    if(para==NULL)
	return -EINVAL;
    vtcm_channel=channel_find(init_para->channel_name);

    if(vtcm_channel==NULL)
	return -EINVAL;	
    extend_template=memdb_get_template(DTYPE_VTCM_EXTERNAL,SUBTYPE_INPUT_COMMAND_EXTERNAL) ;
    if(extend_template==NULL)
    {
    	printf("load extend template error!\n");
    	return -EINVAL;
    }

    return 0;
}

int vtcm_channel_start(void * sub_proc,void * para)
{
    int ret = 0, len = 0, i = 0, j = 0;
    int rc = 0;


    while(1)
    {
        usleep(time_val.tv_usec/10);
	ret=channel_read(vtcm_channel,ReadBuf+readbuf_len,DIGEST_SIZE*32-readbuf_len);
	if(ret<0)
		return ret;
	if(ret>0)
	{
		readbuf_len+=ret;
	
		//get the head of the template

 	        struct vtcm_external_input_command *output_data;
       		struct vtcm_manage_cmd_head *output_cmd;
        	int extend_size = struct_size(extend_template);

        	output_data = (struct vtcm_external_input_command *)Talloc0(extend_size) ;
        	ret = blob_2_struct(ReadBuf, output_data,extend_template) ;
		int offset=ret;
		int type,subtype;
	

		switch(output_data->tag)
		{
			case 0xC100:
			case 0xC200:
			case 0xC300:
			{ 
				if(output_data->tag==0xC100)
				{
					type=DTYPE_VTCM_IN;
				}
				else if(output_data->tag==0xC200)
				{
					type=DTYPE_VTCM_IN_AUTH1;
				}
				else if(output_data->tag==0xC300)
				{
					type=DTYPE_VTCM_IN_AUTH2;
				}		

				subtype=output_data->ordinal;

               			void * command_template = memdb_get_template(type,subtype) ;
					//Get the entire command template
                       		if(command_template == NULL)
                       		{
                       			printf("can't solve this command!\n");
               			}	
               			else 
               			{
                       			void * Extend_input = Talloc0(struct_size(command_template));
                       			ret = blob_2_struct(ReadBuf, Extend_input, command_template);
					if((ret<0)|| (ret>readbuf_len))
					{
						printf("solve command failed!\n");
						return -EINVAL;
					}
				//  clear the read data
			
					Memcpy(ReadBuf,ReadBuf+ret,readbuf_len-ret);
					readbuf_len-=ret;

                       			void * send_msg = message_create(type,subtype,NULL);
                       			if(send_msg == NULL)
                       				return -EINVAL;
                       			message_add_record(send_msg, Extend_input);
                       			ret=ex_module_sendmsg(sub_proc,send_msg);
               			}
				break;
			}
			case	TCM_TAG_RQU_VTCM_COMMAND:
			{	
				// this is the vtcm utils command
               			void * command_template = memdb_get_template(DTYPE_VTCM_STRUCT,SUBTYPE_VTCM_CMD_HEAD) ;
				output_cmd=(struct vtcm_manage_cmd_head *)Talloc0(sizeof(*output_cmd));
        	       		ret = blob_2_struct(ReadBuf, output_cmd,command_template) ;
				offset=ret;
               			output_data = (struct vtcm_external_input_command *)Talloc0(extend_size) ;
          	     		ret = blob_2_struct(ReadBuf+offset, output_data,extend_template) ;
				command_template=NULL;

				type=tcm_get_type_bytag(output_data->tag);
				if(type>0)
				{
					subtype=output_data->ordinal;
               				command_template = memdb_get_template(type,subtype) ;
				}
					//Get the entire command template
              			if(command_template == NULL)
               			{
              				printf("can't solve this command!\n");
              			}	
                	       	else 
                       		{
                       			void * Extend_input = malloc(struct_size(command_template));
                       			ret = blob_2_struct(ReadBuf+offset, Extend_input, command_template);
					// clear read data
					if((ret<0) || (ret>readbuf_len-offset))
					{
						printf("solve vtcm command error!\n");
					}
					else
					{
						Memcpy(ReadBuf,ReadBuf+offset+ret,readbuf_len-offset-ret);
						readbuf_len-=offset+ret;
                       				void * send_msg = message_create(type,subtype,NULL);
                       				if(send_msg == NULL)
                       					return -EINVAL;
                       				message_add_record(send_msg, Extend_input);
						message_add_expand_data(send_msg,DTYPE_VTCM_STRUCT,SUBTYPE_VTCM_CMD_HEAD,output_cmd);
						
                       				ret=ex_module_sendmsg(sub_proc,send_msg);
					}
                       		}
				break;
			}
			case	TCM_TAG_RQU_MANAGE_COMMAND:
			{
				type=DTYPE_VTCM_CTRL_IN;
				// this is the vtcm manage command 
				output_cmd=(struct vtcm_manage_cmd_head *)output_data;
				subtype=(int)output_cmd->cmd;
               			void * command_template = memdb_get_template(type,subtype) ;
					//Get the entire command template
               			if(command_template == NULL)
               			{
               				printf("can't solve this manage command!\n");

               			}	
            	   		else 
               			{
                     			void * Extend_input = malloc(struct_size(command_template));
                       			ret = blob_2_struct(ReadBuf, Extend_input, command_template);
					if((ret<0)|| (ret>readbuf_len))
					{
						printf("solve command failed!\n");
						return -EINVAL;
					}
					//  clear the read data
			
					Memcpy(ReadBuf,ReadBuf+ret,readbuf_len-ret);
					readbuf_len-=ret;
                       			void * send_msg = message_create(type,subtype,NULL);
                       			if(send_msg == NULL)
                      				return -EINVAL;
                     	  		message_add_record(send_msg, Extend_input);
                       			ret=ex_module_sendmsg(sub_proc,send_msg);
               			}	
				break;
			}
			default:
			printf("error vtcm command head format!\n");
		}
	}	
					
     	void *message_box ;

     	if((ex_module_recvmsg(sub_proc,&message_box)>=0)
		&&(message_box!=NULL))
     	{
	    int type;
	    int subtype;
	    type=message_get_type(message_box);
	    subtype=message_get_subtype(message_box);

            MSG_HEAD * message_head;
            message_head=message_get_head(message_box);
	    MSG_EXPAND * msg_expand;
	    struct vtcm_manage_return_head * return_head; 
	    BYTE * cmd_buf;
	    UINT16 tag;
	
            void * record;
            void * out_msg_template=memdb_get_template(message_head->record_type,message_head->record_subtype);
	    if(out_msg_template==NULL)
	    {
		  printf("get record (%d %d)'s template error!\n",message_head->record_type,message_head->record_subtype);
		  return -EINVAL;
	    }	
            int  blob_size;
	    int  offset;

	    offset=0;
	    	
	    // Judge if the message is an vtcm_cmd

	    ret=message_get_define_expand(message_box,&msg_expand,DTYPE_VTCM_STRUCT,SUBTYPE_VTCM_RETURN_HEAD);
	    if(ret<0)
		return ret;
	    if(msg_expand==NULL)
	    {
		cmd_buf=sendbuf;
	    }
	    else
	    {	
	   	 return_head=msg_expand->expand;
	    	if(return_head==NULL)
	    	{
			cmd_buf=sendbuf;
	    	}
		else
		{
			offset=sizeof(*return_head);
			cmd_buf=sendbuf+offset;
			void * return_head_template=memdb_get_template(DTYPE_VTCM_STRUCT,SUBTYPE_VTCM_RETURN_HEAD);
			ret=struct_2_blob(return_head,sendbuf,return_head_template);
			if(ret<0)
				return -EINVAL;
		}
		
	     }	

            record=Talloc0(struct_size(out_msg_template));

            ret = message_get_record(message_box,&record,0);


            blob_size=struct_2_blob(record, cmd_buf,out_msg_template);

            // process the nv_definespace's two condition
	    if(subtype==SUBTYPE_NV_DEFINESPACE_OUT)
	    {
		tag=*(UINT16 *)cmd_buf;
	        if(tag==htons(TCM_TAG_RSP_COMMAND))
		{
			blob_size-=DIGEST_SIZE;
		}
	    }		
	    

	    *(int *)(cmd_buf+2)=htonl(blob_size);
            if(offset>0)
	    {
		    *(int *)(sendbuf+2)=htonl(offset+blob_size);
	    }	

	    if(deep_debug)
            	printf("response cmd size %d\n", blob_size);

	    int len=channel_write(vtcm_channel,sendbuf,blob_size+offset);
            if (len != blob_size+offset)
                print_cubeerr("vtcm_channel write failed!\n");
        }
    }
    return 0;
}
