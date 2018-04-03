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

#include "tcm_constants.h"
#include "app_struct.h"
#include "vtcm_struct.h"
#include "vtcm_manager.h"

const int max_vtcm_copy_num =5;
const int active_time_limit=20;
static	BYTE in_cmd[2048];
static	BYTE out_cmd[2048];

struct manager_vtcm_buffer * _vtcm_manager_get_buffer(void * sub_proc)
{
	return ex_module_getpointer(sub_proc);	
}

BYTE * _vtcm_get_instance_uuid(void * instance)
{
	if(instance==NULL)
		return NULL;
	struct vtcm_msg_buffer * vtcm_buffer = *(struct vtcm_msg_buffer **)instance;
	if(vtcm_buffer==NULL)
		return -EINVAL;
	return &vtcm_buffer->vtcm_instance.vtcm_id; 
}

void * _vtcm_get_first_instance(void * sub_proc)
{
	Record_List * record;
	struct manager_vtcm_buffer * vtcm_buffer=_vtcm_manager_get_buffer(sub_proc);
	if(vtcm_buffer==NULL)
		return NULL;
	Record_List *instance_list=&vtcm_buffer->msg_buffer;
	
	if(instance_list->list.next==&instance_list->list)
		return NULL;
	record=List_entry(instance_list->list.next,Record_List,list);
	return &(record->record);	
}
void * _vtcm_get_next_instance(void * curr_instance)
{
	Record_List * record;
	record=List_entry(curr_instance,Record_List,record);
	if(record==NULL)
		return NULL;
	
	record=List_entry(record->list.next,Record_List,list);
	if(record->record==NULL)
		return NULL;
	return &(record->record);	
}

void * vtcm_find_byuuid(void * sub_proc,BYTE * uuid)
{
	void * vtcm_instance;
	vtcm_instance=_vtcm_get_first_instance(sub_proc);	

	while(vtcm_instance!=NULL)
	{
		if(Memcmp(uuid,_vtcm_get_instance_uuid(vtcm_instance),DIGEST_SIZE)==0)
		{
			break;
		}
		vtcm_instance=_vtcm_get_next_instance(vtcm_instance);
	}
	return vtcm_instance;
}

int vtcm_add_msg(void * sub_proc,void * recv_msg,BYTE * uuid)
{
	void * vtcm_instance;
	struct vtcm_msg_buffer * vtcm_buf;
	Record_List * record;
	struct manager_vtcm_buffer * vtcm_manager=_vtcm_manager_get_buffer(sub_proc);	
	
	vtcm_instance=vtcm_find_byuuid(sub_proc,uuid);
	if(vtcm_instance==NULL)
	{
		vtcm_buf=Calloc0(sizeof(*vtcm_buf));
		if(vtcm_buf==NULL)
			return NULL;
		Memcpy(vtcm_buf->vtcm_instance.vtcm_id,uuid,DIGEST_SIZE);
		vtcm_buf->vtcm_instance.state=VTCM_INIT;
		vtcm_buf->vtcm_instance.active_times=0;

		record=Calloc0(sizeof(*record));
		if(record==NULL)
			return -ENOMEM;
		INIT_LIST_HEAD(&(record->list));
		record->record=vtcm_buf;
		vtcm_buf->in_msg=recv_msg;
		List_add(&(record->list),&(vtcm_manager->msg_buffer.list));
	}
	else
	{
		vtcm_buf=*(struct vtcm_msg_buf **)vtcm_instance;
		if(vtcm_buf->in_msg!=NULL)
			return -EINVAL;
		vtcm_buf->in_msg=recv_msg;	
	}
	return 0;
};

int vtcm_select_copy(void * sub_proc)
{
	int ret;
	int i;
	int elder_copy_no=0;
	void * temp_pointer;
	struct vtcm_copy * active_vtcm;
	struct vtcm_msg_buffer * instance_msg_buf;
	struct vtcm_instance * instance;
	struct vtcm_msg_buffer * max_wait_instance=NULL;
	struct vtcm_msg_buffer * max_active_instance=NULL;
	struct manager_vtcm_buffer * vtcm_manager=_vtcm_manager_get_buffer(sub_proc);	
	
	temp_pointer=_vtcm_get_first_instance(sub_proc);
        if(temp_pointer == NULL)
		return 0;
	// count the active_time,sleep_time and wait_time,find the max_active_instance and max_wait_instance;
	
	while(temp_pointer!=NULL)
	{
		instance_msg_buf=*(struct vtcm_msg_buffer **)temp_pointer;
		instance=&instance_msg_buf->vtcm_instance;
		switch(instance->state)
		{
			case VTCM_INIT:
			{
				if(max_wait_instance==NULL)
					max_wait_instance=instance_msg_buf;
				else
				{
					if(max_wait_instance->vtcm_instance.state!=VTCM_INIT)
						max_wait_instance=instance_msg_buf;
				}
				break;
			}
			case VTCM_ACTIVATE:
			{
				if(max_active_instance==NULL)
					max_active_instance=instance_msg_buf;
				else
				{
					if(instance->active_times>max_active_instance->vtcm_instance.active_times)
					{
						if(!instance->iswaitout)
							max_active_instance=instance_msg_buf;
					}
				}
				instance->active_times++;
				break;
			}
			case VTCM_SLEEP:
			{
				instance->sleep_times++;
				if(instance_msg_buf->in_msg!=NULL)
					instance->wait_times++;
				if(max_wait_instance==NULL)
					max_wait_instance=instance_msg_buf;
				else
				{
					if(instance->wait_times>max_wait_instance->vtcm_instance.wait_times)
						max_wait_instance=instance_msg_buf;
				}
				break;
			}
			default:
				return -EINVAL;
		}
		temp_pointer=_vtcm_get_next_instance(temp_pointer);
		
	}

	// look for the empty vtcm_copy in vtcm_list 
	for(i=0;i<vtcm_manager->vtcm_list.vtcm_copy_num;i++)
	{
		active_vtcm=&vtcm_manager->vtcm_list.vtcm_copy[i];
		if(Isemptyuuid(active_vtcm->vtcm_id))
		{
			if(max_wait_instance!=NULL)
			{
				Memcpy(active_vtcm->vtcm_id,max_wait_instance->vtcm_instance.vtcm_id,DIGEST_SIZE);
				active_vtcm->no=i+1;
				active_vtcm->active_times=1;
				active_vtcm->finish_cmds=0;
				max_wait_instance->vtcm_instance.state=VTCM_ACTIVATE;
				max_wait_instance=NULL;
			}	
			
		}
		else if(Memcmp(active_vtcm->vtcm_id,max_active_instance->vtcm_instance.vtcm_id,DIGEST_SIZE)==0)
		{
			elder_copy_no=i;	
			
		}

	}

	if((max_active_instance!= NULL) &&(max_wait_instance !=NULL))
	{
		if((elder_copy_no<0))
			return -EINVAL;
		if(max_active_instance->vtcm_instance.active_times>active_time_limit)
		{
			max_active_instance->vtcm_instance.active_times=0;
			max_active_instance->vtcm_instance.sleep_times=0;
			max_active_instance->vtcm_instance.wait_times=0;
			active_vtcm=&vtcm_manager->vtcm_list.vtcm_copy[elder_copy_no];
			Memcpy(active_vtcm->vtcm_id,max_wait_instance->vtcm_instance.vtcm_id,DIGEST_SIZE);
			active_vtcm->no=elder_copy_no+1;
			active_vtcm->active_times=1;
			active_vtcm->finish_cmds=0;
			max_wait_instance=NULL;
		}
	}
	return 0;
}


int vtcm_dispatch(void * sub_proc)
{
	int ret;
	int i;
	void * temp_pointer;
	struct vtcm_copy * active_vtcm;
	struct vtcm_msg_buffer * instance_msg_buf;
	struct vtcm_instance * instance;
	struct manager_vtcm_buffer * vtcm_manager=_vtcm_manager_get_buffer(sub_proc);	
	int offset;
	int out_size;
	int type;
	int subtype;

	void * record_template;
	void * vtcm_template = memdb_get_template(DTYPE_VTCM_STRUCT,SUBTYPE_VTCM_CMD_HEAD);
	void * return_head_template = memdb_get_template(DTYPE_VTCM_STRUCT,SUBTYPE_VTCM_RETURN_HEAD);
	void * cmd_head_template = memdb_get_template(DTYPE_VTCM_EXTERNAL,SUBTYPE_INPUT_COMMAND_EXTERNAL);
	
	for(i=0;i<vtcm_manager->vtcm_list.vtcm_copy_num;i++)
	{
		active_vtcm=&vtcm_manager->vtcm_list.vtcm_copy[i];
		if(!Isemptyuuid(active_vtcm->vtcm_id))
		{
			temp_pointer = vtcm_find_byuuid(sub_proc,active_vtcm->vtcm_id);
			if(temp_pointer == NULL)
				return -EINVAL;
			instance_msg_buf=*(struct vtcm_msg_buffer **)temp_pointer;
			switch(instance_msg_buf->vtcm_instance.state)
			{
				case VTCM_INIT:
					ret=vtcm_copy_init(sub_proc,i+1,instance_msg_buf->vtcm_instance.vtcm_id);
					if(ret<0)
					{
						printf("init vtcm copy error!\n");
					}
					else
					{
						instance_msg_buf->vtcm_instance.state=VTCM_ACTIVATE;
					}
					break;
				
				case VTCM_START:
					break;
				case VTCM_ACTIVATE:
					break;
				case VTCM_SLEEP:
					break;
				case VTCM_MIGRATE:
					break;
				default:
					return -EINVAL;	
			}

			if(instance_msg_buf->in_msg!=NULL)
			{
				void * send_msg=instance_msg_buf->in_msg;
				struct vtcm_manage_cmd_head cmd_head;
				void * record;
				cmd_head.tag=TCM_TAG_RQU_VTCM_COMMAND;
				cmd_head.vtcm_no=(unsigned short)i+1;						
				cmd_head.cmd=VTCM_CMD_TRANS;						
				offset=struct_size(vtcm_template);
 				type=message_get_type(send_msg);
				if(type!=DTYPE_VTCM_IN)
				{
					printf("wrong command format!\n");
					continue;	
				}
				subtype=message_get_subtype(send_msg);
				ret=message_get_record(send_msg,&record,0);
				if(ret<0)
					return ret;
				record_template=memdb_get_template(type,subtype);
				if(record_template==NULL)
				{
					print_cubeerr("wrong record type %d %d!\n",type,subtype);
					return -EINVAL;
				}
				ret=struct_2_blob(record,in_cmd+offset,record_template);
				offset+=ret;				
				cmd_head.paramSize=offset;
				ret=struct_2_blob(&cmd_head,in_cmd,vtcm_template);

				vtcm_manager_transmit(offset,in_cmd,&out_size,out_cmd);
				
				struct vtcm_manage_return_head * return_head;
				return_head=Talloc0(sizeof(*return_head));
				if(return_head==NULL)
					return -ENOMEM;
				if(out_size<sizeof(*return_head))
				{
					print_cubeerr("wrong vtpm‘s return data!\n");
					return -EINVAL;
				}
					
				ret=blob_2_struct(out_cmd,return_head,return_head_template);
				if(ret<0)
					return ret;
				offset=ret;

				type=DTYPE_VTCM_OUT;				
				record_template=memdb_get_template(type,subtype);
				if(record_template==NULL)
				{
					print_cubeerr("wrong return record type %d %d!\n",type,subtype);
					return -EINVAL;
				}

				record=Talloc0(struct_size(record_template));
				
				ret=blob_2_struct(out_cmd+offset,record,record_template);
				if(ret<0)
				{
					printf("return cmd format error!\n");
					continue;
				}
				if(ret+offset!=out_size)
				{
					printf("return cmd size error!\n");
					continue;
				}
				
				instance_msg_buf->in_msg=NULL;
				void * response_msg=message_create(type,subtype,send_msg);	
				if(response_msg==NULL)
				{
					printf("can't create response message!\n");
					continue;
				}
				message_add_record(response_msg,record);
				struct uuid_record * record_expand=Talloc0(sizeof(*record_expand));
				Memcpy(record_expand->uuid,active_vtcm->vtcm_id,DIGEST_SIZE);
  				message_add_expand_data(response_msg, DTYPE_MESSAGE, SUBTYPE_UUID_RECORD, record_expand);		
				ex_module_sendmsg(sub_proc,response_msg);
				switch(subtype)
				{
					case SUBTYPE_CREATEEKPAIR_IN:
					{
						ret=vtcm_copy_store(sub_proc,return_head->vtcm_no,record_expand->uuid);	
						break;
					}
					default:
						break;
				}

			}
		}
	}
	return 0;
}

int vtcm_manager_transmit(int in_len,BYTE * in, int * out_len, BYTE * out)
{
	int ret;
	int sockfd,sock_dt;
    	struct sockaddr_in my_addr;//local ip info
    	struct sockaddr_in dest_addr; //destnation ip info

	char * tcm_socket_name;
	int tcm_port;
	char * temp_str;
	tcm_socket_name=getenv("TCM_SERVER_NAME");
	if(tcm_socket_name==NULL)
		return -EINVAL;
	temp_str=getenv("TCM_SERVER_PORT");
	if(temp_str==NULL)
		return -EINVAL;
	tcm_port=Atoi(temp_str,DIGEST_SIZE);	

	if(-1 == (sockfd = socket(AF_INET,SOCK_STREAM,0)) )
    	{
        	print_cubeerr("error in create socket\n");
        	return -1;
    	}
    	dest_addr.sin_family = AF_INET;
    	dest_addr.sin_port = htons(tcm_port);
    	dest_addr.sin_addr.s_addr = inet_addr(tcm_socket_name);
    	memset(&dest_addr.sin_zero,0,8);
    	if(-1 == connect(sockfd,(struct sockaddr*)&dest_addr,sizeof(struct sockaddr)))
    	{
        	print_cubeerr("connect error\n");
        	return -EINVAL;
    	}
    	ret = send(sockfd,in,in_len,0);
	if(ret!=in_len)
		return -EINVAL;
	print_cubeaudit("write %d data!\n",ret);
    	ret=recv(sockfd,out,2048,0);
	print_cubeaudit("read %d data!\n",ret);
    	close(sockfd);
	*out_len=ret;
	return ret;
}

int vtcm_find_storedata(BYTE * uuid)
{
	char * storedir="./vtcm_lib/";
	char filename[DIGEST_SIZE*3];
	Strcpy(filename,storedir);
	digest_to_uuid(uuid,filename+Strlen(storedir));
	if(access(filename,R_OK|W_OK)==0)
		return 0;
	return -ENFILE;
}


int vtcm_copy_init(void * sub_proc,int no,BYTE * uuid)
{
	int offset=0;
	struct vtcm_init_cmd_in * vtcm_in;
	struct vtcm_init_cmd_out * vtcm_out;
	void * vtcm_template;
	int out_size;

	vtcm_in=Talloc0(sizeof(*vtcm_in));
	if(vtcm_in==NULL)
		return -ENOMEM;
	vtcm_in->cmd_head.tag=TCM_TAG_RQU_MANAGE_COMMAND;
	vtcm_in->cmd_head.vtcm_no=no;
	vtcm_in->cmd_head.cmd=VTCM_CTRL_INIT;

	Memcpy(vtcm_in->uuid,uuid,DIGEST_SIZE);
	vtcm_in->cmd_head.paramSize=sizeof(*vtcm_in);

	vtcm_template=memdb_get_template(DTYPE_VTCM_CTRL_IN,VTCM_CTRL_INIT);	
	if(vtcm_template==NULL)
		return -EINVAL;
	
	offset=struct_2_blob(vtcm_in,in_cmd,vtcm_template);
	if(offset<=0)
		return -EINVAL;
        vtcm_manager_transmit(offset,in_cmd,&out_size,out_cmd);
	if(out_size<=0)
		return -EINVAL;
	vtcm_out=Talloc0(sizeof(*vtcm_out));
	if(vtcm_out==NULL)
		return -ENOMEM;
	vtcm_template=memdb_get_template(DTYPE_VTCM_CTRL_OUT,VTCM_CTRL_INIT);	
	if(vtcm_template==NULL)
		return -EINVAL;
	
	offset=blob_2_struct(out_cmd,vtcm_out,vtcm_template);
	if(offset<=0)
		return -EINVAL;
	return 0;
}

int vtcm_copy_export(void * sub_proc,int no,BYTE * uuid)
{

}

int vtcm_copy_store(void * sub_proc,int no,BYTE * uuid)
{
	int offset=0;
	struct vtcm_export_cmd_in * vtcm_in;
	struct vtcm_export_cmd_out * vtcm_out;
	void * vtcm_template;
	int out_size;

	vtcm_in=Talloc0(sizeof(*vtcm_in));
	if(vtcm_in==NULL)
		return -ENOMEM;
	vtcm_in->cmd_head.tag=TCM_TAG_RQU_MANAGE_COMMAND;
	vtcm_in->cmd_head.vtcm_no=no;
	vtcm_in->cmd_head.cmd=VTCM_CTRL_EXPORT;
	vtcm_in->type=VTCM_IO_STATIC;
	vtcm_in->max_size=2048;

	Memcpy(vtcm_in->crypt_id,uuid,DIGEST_SIZE);
	vtcm_in->cmd_head.paramSize=sizeof(*vtcm_in);

	vtcm_template=memdb_get_template(DTYPE_VTCM_CTRL_IN,VTCM_CTRL_EXPORT);	
	if(vtcm_template==NULL)
		return -EINVAL;
	
	offset=struct_2_blob(vtcm_in,in_cmd,vtcm_template);
	if(offset<=0)
		return -EINVAL;
        vtcm_manager_transmit(offset,in_cmd,&out_size,out_cmd);
	if(out_size<=0)
		return -EINVAL;
	vtcm_out=Talloc0(sizeof(*vtcm_out));
	if(vtcm_out==NULL)
		return -ENOMEM;
	vtcm_template=memdb_get_template(DTYPE_VTCM_CTRL_OUT,VTCM_CTRL_EXPORT);	
	if(vtcm_template==NULL)
		return -EINVAL;
	
	offset=blob_2_struct(out_cmd,vtcm_out,vtcm_template);
	if(offset<=0)
		return -EINVAL;

	vtcm_store_export_data(vtcm_out,uuid);

	return 0;

}
int vtcm_copy_load(void * sub_proc,int no,BYTE * uuid)
{

}
int vtcm_copy_import(void * sub_proc,int no,BYTE * uuid)
{

}

int vtcm_copy_mig_ready(void * sub_proc,int no,BYTE * uuid)
{

}
int vtcm_copy_mig_exportkey(void * sub_proc,int no,BYTE * uuid)
{

}
int vtcm_copy_mig_importkey(void * sub_proc,int no,BYTE * uuid)
{

}
int vtcm_copy_mig_clean(void * sub_proc,int no,BYTE * uuid)
{

}
int vtcm_copy_mig_active(void * sub_proc,int no,BYTE * uuid)
{

}

int vtcm_store_export_data(void * vtcm_out, BYTE * uuid)
{
	int ret;
	char * store_dir="./vtcm_lib/";
	char * cache_dir="./vtcm_cache/";
	char filename[DIGEST_SIZE*4];
	int fd;
	struct vtcm_export_cmd_out * export_cmd=vtcm_out;
	Memset(filename,0,DIGEST_SIZE*4);
	switch(export_cmd->type)
	{
		case	VTCM_IO_STATIC:
			Strcpy(filename,store_dir);
			break;
		case 	VTCM_IO_CACHE:
			Strcpy(filename,cache_dir);
			break;
		case 	VTCM_IO_MIG:
			break;
		default:
			return -EINVAL;
	}	
	digest_to_uuid(uuid,filename+Strlen(filename));
	Strcat(filename,".dat");
	fd=open(filename,O_CREAT|O_TRUNC|O_WRONLY,0666);
	
	if(fd<0)
		return -EIO;
		
	ret=write(fd,export_cmd->data,export_cmd->data_size);
	close(fd);
	return ret;	
}
