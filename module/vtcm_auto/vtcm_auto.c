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
#include "memfunc.h"
#include "list.h"
#include "attrlist.h"

#include "basefunc.h"
#include "struct_deal.h"
#include "crypto_func.h"
#include "memdb.h"
#include "message.h"
#include "ex_module.h"
#include "sys_func.h"

#include "vtcm_auto.h"
#include "app_struct.h"
#include "vtcm_script.h"


static BYTE Buf[DIGEST_SIZE*32];
static struct tcm_utils_input cmd_input;
static struct tcm_utils_output cmd_output;
static char info[DIGEST_SIZE*16];
static char cmd_line[DIGEST_SIZE*16];
static int cmd_no=0;

struct cmd_var
{
	char var_name[32];
	char var_data[64];	
}__attribute__((packed));

Record_List varList;
Record_List scriptList;

struct cmd_var * _add_cmd_var(char * var_name,char * var_data) 
{
    struct cmd_var * new_var=Dalloc(sizeof(*new_var),NULL);
    if(new_var==NULL)
	return NULL;
    Strncpy(new_var->var_name,var_name,DIGEST_SIZE);			
    Strncpy(new_var->var_data,var_data,DIGEST_SIZE*2);			

    Record_List * record = Calloc0(sizeof(*record));
    if(record==NULL)
        return -EINVAL;
    INIT_LIST_HEAD(&record->list);
    record->record=new_var;
    List_add_tail(&record->list,&varList.list);
    return new_var;	
}

struct cmd_var * _del_cmd_var(char * var_name)
{
    Record_List * record;
    Record_List * head;
    struct List_head * curr;
    struct cmd_var  * old_var;

    head=&(varList.list);
    curr=head->list.next;

    while(curr!=head)
    {
        record=List_entry(curr,Record_List,list);
        old_var=record->record;
	if(Strncmp(old_var->var_name,var_name,DIGEST_SIZE)==0)
	{
		List_del(&record->list);
		Free(record);
		return old_var;
	}
        curr=curr->next;
    }
    return NULL;
}

struct cmd_var * _find_cmd_var(char * var_name)
{
    Record_List * record;
    Record_List * head;
    struct List_head * curr;
    struct cmd_var  * old_var;

    head=&(varList.list);
    curr=head->list.next;

    while(curr!=head)
    {
        record=List_entry(curr,Record_List,list);
        old_var=record->record;
	if(Strncmp(old_var->var_name,var_name,DIGEST_SIZE)==0)
	{
		return old_var;

	}
        curr=curr->next;
    }
    return NULL;
}

int _read_cmd_line(FILE * file,char * cmd)   	 // return type : 1-in, 2-out, 3-info
						  // return value: -x means read failed, 
						// 0 means no cmd line read
{
	
	char * comp_str[]={"in:","out:","info:",NULL};
	char * str;
	int ret;
	int offset;
	int i;

	do{
			
		// read a line from cmd_list file
		str=fgets(Buf,DIGEST_SIZE*32,file);
		if(str==NULL)
			return 0;
		ret=Strlen(Buf);
		if(Buf[ret-1]=='\n')
			Buf[ret-1]=0;
		offset=0;
		// remove the space and tab in the head
		while((Buf[offset]==' ')||(Buf[offset]=='\t'))
		{
			offset++;
			if(offset==ret)
				break;
		}
		if(offset==ret)
			continue;
		
	}while((Buf[offset]=='#')||Buf[offset]=='\0');

	for(i=0;comp_str[i]!=NULL;i++)
	{
		if(Strncmp(Buf+offset,comp_str[i],Strlen(comp_str[i]))==0)
			break;
	}
	if(comp_str[i]==NULL)
	{
		Strncpy(cmd,Buf+offset,Strlen(Buf+offset)+1);
		return -EINVAL;
	}
	offset+=Strlen(comp_str[i]);	

	Strncpy(cmd,Buf+offset,Strlen(Buf+offset)+1);
	return i+1;
}
	

int vtcm_auto_init(void * sub_proc,void * para)
{
    INIT_LIST_HEAD(&varList.list);
    varList.record=NULL;
    INIT_LIST_HEAD(&scriptList.list);
    scriptList.record=NULL;
    return 0;
}

int vtcm_auto_start(void * sub_proc,void * para)
{
	int ret;
	int retval;
	void * recv_msg;
	void * send_msg;
	void * context;
	BYTE uuid[DIGEST_SIZE];
	int i;
	int type;
	int subtype;
	FILE * file;
	struct start_para * start_para=para;
	struct vtcm_script_call * script_call;
	struct vtcm_script_ret * script_ret;
	int running_state=0;  // 0: wait
                              // 1: cmd line type
			      // 2: message type
	int cmd_para_num=0;
	void * call_msg=NULL;

	printf("begin vtcm_auto start!\n");
	
	sleep(1);

	
	if(para!=NULL)    // cmd line type
        {
		if(start_para->argc >=2)
                { 

			file=fopen(start_para->argv[1],"r");
			if(file==NULL)
			{
				printf("can't open cmd_list file %s!\n",start_para->argv[1]);
				return -EIO;
			}
			running_state=1;
			cmd_para_num=start_para->argc-2;
			if(cmd_para_num>0)
			{
				for(i=1;i<=cmd_para_num;i++)	
				{
					Buf[0]='$';
					Itoa(i,Buf+1);
					_add_cmd_var(Buf,start_para->argv[i+1]);
				}		
			}
			ret=_read_cmd_line(file,cmd_line);

			if(ret!=1)
			{
				printf("first command is not an input command!\n");
				return -EINVAL;	
			}

			proc_vtcm_sendonecmd(sub_proc,cmd_line,NULL);
		}
	}	


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

		if((type==DTYPE_VTCM_SCRIPT) &&(subtype==VTCM_SCRIPT_CALL))
		{
			// get script call cmd
			if(running_state!=0)
                        {
				printf("last script do not finished!\n");
				continue;
			}
			ret=message_get_record(recv_msg,&script_call,0);
			if(script_call==NULL)
				return -EINVAL;
			call_msg=recv_msg;

			// check the script file
			file=fopen(script_call->name,"r");
			if(file==NULL)
			{
				printf("can't open cmd_list file %s!\n",script_call->name);
				return -EIO;
			}
			running_state=2;
			cmd_para_num=script_call->param_num-1;
			// add the cmd parameter
			if(cmd_para_num>0)
			{
				for(i=1;i<=cmd_para_num+1;i++)	
				{
					Buf[0]='$';
					Itoa(i,Buf+1);
					_add_cmd_var(Buf,script_call->params+i*DIGEST_SIZE);
				}		
			}	
		

			ret=_read_cmd_line(file,cmd_line);

			if(ret!=1)
			{
				printf("first command is not an input command!\n");
				return -EINVAL;	
			}
			cmd_no=0;
			proc_vtcm_sendonecmd(sub_proc,cmd_line,NULL);
		}
		

        	if((type==DTYPE_VTCM_UTILS) &&(subtype ==SUBTYPE_TCM_UTILS_OUTPUT))
		{
			if(running_state==0)
				continue;
			cmd_no++;
			do{
				ret=_read_cmd_line(file,cmd_line);
			}while(ret==3);
			
			if(ret==2)
			{
				ret=proc_vtcm_receiveresponse(sub_proc,recv_msg,cmd_line);
				if(ret<0)
					return ret; 
				ret=_read_cmd_line(file,cmd_line);
			}

			while(ret==3)
			{			
				ret=_read_cmd_line(file,cmd_line);
			}

			if(ret==0)
			{
				printf("Finish cmd list!\n");
				fclose(file);
				running_state=0;

				script_ret=Talloc0(sizeof(*script_ret));
				if(script_ret==NULL)
					return -ENOMEM;
				ret=proc_get_scriptret(sub_proc,recv_msg,script_ret);	
				if(ret<0)
					return ret;

				// remove all the  cmd parameters
 				 
				for(i=1;i<=cmd_para_num;i++)	
				{
					Buf[0]='$';
					Itoa(i,Buf+1);
					struct cmd_var * old_var = _del_cmd_var(Buf);
					if(old_var!=NULL)
					{
						Free(old_var);
						old_var=NULL;
					}

				}		
				void * send_msg;
				send_msg=message_create(DTYPE_VTCM_SCRIPT,VTCM_SCRIPT_RET,call_msg);
				if(send_msg==NULL)
					return -EINVAL;
				message_add_record(send_msg,script_ret);
				ex_module_sendmsg(sub_proc,send_msg);	
				continue;	
			}		
			if(ret!=1)
			{
				printf("not input command after outputcommand!\n");
				return -EINVAL;	
			}
			ret=proc_vtcm_sendonecmd(sub_proc,cmd_line,NULL);
			if(ret<0)
				return ret;
		}
	}
	return 0;
};

int proc_get_scriptret(void * sub_proc,void *recv_msg, struct vtcm_script_ret *script_ret)
{
	int ret;
	struct tcm_utils_output * output_para;
	ret=message_get_record(recv_msg,&output_para,0);
	if(ret<0)
		return -EINVAL;
	script_ret->returnCode=Atoi(output_para->params,DIGEST_SIZE);
	script_ret->param_num=0;
	script_ret->params=NULL;
	script_ret->cmd_no=cmd_no;	
	return 0;
}
	
int proc_vtcm_sendonecmd(void * sub_proc,char * cmd,void * recv_msg)
{

	int ret;

	int fd ;
	int i;
	int offset;
	struct tcm_utils_input * utils_input;
	char * str;
	struct cmd_var * input_var;

	// get a valid cmd line;
	char output[DIGEST_SIZE*32];
	
	offset=0;
	i=0;
	do{
		ret=Getfiledfromstr(output+32*i,cmd+offset,' ',DIGEST_SIZE);
		if(ret>0)
		{
			if(output[32*i]=='$')
			{
				input_var=_find_cmd_var(output+32*i);
				if(input_var==NULL)
				{
					printf("can't find var %s!\n",output+32*i);
					return -EINVAL;
				}
				Memset(output+32*i,0,32);
				Memcpy(output+32*i,input_var->var_data,32);	
			}

			i++;
			offset+=ret;
		}
	}while(ret>0);
	
	utils_input=Talloc0(sizeof(*utils_input));
	if(utils_input==NULL)
		return -ENOMEM;
	utils_input->param_num=i;
	utils_input->params=Talloc0(DIGEST_SIZE*utils_input->param_num);
	if(utils_input->params==NULL)
		return -ENOMEM;
	Memcpy(utils_input->params,output,DIGEST_SIZE*utils_input->param_num);

	void * send_msg=message_create(DTYPE_VTCM_UTILS,SUBTYPE_TCM_UTILS_INPUT,recv_msg);
	if(send_msg==NULL)
		return -EINVAL;
	message_add_record(send_msg,utils_input);	
	ex_module_sendmsg(sub_proc,send_msg);
	return utils_input->param_num;
}


int proc_vtcm_receiveresponse(void * sub_proc,void * recv_msg,char * cmd)
{
	int ret;

	int i;
	int offset;
	struct tcm_utils_output * output_para;
	char * str;
	int var_no;
	char output[DIGEST_SIZE*32];

	struct cmd_var * output_var;

	offset=0;
	i=0;
	var_no=0;

    	ret==message_get_record(recv_msg,&output_para,0);
	if(ret<0)
		return ret;
	if(output_para==NULL)
		return -EINVAL;

	printf("Return code is %s\n",output_para->params);	

	do{
		ret=Getfiledfromstr(output+32*i,cmd+offset,' ',DIGEST_SIZE);
		if(ret>0)
		{
			offset+=ret;
		
			if((output[32*i+1]!=':')||(output[32*i+2]!='$'))
			{
				printf("Wrong output var format!\n");
				return -EINVAL;
			}		
			var_no=output[32*i]-'0';
			if((var_no<=0) || (var_no>=output_para->param_num))
			{
				return -EINVAL;
			}
			output_var=_find_cmd_var(&output[32*i+2]);
			if(output_var==NULL)
			{
				output_var=_add_cmd_var(&output[32*i+2],output_para->params+64*(i+1));
			}
			i++;
		}

	}while(ret>0);

	return 0;
}
