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
#include "ex_module.h"

#include "vtcm_input.h"
#include "app_struct.h"


static struct timeval time_val={0,50*1000};
//int print_error(char * str, int result)
//{
//	printf("%s %s",str,tss_err_string(result));
//}

int vtcm_input_init(void * sub_proc,void * para)
{
	system("stty erase ^H");
	return 0;
}

int vtcm_input_start(void * sub_proc,void * para)
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

	printf("begin vtcm_input start!\n");
	
	sleep(1);
	
	while(1)
	{
		usleep(time_val.tv_usec);
		proc_vtcm_getinputmsg(sub_proc,para);		
	}

	return 0;
};


int proc_vtcm_getinputmsg(void * sub_proc,void * para)
{
	int ret;

	int fd ;
	int i;
	int offset;
	char buf[DIGEST_SIZE*32];
	struct tcm_utils_input * utils_input;
	char * str;

	char output[DIGEST_SIZE*32];

	printf("Wait for the tcm command input!\n");

	str=fgets(buf,DIGEST_SIZE*32,stdin);
	if(str==NULL)
		return -EIO;
	ret=Strlen(buf);
	if(buf[ret-1]=='\n')
		buf[ret-1]=0;

	offset=0;
	i=0;

	do{
		ret=Getfiledfromstr(output+32*i,buf+offset,' ',DIGEST_SIZE);
		if(ret>0)
		{
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

	void * send_msg=message_create(DTYPE_VTCM_UTILS,SUBTYPE_TCM_UTILS_INPUT,NULL);
	if(send_msg==NULL)
		return -EINVAL;
	message_add_record(send_msg,utils_input);	
	ex_module_sendmsg(sub_proc,send_msg);
	return 0;
}
