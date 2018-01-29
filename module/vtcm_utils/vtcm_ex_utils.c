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
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <string.h>
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
#include "vtcm_utils.h"
#include "app_struct.h"
#include "sm3.h"
#include "sm4.h"

static BYTE Buf[DIGEST_SIZE*32];

extern Record_List sessions_list;
extern TCM_PUBKEY *pubEK;
extern TCM_SECRET ownerAuth;
extern TCM_SECRET smkAuth;
extern Record_List entitys_list;

// Ex CA Module

BYTE * CAprikey=NULL;
unsigned long CAprilen=0;
BYTE * CApubkey=NULL;
 
int proc_vtcmutils_ExCreateSm2Key(void * sub_proc,void * para);
int proc_vtcmutils_ExLoadCAKey(void * sub_proc,void * para);
int proc_vtcmutils_ExCaSign(void * sub_proc,void * para);
int proc_vtcmutils_ExVerify(void * sub_proc,void * para);


int proc_vtcmutils_ExCreateSm2Key(void * sub_proc,void * para)
{
	int ret=0;
    	struct tcm_utils_input * input_para=para;
	char * index_para;
	char * value_para;
	int i;

	//  cmd's params
	char * pubkey_file=NULL;
	char * privkey_file=NULL;
	char * passwd=NULL;
    	printf("Begin ex Create sm2 key:\n");
	
	if((input_para->param_num>0)&&
		(input_para->param_num%2==1))
	{
		for(i=1;i<input_para->param_num;i+=2)
		{
        		index_para=input_para->params+i*DIGEST_SIZE;
        		value_para=index_para+DIGEST_SIZE;
			if(!Strcmp("-pubkey",index_para))
			{
        			pubkey_file=value_para;
			}	
			else if(!Strcmp("-prikey",index_para))
			{
				privkey_file=value_para;
			}
			else if(!Strcmp("-pwd",index_para))
			{
				passwd=value_para;
			}
			else
			{
				printf("Error cmd format! should be %s -pubkey pubkeyfile -prikey prikeyfile"
					"[-pwd passwd]",input_para->params);
				return -EINVAL;
			}
		}
	}	
	
	BYTE prikey[DIGEST_SIZE*2];
	BYTE pubkey_XY[64];
	unsigned long prilen=DIGEST_SIZE*2;
	int fd;

	ret=GM_GenSM2keypair(prikey,&prilen,pubkey_XY);	
	if(ret!=0)
		return -EINVAL;
	fd=open(pubkey_file,O_CREAT|O_TRUNC|O_WRONLY,0666);
	if(fd<0)
		return -EIO;	
	
	ret=write(fd,pubkey_XY,64);
	if(ret<0)
	{
		printf("write pubkey file error!\n");
		return -EIO;	
	}
	close(fd);

	fd=open(privkey_file,O_CREAT|O_TRUNC|O_WRONLY,0666);
	if(fd<0)
		return -EIO;	
	
	ret=write(fd,prikey,prilen);
	if(ret<0)
	{
		printf("write prikey file error!\n");
		return -EIO;	
	}

	close(fd);
	printf("proceed  create Sm2 key succeed!\n");

	return ret;
}

int proc_vtcmutils_ExLoadCAKey(void * sub_proc,void * para)
{
	int ret=0;
    	struct tcm_utils_input * input_para=para;
	char * index_para;
	char * value_para;
	int i;

	//  cmd's params
	char * pubkey_file=NULL;
	char * privkey_file=NULL;
	char * passwd=NULL;
    	printf("Begin ex Load CA Key:\n");
	
	if((input_para->param_num>0)&&
		(input_para->param_num%2==1))
	{
		for(i=1;i<input_para->param_num;i+=2)
		{
        		index_para=input_para->params+i*DIGEST_SIZE;
        		value_para=index_para+DIGEST_SIZE;
			if(!Strcmp("-pubkey",index_para))
			{
        			pubkey_file=value_para;
			}	
			else if(!Strcmp("-prikey",index_para))
			{
				privkey_file=value_para;
			}
			else if(!Strcmp("-pwd",index_para))
			{
				passwd=value_para;
			}
			else
			{
				printf("Error cmd format! should be %s -pubkey pubkeyfile -prikey prikeyfile"
					"[-pwd passwd]",input_para->params);
				return -EINVAL;
			}
		}
	}	
	
	int fd;

	if(pubkey_file!=NULL)
	{
		fd=open(pubkey_file,O_RDONLY);
		if(fd<0)
			return -EIO;	
	
		ret=read(fd,Buf,DIGEST_SIZE*16+1);
		if(ret<0)
		{
			printf("read  pubkey file error!\n");
			return -EIO;	
		}
		if(ret>DIGEST_SIZE*16)
		{
			printf("pubkey is too long!\n");
			return -EIO;
		}
		CApubkey=malloc(ret);
		if(CApubkey==NULL)
			return -ENOMEM;
		Memcpy(CApubkey,Buf,ret);
		close(fd);
	}
	if(privkey_file!=NULL)
	{
		fd=open(privkey_file,O_RDONLY);
		if(fd<0)
			return -EIO;	
	
		ret=read(fd,Buf,DIGEST_SIZE*16+1);
		if(ret<0)
		{
			printf("read  privkey file error!\n");
			return -EIO;	
		}
		if(ret>DIGEST_SIZE*16)
		{
			printf("privkey is too long!\n");
			return -EIO;
		}
		CAprilen=ret;
		CAprikey=malloc(ret);
		if(CAprikey==NULL)
			return -ENOMEM;
		Memcpy(CAprikey,Buf,ret);
		close(fd);
	}

	printf("proceed  load ca key succeed!\n");

	return ret;
}
