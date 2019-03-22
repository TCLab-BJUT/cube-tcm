#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include "data_type.h"
#include "alloc.h"
#include "memfunc.h"
#include "json.h"
#include "struct_deal.h"
#include "crypto_func.h"
#include "basefunc.h"
#include "memdb.h"
#include "message.h"
#include "channel.h"
#include "connector.h"
#include "ex_module.h"
#include "sys_func.h"

#include "tcmtddl.h"
#include "vtcm_tddl_client.h"

#define MAX_LINE_LEN 1024

static CHANNEL * vtcm_tddl_client;

static BYTE Buf[DIGEST_SIZE*64];
static BYTE * ReadBuf=Buf+DIGEST_SIZE*32;
static int readbuf_len;

enum vtcm_trans_type
{
	DRV_IOCTL=1,
	DRV_RW
};
static enum vtcm_trans_type trans_type;
enum vtcm_drv_channel_type
{
	ACTIVE=1,
	PASSIVE
};
static enum vtcm_drv_channel_type drv_channel_type;

#define TCMIOC_CANCEL   _IO('T', 0x00)
#define TCMIOC_TRANSMIT _IO('T', 0x01)

int vtcm_tddl_client_init(void * sub_proc,void * para)
{
    struct drv_init_para * init_para=para;
    int ret;

    if((init_para->channel_type==NULL)
	  ||(Strcmp(init_para->channel_type,"ACTIVE")==0))
    {
    	// init the channel
	drv_channel_type=ACTIVE;
    	vtcm_tddl_client=channel_register(init_para->channel_name,CHANNEL_RDWR,sub_proc);
    	if(vtcm_tddl_client==NULL)
		return -EINVAL;
    }
    else if(Strcmp(init_para->channel_type,"PASSIVE")==0)
    {
	drv_channel_type=PASSIVE;
    	vtcm_tddl_client=channel_find(init_para->channel_name);
    	if(vtcm_tddl_client==NULL)
		return -EINVAL;
    }
    else
    {
	print_cubeerr("vtcm_tddl_client: error channel type!\n");
	return -EINVAL;
    }
/*
    if(init_para->trans_type==NULL)
    	trans_type=DRV_IOCTL;
    else if(Strcmp(init_para->trans_type,"IOCTL")==0)
    {
	trans_type=DRV_IOCTL;
    }
    else if(Strcmp(init_para->trans_type,"RW")==0)
    {
	trans_type=DRV_RW;
    }	
    else
    {
	print_cubeerr("vtcm_tddl_client: error trans type!\n");
	return -EINVAL;
    }
*/	

    return 0;
}

int vtcm_tddl_client_start(void * sub_proc,void * para)
{
    int ret = 0, len = 0, i = 0, j = 0;
    int rc = 0;
    UINT32 outlen=0;

    struct timeval conn_val;
    conn_val.tv_sec=time_val.tv_sec;
    conn_val.tv_usec=time_val.tv_usec;
/*
    dev_fd=open(dev_name,O_RDWR);
    if(dev_fd<0)
	    return -EIO;	
*/

    TSM_RESULT * result;

    while(1)
    {
        usleep(conn_val.tv_usec);
	if(drv_channel_type==ACTIVE)
        	len=channel_inner_read(vtcm_tddl_client,ReadBuf,1024);
	else
        	len=channel_read(vtcm_tddl_client,ReadBuf,1024);
	if(len<0)
		return len;
	if(len==0)
		continue;
    	result=Tddli_open();
	result=Tddli_TransmitData(ReadBuf,len,Buf,&outlen);
    	Tddli_close();
	

//  	print_cubeaudit("write %d data!\n",ret);
  //	len=read(dev_fd,Buf,1024);
  	printf("vtcm_tddl_client read %d data!\n",len);
	if(drv_channel_type==ACTIVE)
		ret=channel_inner_write(vtcm_tddl_client,Buf,outlen);	
	else
		ret=channel_write(vtcm_tddl_client,Buf,outlen);	
	if(ret<outlen)
	{
		printf(" vtcm_tddl_client write channel failed!\n");
		return -EINVAL;	
	}	
	    
    }
    return 0;
}
