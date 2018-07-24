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

#include "vtcm_drv_client.h"

#define MAX_LINE_LEN 1024

static char * dev_name;
static CHANNEL * vtcm_drv_client;

static BYTE Buf[DIGEST_SIZE*64];
static BYTE * ReadBuf=Buf+DIGEST_SIZE*32;
static int readbuf_len;
static int dev_fd;

#define TCMIOC_CANCEL   _IO('T', 0x00)
#define TCMIOC_TRANSMIT _IO('T', 0x01)

int vtcm_drv_client_init(void * sub_proc,void * para)
{
    struct drv_init_para * init_para=para;
    int ret;

    dev_name=dup_str(init_para->dev_name,0);
    if(dev_name==NULL)
	return -ENOMEM;


    // init the channel
    vtcm_drv_client=channel_register(init_para->channel_name,CHANNEL_RDWR,sub_proc);
    if(vtcm_drv_client==NULL)
	return -EINVAL;

    return 0;
}

int vtcm_drv_client_start(void * sub_proc,void * para)
{
    int ret = 0, len = 0, i = 0, j = 0;
    int rc = 0;

    struct timeval conn_val;
    conn_val.tv_sec=time_val.tv_sec;
    conn_val.tv_usec=time_val.tv_usec;

    dev_fd=open(dev_name,O_RDWR);
    if(dev_fd<0)
	    return -EIO;	
    for (;;)
    {
        usleep(conn_val.tv_usec);
        len=channel_inner_read(vtcm_drv_client,ReadBuf,1024);
	if(len<0)
		return len;
	if(len==0)
		continue;

//  	ret = write(dev_fd,ReadBuf,len);
//  	if(ret!=len)
//    		return -EINVAL;
        len = ioctl(dev_fd, TCMIOC_TRANSMIT, ReadBuf);
	if(len==-1)
		return -EINVAL; 

//  	print_cubeaudit("write %d data!\n",ret);
  //	len=read(dev_fd,Buf,1024);
  	print_cubeaudit("read %d data!\n",len);
	ret=channel_inner_write(vtcm_drv_client,ReadBuf,len);	
	if(ret<len)
	{
		printf(" vtcm_drv_client write channel failed!\n");
		return -EINVAL;	
	}	
	    
    }
   close(dev_fd);
    return 0;
}
