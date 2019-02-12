#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

#include "vtcm_tcp_client.h"

#define MAX_LINE_LEN 1024

static char * tcp_addr;
static int tcp_port;
static CHANNEL * vtcm_tcp_client;

static BYTE Buf[DIGEST_SIZE*64];
static BYTE * ReadBuf=Buf+DIGEST_SIZE*32;
static int readbuf_len;
static struct sockaddr_in my_addr;
static struct sockaddr_in dest_addr;
static int sockfd;

int vtcm_tcp_client_init(void * sub_proc,void * para)
{
    struct tcp_init_para * init_para=para;
    int ret;

    Strcpy(Buf,init_para->tcp_addr);
    Strcat(Buf,":");
    Itoa(init_para->tcp_port,Buf+Strlen(Buf));

  	dest_addr.sin_family = AF_INET;
  	dest_addr.sin_port = htons(init_para->tcp_port);
  	dest_addr.sin_addr.s_addr = inet_addr(init_para->tcp_addr);
  	Memset(&dest_addr.sin_zero,0,8);
    	
    // init the channel
    vtcm_tcp_client=channel_register(init_para->channel_name,CHANNEL_RDWR,sub_proc);
    if(vtcm_tcp_client==NULL)
	return -EINVAL;

    return 0;
}

int vtcm_tcp_client_start(void * sub_proc,void * para)
{
    int ret = 0, len = 0, i = 0, j = 0;
    int rc = 0;

    struct timeval conn_val;
    conn_val.tv_sec=time_val.tv_sec;
    conn_val.tv_usec=time_val.tv_usec;

    while(1)
    {
        usleep(conn_val.tv_usec);
        len=channel_inner_read(vtcm_tcp_client,ReadBuf,1024);
	if(len<0)
		return len;
	if(len==0)
		continue;
       if(-1 == (sockfd = socket(AF_INET,SOCK_STREAM,0)) )
       {
    		print_cubeerr("error in create socket\n");
    		return -1;
       }
    // init the dest_addr 

  	if(-1 == connect(sockfd,(struct sockaddr*)&dest_addr,sizeof(struct sockaddr)))
  	{
    		print_cubeerr("connect error\n");
    		return -EINVAL;
  	}
  	ret = send(sockfd,ReadBuf,len,0);
  	if(ret!=len)
    		return -EINVAL;
  	print_cubeaudit("write %d data!\n",ret);
  	len=recv(sockfd,Buf,1024,0);
  	print_cubeaudit("read %d data!\n",len);
  	close(sockfd);
	ret=channel_inner_write(vtcm_tcp_client,Buf,len);	
	if(ret<len)
	{
		printf(" vtcm_tcp_client write channel failed!\n");
		return -EINVAL;	
	}	
	    
    }
    return 0;
}
