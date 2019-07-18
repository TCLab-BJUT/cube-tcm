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
#include <linux/netlink.h>

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

#include "app_struct.h"
#include "vtcm_struct.h"
#include "vtcm_netlink_channel.h"

#define MAX_LINE_LEN 1024

#define NETLINK_TEST    30
#define MSG_LEN            1024
#define MAX_PLOAD        1024

typedef struct _user_msg_info
{
    struct nlmsghdr hdr;
    char  msg[MSG_LEN];
} user_msg_info;

int skfd;
struct sockaddr_nl saddr,daddr;


static CHANNEL * vtcm_netlink_channel;

static BYTE Buf[DIGEST_SIZE*64];
static int index = 0;
static BYTE * ReadBuf=Buf+DIGEST_SIZE*32;
static int readbuf_len;

static void * extend_template;

struct default_conn_index
{
    BYTE uuid[DIGEST_SIZE];
    BYTE ek_uuid[DIGEST_SIZE];
    int vtcm_no;
};

static int conn_count=0;

int vtcm_netlink_channel_init(void * sub_proc,void * para)
{
    struct netlink_init_para * init_para=para;
    int ret;

    skfd = socket(AF_NETLINK,SOCK_RAW,NETLINK_TEST);
    if(skfd<0)
    {
	perror("create netlink socket error!\n");
        return skfd;	
    }
	
    //if(setsockopt(skfd,SOL_SOCKET,SO_RCVTIMEO,&time_val,sizeof(time_val))==-1)
    //{
    //     printf("setsockopt timeout error!\n");
    //     return -EINVAL;
   // }

    memset(&saddr,0,sizeof(saddr));
    saddr.nl_family = AF_NETLINK;
    saddr.nl_pid = 100;  //端口号(port ID) 
    saddr.nl_groups = 0;
    if(bind(skfd, (struct sockaddr *)&saddr, sizeof(saddr)) != 0)
    {
        perror("bind() error\n");
        close(skfd);
        return -1;
    }

    memset(&daddr, 0, sizeof(daddr));
    daddr.nl_family = AF_NETLINK;
    daddr.nl_pid = 0; // to kernel 
    daddr.nl_groups = 0;
   		
    vtcm_netlink_channel=channel_register(init_para->channel_name,CHANNEL_RDWR,sub_proc);
    if(vtcm_netlink_channel==NULL)
	return -EINVAL;
    extend_template=memdb_get_template(DTYPE_VTCM_EXTERNAL,SUBTYPE_INPUT_COMMAND_EXTERNAL) ;
    if(extend_template==NULL)
    {
    	printf("load extend template error!\n");
    	return -EINVAL;
    }

    return 0;
}

int vtcm_netlink_channel_start(void * sub_proc,void * para)
{
    int ret = 0, len = 0, i = 0, j = 0;
    int rc = 0;

    int rwstate=0;

    struct nlmsghdr *nlh = NULL;
    user_msg_info u_info;

    struct timeval conn_val;
    conn_val.tv_sec=time_val.tv_sec;
    conn_val.tv_usec=time_val.tv_usec/5;

    while(1)
    {
        usleep(conn_val.tv_usec);
        if(rwstate==0)
	{
		len=0;
		Memset(&u_info,0,sizeof(user_msg_info));
    		ret = recvfrom(skfd, &u_info, sizeof(user_msg_info), 0, (struct sockaddr *)&daddr, &len);
       		if(ret<0)
       		{
        		perror("recv from kernel error\n");
        		close(skfd);
			return ret;
       		}		
       		if(ret>0)	
       		{
			ret=channel_inner_write(vtcm_netlink_channel,u_info.msg,u_info.hdr.nlmsg_len-NLMSG_HDRLEN);	
			if(ret<u_info.hdr.nlmsg_len-NLMSG_HDRLEN)
			{
				print_cubeerr(" write netlink channel error!\n");
				return -EINVAL;	
			}	
			print_cubeaudit("write data %d to vtcm_netlink_channel! %d \n",ret,len);
			rwstate=1;
       		}
	}
	else
	{
		len=channel_inner_read(vtcm_netlink_channel,ReadBuf,1024);
		if(len<0)
			return -EINVAL;
		if(len>0)
		{
			print_cubeaudit("read data %d from vtcm_netlink_channel!\n",len);
			nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PLOAD));
   			memset(nlh, 0, sizeof(struct nlmsghdr));
    			nlh->nlmsg_len = NLMSG_SPACE(MAX_PLOAD);
    			nlh->nlmsg_flags = 0;
    			nlh->nlmsg_type = 0;
    			nlh->nlmsg_seq = 0;
    			nlh->nlmsg_pid = saddr.nl_pid; //self port

    			memcpy(NLMSG_DATA(nlh), ReadBuf, len);
    			ret = sendto(skfd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr_nl));
    			if(!ret)
			{
        			perror("sendto error\n");
       				close(skfd);
				return -EINVAL;
			}
			rwstate=0;
		}
    	}
	    
    }
    return 0;
}
