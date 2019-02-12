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
#include "channel.h"
#include "connector.h"
#include "ex_module.h"
#include "sys_func.h"

#include "app_struct.h"
#include "vtcm_struct.h"
#include "vtcm_tcp_channel.h"

#define MAX_LINE_LEN 1024

static char * tcp_addr;
static int tcp_port;
static struct tcloud_connector_hub * conn_hub;
static CHANNEL * vtcm_tcp_channel;

static BYTE Buf[DIGEST_SIZE*64];
static int index = 0;
static BYTE * ReadBuf=Buf+DIGEST_SIZE*32;
static int readbuf_len;

static void * default_conn = NULL;
struct tcloud_connector * server_conn;
static void * extend_template;


struct default_conn_index
{
    BYTE uuid[DIGEST_SIZE];
    BYTE ek_uuid[DIGEST_SIZE];
    int vtcm_no;
};

static int conn_count=0;

int _channel_set_recv_conn(BYTE * Buf,void * conn)
//本函数用于改写模块者实现一个为连接设置属性的函数。缺省属性设置为连接接入的次序
{
	struct default_conn_index * conn_index;
	TCLOUD_CONN * set_conn=conn;
	if(conn==NULL)
		return -EINVAL;
	if(set_conn->conn_extern_info==NULL)
	{
		conn_index=Dalloc0(sizeof(*conn_index),set_conn);
		if(conn_index==NULL)
			return -EINVAL;
		set_conn->conn_extern_info=conn_index;
		conn_count++;
		conn_index->vtcm_no=0;
	}
	return 0;
}

int _channel_get_send_conn(BYTE * Buf,int length,void **conn)
//本函数用于改写模块者实现一个根据缓冲区确定写连接对象和连接长度的函数，缺省设置为
//连接编号和写入数据长度
{
	struct default_conn_index * conn_index;
 	struct vtcm_external_input_command *output_data;
	int extend_size=struct_size(extend_template);
	int ret;

	if(length<extend_size)
		return 0;

       	output_data = (struct vtcm_external_input_command *)Talloc0(extend_size) ;
       	ret = blob_2_struct(Buf, output_data,extend_template);
	if(ret<0)
		return -EINVAL;

	TCLOUD_CONN * temp_conn;
	temp_conn=hub_get_first_connector(conn_hub);
	while(temp_conn!=NULL)
	{
		conn_index=temp_conn->conn_extern_info;
		if(conn_index!=NULL)
		{
			if(conn_index->vtcm_no==0)
			{
				break;
			}
		}
		temp_conn=hub_get_next_connector(conn_hub);
	}
	
	*conn=temp_conn;
	
	return output_data->paramSize;
}



int vtcm_tcp_channel_init(void * sub_proc,void * para)
{
    struct tcp_init_para * init_para=para;
    int ret;

    conn_hub = get_connector_hub();

    if(conn_hub==NULL)
	return -EINVAL;
    server_conn	= get_connector(CONN_SERVER,AF_INET);
    if((server_conn ==NULL) & IS_ERR(server_conn))
    {
         printf("get conn failed!\n");
         return -EINVAL;
    }
 
    Strcpy(Buf,init_para->tcp_addr);
    Strcat(Buf,":");
    Itoa(init_para->tcp_port,Buf+Strlen(Buf));

    ret=server_conn->conn_ops->init(server_conn,"tcp_channer_server",Buf);
    if(ret<0)
	return ret;
    conn_hub->hub_ops->add_connector(conn_hub,server_conn,NULL);

    ret=server_conn->conn_ops->listen(server_conn);
    fprintf(stdout,"test server listen,return value is %d!\n",ret);

    vtcm_tcp_channel=channel_register(init_para->channel_name,CHANNEL_RDWR,sub_proc);
    if(vtcm_tcp_channel==NULL)
	return -EINVAL;
    extend_template=memdb_get_template(DTYPE_VTCM_EXTERNAL,SUBTYPE_INPUT_COMMAND_EXTERNAL) ;
    if(extend_template==NULL)
    {
    	printf("load extend template error!\n");
    	return -EINVAL;
    }

    return 0;
}

int vtcm_tcp_channel_start(void * sub_proc,void * para)
{
    int ret = 0, len = 0, i = 0, j = 0;
    int rc = 0;

    struct tcloud_connector *recv_conn;
    struct tcloud_connector *temp_conn;
    struct timeval conn_val;
    conn_val.tv_sec=time_val.tv_sec;
    conn_val.tv_usec=time_val.tv_usec;

    while(1)
    {
        ret = conn_hub->hub_ops->select(conn_hub, &conn_val);
        usleep(conn_val.tv_usec);
    	conn_val.tv_usec = time_val.tv_usec;
        if (ret > 0) {
            do {
                recv_conn = conn_hub->hub_ops->getactiveread(conn_hub);
                if (recv_conn == NULL)
                    break;
        	usleep(conn_val.tv_usec);
                if (connector_get_type(recv_conn) == CONN_SERVER)
                {
                    struct tcloud_connector * channel_conn;
		    char * peer_addr;
                    channel_conn = recv_conn->conn_ops->accept(recv_conn);
                    if(channel_conn == NULL)
                    {
                        printf("error: server connector accept error %p!\n", channel_conn);
                        continue;
                    }
                    connector_setstate(channel_conn, CONN_CHANNEL_ACCEPT);
                    printf("create a new channel %p!\n", channel_conn);
//		    channel_conn->conn_ops->write(channel_conn,"test",5);

                    conn_hub->hub_ops->add_connector(conn_hub, channel_conn, NULL);
		    // should add a start message
		    if(channel_conn->conn_ops->getpeeraddr!=NULL)
		    {
			peer_addr=channel_conn->conn_ops->getpeeraddr(channel_conn);
			if(peer_addr!=NULL)
				printf("build channel to %s !\n",peer_addr);	
			_channel_set_recv_conn(NULL,channel_conn);
                    }	
			

                }
                else if (connector_get_type(recv_conn) == CONN_CHANNEL)
                {
                    printf("conn peeraddr %s send message\n", recv_conn->conn_peeraddr);
                    rc = 0;
                    len = recv_conn->conn_ops->read(recv_conn, Buf, 1024);
                    if (len < 0) {
                        perror("read error");
           //           conn_hub->hub_ops->del_connector(conn_hub, recv_conn);
                    } else if (len == 0) {
                        printf("peer close\n");
                        conn_hub->hub_ops->del_connector(conn_hub, recv_conn);
                    } 
 		    else
		    {
			_channel_set_recv_conn(Buf,recv_conn);
			ret=channel_inner_write(vtcm_tcp_channel,Buf,len);	
			if(ret<len)
			{
				printf(" read Buffer overflow!\n");
				return -EINVAL;	
			}	
			
                    }
                }
            } while (1);
        }
	else
	{
		int len=0;
		TCLOUD_CONN * send_conn=NULL;
		len=channel_inner_read(vtcm_tcp_channel,ReadBuf+readbuf_len,1024-readbuf_len);
		if(len<0)
			return -EINVAL;
		if(len>0)
		{
			readbuf_len+=len;
			len=_channel_get_send_conn(ReadBuf,1024,&send_conn);
			if(len>0)
			{
				ret=send_conn->conn_ops->write(send_conn,ReadBuf,len);
				if(ret<len)
					return -EINVAL;
				if(readbuf_len>ret)
				{
					Memcpy(ReadBuf,ReadBuf+ret,readbuf_len-ret);
				}
				readbuf_len-=ret;	
			}
		}
	 }		
	    
    }
    return 0;
}


struct tcloud_connector * getConnectorByIp(struct tcloud_connector_hub *hub, char *ip)
{
    struct tcloud_connector * conn =  hub_get_first_connector(hub);

    // find Ip's conn
    while (conn != NULL)
    {
        if (connector_get_type(conn) == CONN_CHANNEL)
        {
            // printf("conn peeraddr %s\n", conn->conn_peeraddr);
            if (conn->conn_peeraddr != NULL && !Strncmp(conn->conn_peeraddr, ip, Strlen(ip)))
                return conn;
        }
        conn = hub_get_next_connector(hub);
    }
    return NULL;
}

/*
 * debug in use
 *
 */
void printAllConnect(struct tcloud_connector_hub *hub)
{
    printf("All Connector Channel\n");
    struct tcloud_connector * conn =  hub_get_first_connector(hub);

    // find Ip's conn
    while (conn != NULL)
    {
        if (connector_get_type(conn) == CONN_CHANNEL)
        {
            printf("conn peeraddr %s\n", conn->conn_peeraddr);
        }
        conn = hub_get_next_connector(hub);
    }
}
