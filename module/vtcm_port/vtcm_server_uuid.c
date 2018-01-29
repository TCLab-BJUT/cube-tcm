#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "data_type.h"
#include "list.h"
#include "string.h"
#include "alloc.h"
#include "json.h"
#include "struct_deal.h"
#include "basefunc.h"
#include "memdb.h"
#include "message.h"

#include "connector.h"

struct connect_ack
{
	char uuid[DIGEST_SIZE];    //client's uuid
	char * client_name;	     // this client's name
	char * client_process;       // this client's process
	char * client_addr;          // client's address
	char server_uuid[DIGEST_SIZE];  //server's uuid
	char * server_name;               //server's name
	char * service;
	char * server_addr;              // server's addr
	int flags;
	char nonce[DIGEST_SIZE];
} __attribute__((packed));

struct connect_syn
{
	char uuid[DIGEST_SIZE];
	char * server_name;
	char * service;
	char * server_addr;
	int  flags;
	char nonce[DIGEST_SIZE];
}__attribute__((packed));


void * hub_get_connector_byreceiver(void * hub, char * uuid, char * name, char * service)
{
	struct tcloud_connector * this_conn, *temp_conn;
	
	int new_fd;

	temp_conn=hub_get_first_connector(hub);

	while(temp_conn!=NULL)
	{
		this_conn=temp_conn;
		temp_conn=hub_get_next_connector(hub);
		
		if(this_conn->conn_type==CONN_CHANNEL)
		{
			struct connect_proc_info * connect_extern_info;
			connect_extern_info=(struct connect_proc_info *)(this_conn->conn_extern_info);
			if(connect_extern_info==NULL)
				continue;
			if(uuid!=NULL)
			{
				if(strncmp(uuid,connect_extern_info->uuid,64)!=0)
					continue;
			}
			if(name==NULL)
				return this_conn;
			if(strcmp(this_conn->conn_name,name)==0)
				return this_conn;		
		}
		else if(this_conn->conn_type==CONN_CLIENT)
		{
			struct connect_syn * connect_extern_info;
			connect_extern_info=(struct connect_syn *)(this_conn->conn_extern_info);
			if(connect_extern_info==NULL)
				continue;
			if(uuid!=NULL)
			{
				if(strncmp(uuid,connect_extern_info->uuid,64)!=0)
					continue;
			}
			if(name!=NULL)
			{
				if(strncmp(name,connect_extern_info->server_name,64)!=0)
					continue;
			}
			if(service==NULL)
				return this_conn;
			if(strcmp(connect_extern_info->service,service)==0)
				return this_conn;		

		}
	}
	return NULL;
}

void * hub_get_connector_bypeeruuid(void * hub,char * uuid)
{
	int ret;
	int i;
	TCLOUD_CONN * conn;
	BYTE conn_uuid[DIGEST_SIZE];

	conn=hub_get_first_connector(hub);
	
	while(conn!=NULL)
	{	

		if(connector_get_type(conn)==CONN_CLIENT)
		{
			struct connect_syn * syn_info=(struct connect_syn *)(conn->conn_extern_info);
			if(syn_info!=NULL)
			{
				comp_proc_uuid(syn_info->uuid,syn_info->server_name,conn_uuid);
				if(strncmp(conn_uuid,uuid,DIGEST_SIZE)==0)
					break;
			}

		}
		else if(connector_get_type(conn)==CONN_CHANNEL)
		{
			struct connect_proc_info * channel_info=(struct connect_ack *)(conn->conn_extern_info);
			if(channel_info!=NULL)
			{
				comp_proc_uuid(channel_info->uuid,channel_info->proc_name,conn_uuid);
				if(strncmp(conn_uuid,uuid,DIGEST_SIZE)==0)
					break;
			}

		}
		conn=hub_get_next_connector(hub);
	}
	return conn;

}

void * build_server_syn_message(char * service,char * local_uuid,char * proc_name)
{
	void * message_box;
	struct connect_syn * server_syn;
	MSG_HEAD * message_head;
	void * syn_template;
	BYTE * blob;
	int record_size;
	int retval;

	server_syn=malloc(sizeof(struct connect_syn));
	if(server_syn == NULL)
		return -ENOMEM;

	Memset(server_syn,0,sizeof(struct connect_syn));
	
	Memcpy(server_syn->uuid,local_uuid,DIGEST_SIZE);
	server_syn->server_name=dup_str(proc_name,0);

	if(service!=NULL)
	{
		server_syn->service=dup_str(service,0);
	}
	message_box=message_create(DTYPE_MESSAGE,SUBTYPE_CONN_SYNI,NULL); // SYNI
	if(message_box==NULL)
		return -EINVAL;
	if(IS_ERR(message_box))
		return -EINVAL;
	retval=message_add_record(message_box,server_syn);

//	message_head->state=MSG_FLOW_INIT;
	message_set_state(message_box,MSG_FLOW_INIT);
	printf("init message success!\n");
	return message_box;

}

void * build_client_ack_message(void * message_box,char * local_uuid,char * proc_name,void * conn)
{
	MSG_HEAD * message_head;
	struct connect_ack  * client_ack;
	struct connect_syn  * server_syn;
	int retval;
	void * ack_template;
	int record_size;
	void * blob;
	struct tcloud_connector * temp_conn=conn;
	void * new_msg;

	client_ack=malloc(sizeof(struct connect_ack));
	if(client_ack==NULL)
		return -ENOMEM;
//	server_syn=malloc(sizeof(struct connect_syn));
//	if(server_syn==NULL)
//		return -ENOMEM;

	Memset(client_ack,0,sizeof(struct connect_ack));
		// monitor send a new image message
	retval=message_get_record(message_box,&server_syn,0);

	if(retval<0)
		return -EINVAL;
	if(server_syn==NULL)
		return -EINVAL;
	temp_conn->conn_extern_info=server_syn;

	Memcpy(client_ack->uuid,local_uuid,DIGEST_SIZE);
//	client_ack->client_name=dup_str("unknown machine",0);
	client_ack->client_name=dup_str(proc_name,0);
	client_ack->client_process=dup_str(proc_name,0);
	client_ack->client_addr=dup_str("unknown addr",0);

	Memcpy(client_ack->server_uuid,server_syn->uuid,DIGEST_SIZE);
	client_ack->server_name=dup_str(server_syn->server_name,0);
	client_ack->service=dup_str(server_syn->service,0);
	client_ack->server_addr=dup_str(server_syn->server_addr,0);
	client_ack->flags=server_syn->flags;
	strncpy(client_ack->nonce,server_syn->nonce,DIGEST_SIZE);

	new_msg=message_create(DTYPE_MESSAGE,SUBTYPE_CONN_ACKI,message_box); //ACKI
	if(new_msg==NULL)
		return -EINVAL;

	
//	message_head=message_get_head(new_msg);
//	message_head->state=MSG_FLOW_INIT;
	message_set_state(new_msg,MSG_FLOW_INIT);
	retval=message_add_record(new_msg,client_ack);
	return new_msg;
}

int receive_local_client_ack(void * message_box,void * conn,void * hub)
{
	MSG_HEAD * message_head;
	struct connect_ack  * client_ack;
	int retval;
	struct tcloud_connector * channel_conn=conn;
	void * ack_template;
	int record_size;
	void * blob;
	struct connect_proc_info * channel_info;


	client_ack=malloc(sizeof(struct connect_ack));
	if(client_ack==NULL)
		return -ENOMEM;
	Memset(client_ack,0,sizeof(struct connect_ack));


	channel_info=malloc(sizeof(struct connect_proc_info));
	if(channel_info==NULL)
		return -ENOMEM;
	Memset(channel_info,0,sizeof(struct connect_proc_info));
//	channel_info->channel_state=PROC_CHANNEL_RECVACK;
	channel_conn->conn_extern_info=channel_info;

//	retval=load_message_record(message_box,&client_ack);
	retval=message_get_record(message_box,&client_ack,0);

	if(retval<0)
		return -EINVAL;

	channel_conn->conn_ops->setname(channel_conn,client_ack->client_name);

	BYTE conn_uuid[DIGEST_SIZE];

	comp_proc_uuid(client_ack->uuid,client_ack->client_process,conn_uuid);

	TCLOUD_CONN * temp_conn=hub_get_connector_bypeeruuid(hub,conn_uuid);
	if(temp_conn!=NULL)
	{
		((TCLOUD_CONN_HUB *)hub)->hub_ops->del_connector(hub,temp_conn);
		temp_conn->conn_ops->disconnect(temp_conn);
	}
	
	Memcpy(channel_info->uuid,client_ack->uuid,DIGEST_SIZE);
	channel_info->proc_name=dup_str(client_ack->client_process,0);
	channel_info->channel_name=NULL;
	channel_info->islocal=1;
//	channel_info->channel_state=PROC_CHANNEL_READY;
	
	connector_setstate(channel_conn,CONN_CHANNEL_HANDSHAKE);
	return 0;

}

