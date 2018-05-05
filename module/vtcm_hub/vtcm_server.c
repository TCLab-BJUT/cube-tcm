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
#include "connector.h"
#include "ex_module.h"
#include "connector_value.h"
#include "sys_func.h"


#include "vtcm_server.h"
#include "app_struct.h"

#define MAX_LINE_LEN 1024

static unsigned char messagebuf[1024];
static int index = 0;
static char errorbuf[1024];

// static FILE *fin;
// static FILE *fout;

struct connector_config
{
    char name[DIGEST_SIZE * 2];
    int  family;
    int  type;
    char  *address;
    int  port;
    int  attr;
}__attribute__((packed));

static NAME2VALUE connector_family_valuelist[] = 
{
    {"AF_INET", AF_INET},
    {"AF_UNIX", AF_UNIX},
    {NULL, 0}
};

enum conn_config_attr
{
    CONN_ATTR_DEFAULT = 0x01,
    CONN_ATTR_STOP = 0x8000,
};

static NAME2VALUE connector_attr_valuelist[] =
{
    {"DEFAULT",CONN_ATTR_DEFAULT},
    {"STOP",CONN_ATTR_STOP},
    {NULL,0}
};

static struct struct_elem_attr connector_config_desc[] =
{
    {"name",CUBE_TYPE_STRING,DIGEST_SIZE*2,NULL,NULL},
    {"family",CUBE_TYPE_ENUM,sizeof(int),&connector_family_valuelist,NULL},
    {"type",CUBE_TYPE_ENUM,sizeof(int),&connector_type_valuelist,NULL},
    {"address",CUBE_TYPE_ESTRING,DIGEST_SIZE*2,NULL,NULL},
    {"port",CUBE_TYPE_INT,sizeof(int),NULL,NULL},
    {"attr",CUBE_TYPE_ENUM,sizeof(int),&connector_attr_valuelist,NULL},
    {NULL,CUBE_TYPE_ENDDATA,0,NULL,NULL}
};

static void * default_conn = NULL;

static void * conn_cfg_template = NULL;

NodeList uuid_ip;

struct tcloud_connector * getConnectorByIp(struct tcloud_connector_hub *, char *);
void printAllConnect(struct tcloud_connector_hub *hub);

void traversList(NodeList list)
{
    Node *cur = list->next;
    while (cur)
    {
        printf("UUID:");
        int i;
        for (i = 0; i < DIGEST_SIZE; ++i)
        {
            printf("%c", cur->uuid[i]);
        }
        printf(" ===> ");
        printf("ip: %s\n", cur->ip);
        cur = cur->next;
    }
}


// format UUID=ip;
int initUUIDIpMap(NodeList *list, const char *configfile) 
{
    int ret = 0;
    ret = initList(list); 
    if (ret < 0)
        return ret;
    FILE *file = fopen(configfile, "r");
    if (file == NULL)
        printf("can't find uuid_ip.conf\n");
    char line[MAX_LINE_LEN];
    char ip[MAX_LINE_LEN], uuid[MAX_LINE_LEN];
    Node * cur = (*list);
    while (NULL != fgets(line, MAX_LINE_LEN, file)) 
    {
        int i = 0, j = 0;  
        Node *p = (Node*)malloc(sizeof(Node));
        line[Strlen(line) - 1] = '\0';
        char *delim = strchr(line, '=');
        if (delim == NULL)
            continue;
        // UUID
        for (i = 0, j = 0; i < delim - line && j < DIGEST_SIZE; ++i) {
            if (line[i] != '-') {
                (p->uuid)[j] = line[i];
                ++j;
            }
        }
        // ip
        Strcpy(p->ip, delim + 1);

	// compute 
	calculate_context_sm3(p->uuid,Strnlen(p->uuid,DIGEST_SIZE),p->hash_id);
	
        LIST_ADD(cur, p);     
        cur = cur->next;
    }
    return ret;
}

int getCmdLen(unsigned char * buffer)
{
    unsigned int i;                                                         
    uint32_t result = 0;
    for (i = 0 ; i < 4 ; i++) {
        result <<= 8;
        result |= buffer[i];   
    }
    return result;
}
/*
 * int message_read_from_conn(void **message,void * conn)
 * {
 *     const int fixed_buf_size=4096;
 *     char readbuf[fixed_buf_size];
 *     void * message_box;
 *     MSG_HEAD * message_head;
 *     int offset=0;
 *     int ret;
 *     int retval;
 *     int flag;
 *     struct tcloud_connector * temp_conn = conn;
 *     int message_size;
 * 
 *     ret = read_message_from_src(message, conn,
 *             (int (*)(void *, char *, int))temp_conn->conn_ops->read);
 *     if (ret <= 0)
 *         return ret;
 *     offset = ret;
 *     flag = message_get_flag(*message);
 *     if(!(flag & MSG_FLAG_CRYPT))
 *     {
 *         ret = message_load_record(*message);
 *         if(ret<0)
 *         {
 *             printf("load record failed in message_read_from_conn! use bin format\n");
 *         }
 *     }
 * 
 *     ret = message_load_expand(*message);
 *     return offset;           // all the message's data are read
 * }
 */


/*
 * Read text data from config file,
 * ignore the ^# line and remove the \n character
 * stream: the config file stream
 * buf: the buffer to store the cfg data
 * size: read data size
 * return value: read data size,
 * negative value if it has special error
 */
int read_conn_cfg_buffer(FILE * stream, char * buf, int size)
{
    long offset = 0;
    long curr_offset;
    char buffer[MAX_LINE_LEN];
    char * retptr;
    int len;
    while (offset < size)
    {
        curr_offset = ftell(stream);
        retptr = fgets(buffer, MAX_LINE_LEN, stream);
        // end of the file
        if(retptr == NULL)
            break;
        len = Strlen(buffer);
        if(len == 0)
            break;
        // commet line
        if(buffer[0]=='#')
            continue;
        while((buffer[len-1] == '\r') || (buffer[len - 1] == '\n'))
        {
            len--;
            if(len == 0)
                continue;
            buffer[len] == 0;
        }
        // this line is too long to read
        if (len > size)
            return -EINVAL;
        // out of the bound
        if (len + offset > size)
        {
            fseek(stream, curr_offset, SEEK_SET);
            break;
        }
        Memcpy(buf + offset, buffer, len);
        offset += len;
    }
    return offset;
}

int read_one_connector(void ** connector,void * json_node)
{
    void * conn_cfg_node;
    void * temp_node;
    char buffer[1024];
    int ret;
    struct connector_config * temp_cfg;

    struct tcloud_connector * conn = NULL;

    if(json_node != NULL)
    {
        temp_cfg = malloc(sizeof(struct connector_config));
        ret = json_2_struct(json_node, temp_cfg, conn_cfg_template);
        if(ret < 0)
            return -EINVAL;
        conn = get_connector(temp_cfg->type, temp_cfg->family);
        if(conn == NULL)
            return -EINVAL;

        switch (temp_cfg->family) {
        case AF_INET:
            sprintf(buffer,"%s:%d", temp_cfg->address, temp_cfg->port);
            break;
        default:
            return -EINVAL;
        }

        ret = conn->conn_ops->init(conn, temp_cfg->name, buffer);
        if(ret<0)
        {
            printf("init conn %s failed!\n", temp_cfg->name);
            return -EINVAL;
        }

    }
    // read the router policy
    // first,read the main router policy
    *connector = conn;
    if(temp_cfg->attr == CONN_ATTR_DEFAULT)
    {
        if(default_conn != NULL)
        {
            printf("not unique default conn!\n");
            return -EINVAL;
        }
        default_conn = conn;
    }
    return 0;
}

int connector_read_cfg(char * filename,void * hub)
{
    const int bufsize = 4096;
    char buffer[bufsize];
    int read_offset;
    int solve_offset;
    int buffer_left = 0;
    int conn_num = 0;
    void *conn;
    int ret;
    void *root;
    struct tcloud_connector_hub *conn_hub = (struct tcloud_connector_hub *)hub;
    int i;

    FILE * fp = fopen(filename, "r");
    if (fp == NULL)
        return -EINVAL;
    do {
        // when the file reading is not finished, we should read new data to the buffer
        if (fp != NULL)
        {
            read_offset = read_conn_cfg_buffer(fp, buffer+buffer_left, bufsize - buffer_left);
            if (read_offset < 0)
                return -EINVAL;
            else if(read_offset < bufsize - buffer_left)
            {
                fclose(fp);
                fp = NULL;
            }
        }
        printf("conn %d is %s\n", conn_num + 1, buffer);

        solve_offset = json_solve_str(&root, buffer);
        if(solve_offset <= 0)
        {
            if(conn_num > 0)
                return conn_num;
            return -EINVAL;
        }

        ret = read_one_connector(&conn, root);

        if (ret < 0)
            return -EINVAL;
        conn_num++;
        conn_hub->hub_ops->add_connector(conn_hub , conn, NULL);
        buffer_left = read_offset - solve_offset;
        if (buffer_left > 0)
        {
            Memcpy(buffer, buffer + solve_offset, buffer_left);
            buffer[buffer_left] = 0;
        }
        else
        {
            if (fp == NULL)
                break;
        }
    } while (1);
    return conn_num;
}

struct connector_proc_pointer
{
    void * hub;
    void * default_local_conn;
    void * default_remote_conn;
};

int vtcm_server_init(void * sub_proc,void * para)
{
    int ret;
    char * config_file ="./vtcm_hub_config.cfg";
    char * uuid_ip_file = "uuid_ip.conf"; 
    struct connector_proc_pointer * sub_proc_pointer;
    struct conn_init_para * conn_init_para = (struct conn_init_para *)para;
    // fin = fopen("cmdwrite", "wb");
    // fout = fopen("cmdread", "wb");

    ret = initUUIDIpMap(&uuid_ip, uuid_ip_file);
    if (ret < 0)
    {
        printf("map init error\n");
        return ret;
    }
    printf("uuid_ip init\n");
    traversList(uuid_ip);

    if (para != NULL)
        config_file = para;

    struct tcloud_connector_hub * conn_hub;
    conn_hub = get_connector_hub();

    conn_cfg_template = create_struct_template(connector_config_desc);
    sub_proc_pointer = malloc(sizeof(struct connector_proc_pointer));
    if (sub_proc_pointer == NULL)
        return -ENOMEM;
    Memset(sub_proc_pointer, 0, sizeof(struct connector_proc_pointer));
    sub_proc_pointer->hub = conn_hub;
    ret = ex_module_setpointer(sub_proc, sub_proc_pointer);
    if (ret < 0)
        return ret;
    ret = connector_read_cfg(config_file, conn_hub);
    if (ret < 0)
        return ret;
    printf("read %d connector!\n",ret);

    struct tcloud_connector * temp_conn;
    temp_conn = hub_get_first_connector(conn_hub);

    // start all the SERVER
    while (temp_conn != NULL)
    {
        if (connector_get_type(temp_conn) == CONN_SERVER)
        {
            ret=temp_conn->conn_ops->listen(temp_conn);
            if(ret<0)
            {
                printf("conn server %s listen error!\n",connector_getname(temp_conn));
                return -EINVAL;
            }
            printf("conn server %s begin to listen!\n",connector_getname(temp_conn));
        }
        temp_conn = hub_get_next_connector(conn_hub);
    }
    return 0;
}

int vtcm_server_start(void * sub_proc,void * para)
{
    int ret = 0, len = 0, i = 0, j = 0;
    int rc = 0;

    void * extend_template=memdb_get_template(DTYPE_VTCM_EXTERNAL,SUBTYPE_INPUT_COMMAND_EXTERNAL) ;//get the head of the template

    if(extend_template==NULL)
    {
        printf("load extend template error!\n");
        return -EINVAL;
    }

    struct tcloud_connector *recv_conn;
    struct tcloud_connector *temp_conn;

    struct timeval conn_val;
    conn_val.tv_usec = time_val.tv_usec;
    struct connector_proc_pointer * sub_proc_pointer;
    sub_proc_pointer = ex_module_getpointer(sub_proc);
    if(sub_proc_pointer == NULL)
        return -EINVAL;
    struct tcloud_connector_hub * hub = sub_proc_pointer->hub;
    if((hub == NULL) || IS_ERR(hub))
        return -EINVAL;
    // start all the CLIENT
    temp_conn = hub_get_first_connector(hub);

    while (temp_conn != NULL)
    {
        if (connector_get_type(temp_conn) == CONN_CLIENT)
        {
            for (i = 0; i < 180; i++)
            {
                ret = temp_conn->conn_ops->connect(temp_conn);
                if (ret >= 0)
                {
                    break;
                }
                usleep(50);
            }

        }
        temp_conn = hub_get_next_connector(hub);
    }

    for (;;)
    {
        ret = hub->hub_ops->select(hub, &conn_val);
        usleep(conn_val.tv_usec);
        conn_val.tv_usec = time_val.tv_usec;
        if (ret > 0) {
            do {
                recv_conn = hub->hub_ops->getactiveread(hub);
                if (recv_conn == NULL)
                    break;
                if (connector_get_type(recv_conn) == CONN_SERVER)
                {
                    struct tcloud_connector * channel_conn;
                    channel_conn = recv_conn->conn_ops->accept(recv_conn);
                    if(channel_conn == NULL)
                    {
                        printf("error: server connector accept error %p!\n", channel_conn);
                        continue;
                    }
                    connector_setstate(channel_conn, CONN_CHANNEL_ACCEPT);
                    printf("create a new channel %p!\n", channel_conn);
                    hub->hub_ops->add_connector(hub, channel_conn, NULL);
                }
                else if (connector_get_type(recv_conn) == CONN_CHANNEL)
                {
                    printf("conn peeraddr %s send message\n", recv_conn->conn_peeraddr);
                    rc = 0;
                    len = recv_conn->conn_ops->read(recv_conn, messagebuf, 1024);
                    if (len < 0) {
                        perror("read error");
                        hub->hub_ops->del_connector(hub, recv_conn);
                    } else if (len == 0) {
                        printf("peer close\n");
                        hub->hub_ops->del_connector(hub, recv_conn);
                    } else {
                        for (i = 0; i < len; ++i)
                        {
                            printf("%02X ", messagebuf[i]);
                        }
                        printf("\n");

                        struct vtcm_external_input_command *output_data;
                        int extend_size = struct_size(extend_template);

                        char * json_str[256];
                        output_data = (struct vtcm_external_input_command *)malloc(extend_size) ;
                        ret = blob_2_struct(messagebuf, output_data,extend_template) ;
                        ret = struct_2_json(output_data,json_str,extend_template) ;
                        printf("convert struct to %d size json str: %s\n",ret,json_str) ;
                        usleep(time_val.tv_usec) ;
                        void * command_template = memdb_get_template(DTYPE_VTCM_IN,output_data->ordinal) ;//Get the entire command template
                        if(command_template == NULL)
                        {
                            printf("can't solve this command!\n");

                        }
                        else 
                        {
                            void* startup_input = malloc(struct_size(command_template));
                            ret = blob_2_struct(messagebuf,startup_input,command_template);
                            void * send_msg = message_create(DTYPE_VTCM_IN,output_data->ordinal,NULL);// create message
                            if(send_msg == NULL)
                                return -EINVAL;
                            // Add the structure of the command to the message
                            message_add_record(send_msg,startup_input);
                            char peerIp[IP_SIZE];
                            BYTE *hash_id = getHashIDByIp(uuid_ip, recv_conn->conn_peeraddr);
                            if (hash_id != NULL) {
                                struct uuid_record  *record = Talloc0(sizeof(*record));
				Memcpy(record->uuid,hash_id,DIGEST_SIZE);
                                message_add_expand_data(send_msg, DTYPE_MESSAGE, SUBTYPE_UUID_RECORD, record);
                            }
                            // send the message
                            ret = ex_module_sendmsg(sub_proc,send_msg);
                        }
                    }
                }
            } while (1);
        }
        void *message_box ;

        while(ex_module_recvmsg(sub_proc,&message_box)>=0)
        {
            if(message_box==NULL)
                break ;
            printf("Receive from State :\n");
            MSG_HEAD * message_head;
            message_head=message_get_head(message_box);

            unsigned char sendbuf[1 << 8] = {0};
            void * record;
            void * out_msg_template=memdb_get_template(message_head->record_type,message_head->record_subtype);
            int  blob_size;
            record=malloc(struct_size(out_msg_template));

            ret = message_get_record(message_box,&record,0);

            blob_size=struct_2_blob(record, sendbuf,out_msg_template);

            int cmdlen = getCmdLen(sendbuf + 2);
            printf("response cmd size %d\n", cmdlen);

            struct tcloud_connector * send_conn = NULL;

            int i;
            MSG_EXPAND  *msg_expand;
	    struct uuid_record * expand_uuid;

 	    ret=  message_get_define_expand(message_box, &msg_expand, DTYPE_MESSAGE,SUBTYPE_UUID_RECORD);
	    if(ret<0)
	    {
		printf("fatal error in get expand from response message!\n");
		continue;
	    }
	    if(msg_expand==NULL)
	    {
		printf("orphan response message!\n");
		continue;	
	    }
	    expand_uuid=msg_expand->expand;

            for(i = 0 ;i < blob_size ; ++i)
            {
                printf("%02X  ",sendbuf[i]) ;
            }
            printf("\n") ;
            printf("blobsize %d\n", blob_size);
            // send_conn = getConnectorByIp(hub, "172.21.4.32");
	    char * ip=getIpByHashID(uuid_ip,expand_uuid->uuid);
	   
            if(ip==NULL)
	    {
		printf("can't find vtcm's ip\n");
		continue;
	    }
            send_conn = getConnectorByIp(hub, ip);
            if (send_conn != NULL) {
                printf("write to conn peeraddr %s\n", send_conn->conn_peeraddr);
                int len = send_conn->conn_ops->write(send_conn, sendbuf, blob_size);
                if (len == cmdlen)
                    printf("write success\n");
                //   if (send_conn->conn_ops->disconnect(send_conn))
                //        printf("close error\n");
                //   hub->hub_ops->del_connector(hub, recv_conn);
            }
	    else
	    {
                printf("write to conn ip %s failed!\n", ip);
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
