/* Software-based Trusted Platform Module (TCM) Emulator
 * Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
 *
 * This module is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * $Id: tcmd_dev.c 459 2011-02-13 16:27:55Z mast $
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/slab.h>

#include <linux/socket.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/un.h>
#include <net/net_namespace.h>
#include <linux/completion.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/time.h>
#include <linux/delay.h>

#include "config.h"

#define DEBUG
#define VTCM_DEVICE_MINOR  224
#define VTCM_DEVICE_ID     "vtcm"
#define TCM_DEVICE_ID     "tcm"
#define TCM_MODULE_NAME   "vtcmd_dev"

#define TCM_STATE_IS_OPEN 0

#ifdef DEBUG
#define debug(fmt, ...) printk(KERN_DEBUG "%s %s:%d: Debug: " fmt "\n", \
                        TCM_MODULE_NAME, __FILE__, __LINE__, ## __VA_ARGS__)
#else
#define debug(fmt, ...)
#endif
#define info(fmt, ...)  printk(KERN_INFO "%s %s:%d: Info: " fmt "\n", \
                        TCM_MODULE_NAME, __FILE__, __LINE__, ## __VA_ARGS__)
#define error(fmt, ...) printk(KERN_ERR "%s %s:%d: Error: " fmt "\n", \
                        TCM_MODULE_NAME, __FILE__, __LINE__, ## __VA_ARGS__)
#define alert(fmt, ...) printk(KERN_ALERT "%s %s:%d: Alert: " fmt "\n", \
                        TCM_MODULE_NAME, __FILE__, __LINE__, ## __VA_ARGS__)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hu Jun");
MODULE_DESCRIPTION("Virtual Trusted Cryptography Module (VTCM) Emulator");
MODULE_SUPPORTED_DEVICE(VTCM_DEVICE_ID);

/* module parameters */
char *vtcmd_socket_name = VTCM_SOCKET_NAME;
module_param(vtcmd_socket_name, charp, 0444);
MODULE_PARM_DESC(vtcmd_socket_name, " Sets the name of the VTCM daemon socket.");

int vtcmd_port=6543;
module_param(vtcmd_port, int, 0444);
MODULE_PARM_DESC(vtcmd_port, " Sets the port number of the TCM daemon socket.");
/* TCM lock */
//static struct semaphore vtcm_mutex;
static int major;

enum vtcm_state {
	VTCM_STATE_WAIT=1,
	VTCM_STATE_SEND,
	VTCM_STATE_RECV,
	VTCM_STATE_RET,
	VTCM_STATE_ERR=0x1001
};

enum vtcm_action{
	VTCM_ACTION_NONE=1,
	VTCM_ACTION_IOCTL,
	VTCM_ACTION_RW
	
}vtcm_action;
static struct vtcm_device
{
	char * name;
	dev_t  devno;
	BYTE uuid[DIGEST_SIZE];
	BYTE * data_buf;
	BYTE * cmd_buf;
	BYTE * res_buf;
	struct cdev cdev;
	struct completion vtcm_notice;
	enum vtcm_state state;
	enum vtcm_action action;
	u64 timeout;
}vtcm_device[VTCM_DEFAULT_NUM];

static struct task_struct *vtcm_io_task;
const int maxwaittime=500000;

/* TCM command response */
static struct {
  uint8_t *data;
  uint32_t size;
} tcm_response;

/* module state */
static uint32_t module_state;
static struct socket *tcmd_sock;
//static struct sockaddr_un addr;
static struct sockaddr addr;

/* TCM_TAG (Command and Response Tags) rev 100

   These tags indicate to the TCM the construction of the command either as input or as output. The
   AUTH indicates that there are one or more AuthData values that follow the command
   parameters.
*/

#define TCM_TAG_RQU_COMMAND             0xC100 /* A command with no authentication.  */
#define TCM_TAG_RQU_AUTH1_COMMAND       0xC200 /* An authenticated command with one authentication
                                                  handle */
#define TCM_TAG_RQU_AUTH2_COMMAND       0xC300 /* An authenticated command with two authentication
                                                  handles */
#define TCM_TAG_RSP_COMMAND             0xC400 /* A response from a command with no authentication
                                                */
#define TCM_TAG_RSP_AUTH1_COMMAND       0xC500 /* An authenticated response with one authentication
                                                  handle */
#define TCM_TAG_RSP_AUTH2_COMMAND       0xC600 /* An authenticated response with two authentication
                                                  handles */

// vtcm special TAG
#define TCM_TAG_RQU_VTCM_COMMAND        0xD100 /* An authenticated response with two authentication
                                                  handles */
#define TCM_TAG_RSP_VTCM_COMMAND       	0xD400 /* An authenticated response with two authentication
                                                  handles */
#define TCM_TAG_RQU_MANAGE_COMMAND      0xE100 /* An authenticated response with two authentication
                                                  handles */
#define TCM_TAG_RSP_MANAGE_COMMAND      0xE400 /* An authenticated response with two authentication
                                                  handles */

struct vtcm_manage_cmd_head
{
    u16 tag;
    int paramSize;
    u16 vtcm_no;	
    u16 cmd;
}__attribute__((packed));

struct vtcm_manage_return_head
{
    u16 tag;
    int paramSize;
    u16 vtcm_no;	
    u16 returnCode;
}__attribute__((packed));

static int tcmd_connect(char *socket_name,int port)
{
  int res;
  struct sockaddr_in * tcm_addr;
//   res = sock_create(PF_UNIX, SOCK_STREAM, 0, &tcmd_sock);
   res = sock_create_kern(AF_INET, SOCK_STREAM, 0, &tcmd_sock);
  if (res != 0) {
    error("sock_create_kern() failed: %d\n", res);
    tcmd_sock = NULL;
    return res;
  }
//  addr.sun_family = AF_UNIX;
  tcm_addr =(struct sockaddr_in *)&addr;
  tcm_addr->sin_family=AF_INET;
//  tcm_addr->sin_port=htons(VTCM_SOCKET_PORT);
//  tcm_addr->sin_addr.s_addr=in_aton(VTCM_SOCKET_NAME);
  tcm_addr->sin_addr.s_addr=in_aton(socket_name);
  tcm_addr->sin_port=htons(port);
  memset(&(tcm_addr->sin_zero),'\0',8);
//  strncpy(addr.sun_path, socket_name, sizeof(addr.sun_path));
//  strncpy(addr.sa_data, &tcm_addr, sizeof(addr.sa_data));
  res = tcmd_sock->ops->connect(tcmd_sock, 
    (struct sockaddr*)&addr, sizeof(struct sockaddr), 0);
//    (struct sockaddr*)&addr, sizeof(struct sockaddr_un), 0);
  if (res != 0) {
    error("sock_connect() failed: %d\n", res);
    tcmd_sock->ops->release(tcmd_sock);
    tcmd_sock = NULL;
    return res;
  }
  printk("connect tcmd_sock!\n");
  return 0;
}

static void tcmd_disconnect(void)
{
  if (tcmd_sock != NULL)
  {	
//	 kernel_sock_shutdown(tcmd_sock, SHUT_RDWR);	
	printk("close tcmd_sock!\n");
	tcmd_sock->ops->release(tcmd_sock);
  	tcmd_sock = NULL;
  }	
}

static int tcmd_send_comm(const uint8_t *in, uint32_t in_size)
{
  int res;
  struct msghdr send_msg;
  struct kvec send_vec;


  /* send command to tcmd */
  memset(&send_msg, 0, sizeof(send_msg));
  memset(&send_vec, 0, sizeof(send_vec));
  send_vec.iov_base = (void*)in;
  send_vec.iov_len = in_size;
//  msg.msg_iov = &iov;
//  msg.msg_iovlen = 1;
//  debug("%s(%p %d)", __FUNCTION__,in,in_size);
  res = kernel_sendmsg(tcmd_sock, &send_msg, &send_vec,1,in_size);
  if (res < 0) {
    error("sock_sendmsg() failed: %d\n", res);
    return res;
  }

  return 0;
}

static int tcmd_recv_comm(uint8_t *out,uint32_t *out_size)
{
  int res;
  mm_segment_t oldmm;
  struct msghdr recv_msg;
  struct kvec recv_vec;

  /* receive response from tcmd */
//  tcm_response.size = VTCM_CMD_BUF_SIZE;
//  tcm_response.data = kmalloc(tcm_response.size, GFP_KERNEL);
  memset(out,0,*out_size);
// debug("%s(%d %d)", __FUNCTION__, *out_size, tcm_response.size);
  if (out == NULL) return -1;
  memset(&recv_msg, 0, sizeof(recv_msg));
  memset(&recv_vec, 0, sizeof(recv_vec));
  recv_vec.iov_base = (void*)out;
  recv_vec.iov_len = *out_size;
//  msg.msg_iov = &iov;
//  msg.msg_iovlen = 1;
  

  oldmm = get_fs();
  set_fs(KERNEL_DS);
  res = kernel_recvmsg(tcmd_sock, &recv_msg,&recv_vec,1,*out_size, MSG_DONTWAIT);
  set_fs(oldmm);
  if (res < 0) {
 //     tcm_response.data = NULL;
 //  	debug("%s( receive data error %d)", __FUNCTION__,res);
      return res;
  }
  *out_size = res;

//  if(*out_size>0)
//  	debug("%s(%p %d)", __FUNCTION__,out,*out_size);

  return 0;
}

static int tcm_open(struct inode *inode, struct file *file)
{
  debug("%s()", __FUNCTION__);
//  if (test_and_set_bit(TCM_STATE_IS_OPEN, (void*)&module_state)) return -EBUSY;
//  down(&vtcm_mutex);


// close device start
//  down(&vtcm_mutex);
//  tcmd_disconnect();
//  up(&vtcm_mutex);
 // close device end
  return 0;
}

static int tcm_release(struct inode *inode, struct file *file)
{
  debug("%s()", __FUNCTION__);
//  down(&vtcm_mutex);
  if (tcm_response.data != NULL) {
    kfree(tcm_response.data);
    tcm_response.data = NULL;
  }
//  tcmd_disconnect();
//  up(&vtcm_mutex);
//  clear_bit(TCM_STATE_IS_OPEN, (void*)&module_state);
  return 0;
}

static ssize_t tcm_read(struct file *file, char *buf, size_t count, loff_t *ppos)
{
        int ret;
	uint32_t read_size=0;
        struct inode *inode =
                    file->f_path.dentry->d_inode;
        int minor = MINOR(inode->i_rdev);

	struct vtcm_device * vtcm_dev=&vtcm_device[minor];

//      debug("%s(%zd)", __FUNCTION__, count);


	while(vtcm_dev->state!=VTCM_STATE_RET)
	{
		if(vtcm_dev->state==VTCM_STATE_ERR)
		{
        		debug("%s meets error state!\n", __FUNCTION__);
			// reset vtcm_dev 
			vtcm_dev->state=VTCM_STATE_WAIT;
			return -EINVAL;
		}
		if(vtcm_dev->action!=VTCM_ACTION_RW)
		{
        		debug("%s no read cmd", __FUNCTION__);
			return 0;
		}	
		if((vtcm_dev->state==VTCM_STATE_SEND)
			||(vtcm_dev->state==VTCM_STATE_RECV))
		{
			if(vtcm_dev->timeout!=0)
			{
				int outtime = jiffies_to_msecs(get_jiffies_64()-vtcm_dev->timeout);
				if(outtime > maxwaittime)
				{	
        				debug("%s wait %d ms!\n", __FUNCTION__, outtime);
					vtcm_dev->state=VTCM_STATE_ERR;
					vtcm_dev->timeout=0;
					return 0;
				}
			}
		}
		msleep(10);
	}

	if(vtcm_dev->state==VTCM_STATE_RET)
	{
      		read_size = ntohl(*(uint32_t *)(vtcm_dev->res_buf+2));
      		ret=copy_to_user(buf, vtcm_dev->res_buf,read_size);
		if(ret<0)
		{
    			error("tcm_read() failed: %d\n", ret);
			return -EINVAL;
		}
		if(count<read_size)
		{
    			error("tcm_read() size too small!: %d\n", read_size);
			return -EINVAL;
		}

//		printk("finish waiting count data %d!\n",read_size);
    	}
	else
		read_size=0;
//      debug("%s(return value %d)", __FUNCTION__, read_size);
	vtcm_dev->state=VTCM_STATE_WAIT;

        return read_size;
}

static ssize_t tcm_write(struct file *file, const char *buf, size_t count, loff_t *ppos)
{
        int ret;
	uint32_t write_size=0;
        struct inode *inode =
                    file->f_path.dentry->d_inode;
        int minor = MINOR(inode->i_rdev);

	struct vtcm_device * vtcm_dev=&vtcm_device[minor];

        debug("%s(%zd)", __FUNCTION__, count);
        //  down(&vtcm_mutex);

	if(vtcm_dev->state==VTCM_STATE_ERR)
		vtcm_dev->state=VTCM_STATE_WAIT;
	if(vtcm_dev->state!=VTCM_STATE_WAIT)
		return 0;
	
	vtcm_dev->action=VTCM_ACTION_RW;
        *ppos = 0;
	if(count<10)
		return -EINVAL;

	ret=copy_from_user(vtcm_dev->cmd_buf,buf,6);
	if(ret!=0)
	{
    		error("tcm_write() failed: %d\n", ret);
		return ret;
	}			
    	write_size = ntohl(*(uint32_t *)(vtcm_dev->cmd_buf+2));
	if(write_size!=count)
	{
    		error("tcm_write() size mismatch!: %d\n", ret);
		return -EINVAL;
	}

	ret=copy_from_user(vtcm_dev->cmd_buf,buf,count);
	if(ret!=0)
	{
    		error("tcm_write() failed: %d\n", ret);
		return ret;
	}

//	printk(" write vtcm dev %p\n",vtcm_dev);
	vtcm_dev->state=VTCM_STATE_SEND;
	vtcm_dev->timeout=get_jiffies_64();
//  	debug("%s(%lld, %ld, %d)", __FUNCTION__, vtcm_dev->timeout, count,minor);

	return count;
}

#define TCMIOC_CANCEL   _IO('T', 0x00)
#define TCMIOC_TRANSMIT _IO('T', 0x01)

static long tcm_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
        int ret;
	uint32_t count=0;
        struct inode *inode =
                    file->f_path.dentry->d_inode;
        int minor = MINOR(inode->i_rdev);

	struct vtcm_device * vtcm_dev=&vtcm_device[minor];

	if(vtcm_dev->state==VTCM_STATE_ERR)
		vtcm_dev->state=VTCM_STATE_WAIT;
	if(vtcm_dev->state!=VTCM_STATE_WAIT)
		return 0;
	
	vtcm_dev->action=VTCM_ACTION_IOCTL;

        if (cmd == TCMIOC_TRANSMIT) {
		ret=copy_from_user(vtcm_dev->cmd_buf,(void *)arg,6);
		if(ret!=0)
		{
    			error("tcm_ioctl() failed: %d\n", ret);
			return ret;
		}			
    		count = ntohl(*(uint32_t *)(vtcm_dev->cmd_buf+2));

		ret=copy_from_user(vtcm_dev->cmd_buf,(void *)arg,count);
		if(ret!=0)
		{
    			error("tcm_ioctl() failed: %d\n", ret);
			return ret;
		}			
		printk(" ioctl vtcm dev %p\n",vtcm_dev);
		vtcm_dev->state=VTCM_STATE_SEND;
		vtcm_dev->timeout=get_jiffies_64();
  		debug("%s(%lld, %d, %d)", __FUNCTION__, vtcm_dev->timeout, count,minor);
		wait_for_completion(&vtcm_dev->vtcm_notice);
		if(vtcm_dev->state==VTCM_STATE_RET)
		{
      			count = ntohl(*(uint32_t *)(vtcm_dev->res_buf+2));
      			ret=copy_to_user((char*)arg, vtcm_dev->res_buf,count);

			printk("finish waiting count data %d!\n",count);
		}
    	}
	vtcm_dev->state=VTCM_STATE_WAIT;

    // split
//    if (tcmd_handle_command(vtcm_dev->cmd_buf, count) == 0) {
//    	up(&vtcm_mutex);
//    kfree(pbuf);
    return count;
}

struct file_operations fops = {
  .owner   = THIS_MODULE,
  .open    = tcm_open,
  .release = tcm_release,
  .read    = tcm_read,
  .write   = tcm_write,
  .unlocked_ioctl = tcm_ioctl,
};

//static struct miscdevice vtcm_dev = {
//  .minor      = VTCM_DEVICE_MINOR, 
//  .name       = VTCM_DEVICE_ID, 
//  .fops       = &fops,
//};

struct class *vtcm_class;

static int vtcm_io_process(void * data)
{
	int i;
	int ret;
	struct vtcm_device * device_list = (struct vtcm_device *)data;
//	const int max_time=3000;  // max delay time limit (ms)
	struct vtcm_device * vtcm_dev;
	int count;
	int response_size;
	int vtcm_no;
	BYTE * recv_buf;

	int clock=0;

	struct vtcm_manage_cmd_head * vtcm_cmd_head;
	struct vtcm_manage_return_head * vtcm_return_head;
	
	recv_buf=kmalloc(4096,GFP_KERNEL);
	if(recv_buf==NULL)
		return -ENOMEM;
	printk(" vtcm io process begin!\n");
	// open device start
//	res = tcmd_connect(vtcmd_socket_name,vtcmd_port);
	// open device end
	while(!kthread_should_stop())
	{
		if(clock==0)
			printk(" enter the process circle %p!\n",tcmd_sock);
		msleep(5);
		clock++;
		if(tcmd_sock == NULL)
		{
			int ret;
			if(clock%50==0)
			{
  				ret = tcmd_connect(vtcmd_socket_name,vtcmd_port);
				if(ret == 0)
				{
   					printk("connect succeed!\n");
				}
			}
		}

		//send process
		for(i=0;i<VTCM_DEFAULT_NUM;i++)
		{
			vtcm_dev=&device_list[i];
			if(vtcm_dev->timeout!=0)
			{
				int outtime = jiffies_to_msecs(get_jiffies_64()-vtcm_dev->timeout);
				if(outtime > maxwaittime)
				{	
					debug("vtcm %d timeout %d ms! state is %d\n",i,outtime,vtcm_dev->state);
					vtcm_dev->state=VTCM_STATE_ERR;
					vtcm_dev->timeout=0;
					if(vtcm_dev->action == VTCM_ACTION_IOCTL)
						complete(&vtcm_dev->vtcm_notice);
					continue;
				}
			}
			if((tcmd_sock!=NULL) &&(vtcm_dev->state==VTCM_STATE_SEND))
			{
				count = ntohl(*(uint32_t *)(vtcm_dev->cmd_buf+2));
				response_size=VTCM_CMD_BUF_SIZE/2;
				//printk("vtcm %d has command len %d!\n",i,count);		
		
				if(i!=0)
				{
					vtcm_cmd_head=(struct vtcm_manage_cmd_head *)(vtcm_dev->cmd_buf-sizeof(*vtcm_cmd_head));
					vtcm_cmd_head->tag=TCM_TAG_RQU_VTCM_COMMAND;
					vtcm_cmd_head->paramSize=ntohl(count+sizeof(*vtcm_cmd_head));
					vtcm_cmd_head->vtcm_no=ntohs(i+1);
					vtcm_cmd_head->cmd=0;
					ret=tcmd_send_comm(vtcm_dev->cmd_buf-sizeof(*vtcm_cmd_head),count+sizeof(*vtcm_cmd_head));
				}
				else
				{
					ret=tcmd_send_comm(vtcm_dev->cmd_buf,count);

				}
				if(ret == 0) {

					debug("send (%d %d ) ",i,count); 
					printk(" cmd (%x %x %x %x)", vtcm_dev->cmd_buf[6],vtcm_dev->cmd_buf[7],vtcm_dev->cmd_buf[8],vtcm_dev->cmd_buf[9]);
					// debug("vtcm %d send command succeed! %lld\n",i,vtcm_dev->timeout);		
					vtcm_dev->state=VTCM_STATE_RECV;
				}
				else
				{
					debug("vtcm %d send command error %d!\n",i,ret);
					vtcm_dev->state	=VTCM_STATE_ERR;	
					vtcm_dev->timeout=0;
					tcmd_sock=NULL;
					if(vtcm_dev->action==VTCM_ACTION_IOCTL)
						complete(&vtcm_dev->vtcm_notice);
						
				}
			}
			//receive process
			
			response_size=4000;
			
			if(tcmd_sock!=NULL)
			{
				if (tcmd_recv_comm(recv_buf,&response_size)==0)
				{
					if(response_size==0)
					{
						continue;
					}
					if(response_size<sizeof(*vtcm_return_head))
					{
						printk("return %d byte data less than return head size!\n",response_size);
						tcmd_sock=NULL;
						continue;
					}				
					vtcm_return_head=(struct vtcm_manage_return_head *)recv_buf;
					switch(vtcm_return_head->tag)
					{

						case TCM_TAG_RSP_COMMAND:
						case TCM_TAG_RSP_AUTH1_COMMAND:
						case TCM_TAG_RSP_AUTH2_COMMAND:
							vtcm_no=0;
							vtcm_dev=&device_list[0];
							debug("recv (%d %d) ",0,response_size); 
							if(vtcm_dev->state!=VTCM_STATE_RECV)
							{
								debug("vtcm %d's state %d error! not in recv state!\n",vtcm_no,vtcm_dev->state);
								tcmd_sock=NULL;
								break;
							}
							count=htonl(vtcm_return_head->paramSize);
							if(count>response_size)
							{
								debug("vtcm %d get cmd size error!\n",count);
								tcmd_sock=NULL;
								break;
							}
							vtcm_dev->state=VTCM_STATE_RET;
							vtcm_dev->timeout=0;
							memcpy(vtcm_dev->res_buf,recv_buf,count);
							if(vtcm_dev->action==VTCM_ACTION_IOCTL)
								complete(&vtcm_dev->vtcm_notice);

							break;	
						case TCM_TAG_RSP_VTCM_COMMAND:
							vtcm_no=htons(vtcm_return_head->vtcm_no);	
							if((vtcm_no<=0) || (vtcm_no>VTCM_DEFAULT_NUM))
							{
								debug("Invaild vtcm no %d!\n",vtcm_no);
								tcmd_sock=NULL;
								break;
							}
							vtcm_dev=&device_list[vtcm_no-1];
							debug("recv (%d %d )",vtcm_no,response_size); 

							if(vtcm_dev->state!=VTCM_STATE_RECV)
							{
								debug("vtcm %d's state error! not in recv state!\n",vtcm_no);
								tcmd_sock=NULL;
								break;
							}
							count=htonl(vtcm_return_head->paramSize);
							if(count>response_size)
							{
								printk("vtcm %d get cmd size error!\n",count);
								tcmd_sock=NULL;
								break;
							}
							vtcm_dev->state=VTCM_STATE_RET;
							vtcm_dev->timeout=0;
							memcpy(vtcm_dev->res_buf,recv_buf+sizeof(*vtcm_return_head),count-sizeof(*vtcm_return_head));
							if(vtcm_dev->action==VTCM_ACTION_IOCTL)
								complete(&vtcm_dev->vtcm_notice);

							break;
						default:
							debug("vtcm return head format error! \n");
							tcmd_sock=NULL;
							break;
					}
				
				}
			}
		}
	}
	 // close device end
	kfree(recv_buf);
	printk("exit the io process!\n");
	return 0;
}

static void char_reg_setup_cdev (struct cdev *cdev, dev_t devno)
{
    int error;
 
    cdev_init (cdev, &fops);
    cdev->owner = THIS_MODULE;
    error = cdev_add (cdev, devno , 1);
    if (error)
        printk (KERN_NOTICE "Error %d adding char_reg_setup_cdev", error);
}

int _set_name_no(int no,char * name)
{
	int offset=0;
	if(no<0)
		return -EINVAL;
	if(no>=100)
		return -EINVAL;
	if(no>9)
	{
		*(name+offset)='0'+no/10;
		offset++;
		no%=10;
	}
	*(name+offset)='0'+no;
	offset++;
	return offset;
}

int __init init_tcm_module(void)
{
  int i;
  int ret;
  dev_t devno;
  int name_offset=0;
/*
  int res = misc_register(&tcm_dev);
  if (res != 0) {
    error("misc_register() failed for minor %d\n", VTCM_DEVICE_MINOR);
    return res;
  }
  printk("tcmd_dev: input parameters %s : %d\n",vtcmd_socket_name,vtcmd_port);
*/
  /* initialize variables */
//  sema_init(&vtcm_mutex, 1);
  module_state = 0;
  tcm_response.data = NULL;
  tcm_response.size = 0;
  tcmd_sock = NULL;
  
  ret=alloc_chrdev_region(&devno,0,VTCM_DEFAULT_NUM,VTCM_DEVICE_ID);
  if(ret<0)
	return -EINVAL;
  major=MAJOR(devno);

  printk("vtcm major devno is %d!\n",major);
  vtcm_device[0].name=kmalloc(9*VTCM_DEFAULT_NUM,GFP_KERNEL);
  if(vtcm_device[0].name==NULL)
	return -ENOMEM;
  memset(vtcm_device[0].name,0,9*VTCM_DEFAULT_NUM);


  vtcm_class = class_create(THIS_MODULE,"vtcm_dev_class");
    if(IS_ERR(vtcm_class)) 
    {
        printk("Err: failed in creating class.\n");
        return -1; 
    }

  for(i=0;i<VTCM_DEFAULT_NUM;i++)
  {
	// init each vtcm_device struct
	
	vtcm_device[i].name=vtcm_device[0].name+name_offset;
	if(i==0)
	{
		memcpy(vtcm_device[i].name,TCM_DEVICE_ID,4);
		name_offset=4+1;
	}
	else
	{
		memcpy(vtcm_device[i].name,VTCM_DEVICE_ID,4);
		name_offset=4+1+_set_name_no(i,vtcm_device[i].name+4);
	}
	vtcm_device[i].devno=MKDEV(major,i);	
	memset(vtcm_device[i].uuid,0,DIGEST_SIZE);
	vtcm_device[i].data_buf=kmalloc(VTCM_CMD_BUF_SIZE,GFP_KERNEL);
	if(vtcm_device[i].data_buf==NULL)
		return -ENOMEM;
	if(vtcm_device[i].data_buf==NULL)
		return -ENOMEM;
	vtcm_device[i].cmd_buf=vtcm_device[i].data_buf+sizeof(struct vtcm_manage_cmd_head);
	vtcm_device[i].res_buf=vtcm_device[i].cmd_buf+VTCM_CMD_BUF_SIZE/2;
        printk("create vtcm dev %s devno %d!\n",vtcm_device[i].name,vtcm_device[i].devno);
        device_create(vtcm_class,NULL, vtcm_device[i].devno, NULL, vtcm_device[i].name);
        printk("char reg dev %s cdev %p!\n",vtcm_device[i].name,&vtcm_device[i].cdev);
        char_reg_setup_cdev (&vtcm_device[i].cdev, vtcm_device[i].devno);
	init_completion(&vtcm_device[i].vtcm_notice);
//	complete(&vtcm_device[i].vtcm_notice);
	vtcm_device[i].state=VTCM_STATE_WAIT;
	vtcm_device[i].action=VTCM_ACTION_NONE;
	vtcm_device[i].timeout=0;
  }		
  ret = tcmd_connect(vtcmd_socket_name,vtcmd_port);
//  up(&vtcm_mutex);
  if (ret != 0) {
      clear_bit(TCM_STATE_IS_OPEN, (void*)&module_state);
      printk("connect failed!\n");
  }
   printk("connect succeed!\n");
  vtcm_io_task = kthread_run(vtcm_io_process,vtcm_device,"vtcm_io_process");	

  return 0;
}

void __exit cleanup_tcm_module(void)
{
//misc_deregister(&tcm_dev);
   int i;
   dev_t devno = MKDEV(major,0);
   for(i=0;i<VTCM_DEFAULT_NUM;i++)
   {
       if(vtcm_device[i].data_buf!=NULL)	
             kfree(vtcm_device[i].data_buf);	
       cdev_del (&vtcm_device[i].cdev);
       device_destroy(vtcm_class, vtcm_device[i].devno);         // delete device node under /dev//必须先删除设备，再删除class类
   }
    class_destroy(vtcm_class);                 // delete class created by us
    unregister_chrdev_region (devno, VTCM_DEFAULT_NUM);
    printk("char device exited\n");
    if(tcmd_sock!=NULL)
    	tcmd_disconnect();
    if (tcm_response.data != NULL) kfree(tcm_response.data);
    if(vtcm_io_task)
    {
	printk("stop vtcm_io_process");
        kthread_stop(vtcm_io_task);
    }
}

module_init(init_tcm_module);
module_exit(cleanup_tcm_module);

