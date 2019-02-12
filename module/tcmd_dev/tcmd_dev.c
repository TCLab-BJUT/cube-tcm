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
#include <linux/poll.h>
#include <linux/slab.h>

#include <linux/socket.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/un.h>
#include <net/net_namespace.h>

#include "config.h"

#define DEBUG
#define TCM_DEVICE_MINOR  224
#define TCM_DEVICE_ID     "tcm"
#define TCM_MODULE_NAME   "tcmd_dev"

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
MODULE_AUTHOR("Mario Strasser <mast@gmx.net>");
MODULE_DESCRIPTION("Trusted Platform Module (TCM) Emulator");
MODULE_SUPPORTED_DEVICE(TCM_DEVICE_ID);

/* module parameters */
char *tcmd_socket_name = TCM_SOCKET_NAME;
module_param(tcmd_socket_name, charp, 0444);
MODULE_PARM_DESC(tcmd_socket_name, " Sets the name of the TCM daemon socket.");

int tcmd_port=6543;
module_param(tcmd_port, int, 0444);
MODULE_PARM_DESC(tcmd_port, " Sets the port number of the TCM daemon socket.");
/* TCM lock */
static struct semaphore tcm_mutex;

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
//  tcm_addr->sin_port=htons(TCM_SOCKET_PORT);
//  tcm_addr->sin_addr.s_addr=in_aton(TCM_SOCKET_NAME);
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
  return 0;
}

static void tcmd_disconnect(void)
{
  if (tcmd_sock != NULL)
  {	
//	 kernel_sock_shutdown(tcmd_sock, SHUT_RDWR);	
	 tcmd_sock->ops->release(tcmd_sock);
  	tcmd_sock = NULL;
  }	
}

static int tcmd_handle_command(const uint8_t *in, uint32_t in_size)
{
  int res;
  mm_segment_t oldmm;
  struct msghdr send_msg,recv_msg;
  struct kvec send_vec,recv_vec;

// open device start
  res = tcmd_connect(tcmd_socket_name,tcmd_port);
 // open device end

  /* send command to tcmd */
  memset(&send_msg, 0, sizeof(send_msg));
  memset(&send_vec, 0, sizeof(send_vec));
  send_vec.iov_base = (void*)in;
  send_vec.iov_len = in_size;
//  msg.msg_iov = &iov;
//  msg.msg_iovlen = 1;
  debug("%s(%p %d)", __FUNCTION__,in,in_size);
  res = kernel_sendmsg(tcmd_sock, &send_msg, &send_vec,1,in_size);
  if (res < 0) {
    error("sock_sendmsg() failed: %d\n", res);
    return res;
  }
  /* receive response from tcmd */
  tcm_response.size = TCM_CMD_BUF_SIZE;
  tcm_response.data = kmalloc(tcm_response.size, GFP_KERNEL);
  memset(tcm_response.data,0,TCM_CMD_BUF_SIZE);
//  debug("%s(%d %d)", __FUNCTION__, res, tcm_response.size);
  if (tcm_response.data == NULL) return -1;
  memset(&recv_msg, 0, sizeof(recv_msg));
  memset(&recv_vec, 0, sizeof(recv_vec));
  recv_vec.iov_base = (void*)tcm_response.data;
  recv_vec.iov_len = tcm_response.size;
//  msg.msg_iov = &iov;
//  msg.msg_iovlen = 1;
  oldmm = get_fs();
  set_fs(KERNEL_DS);
  res = kernel_recvmsg(tcmd_sock, &recv_msg,&recv_vec,1,tcm_response.size, 0);
  set_fs(oldmm);
  if (res < 0) {
    error("sock_recvmsg() failed: %d\n", res);
    tcm_response.data = NULL;
    return res;
  }
  tcm_response.size = res;

// close device start
  tcmd_disconnect();
 // close device end

  return 0;
}

static int tcm_open(struct inode *inode, struct file *file)
{
  int res;
  debug("%s()", __FUNCTION__);
  if (test_and_set_bit(TCM_STATE_IS_OPEN, (void*)&module_state)) return -EBUSY;
  down(&tcm_mutex);


  res = tcmd_connect(tcmd_socket_name,tcmd_port);
  up(&tcm_mutex);
  if (res != 0) {
    clear_bit(TCM_STATE_IS_OPEN, (void*)&module_state);
    return -EIO;
  }
// close device start
  down(&tcm_mutex);
  tcmd_disconnect();
  up(&tcm_mutex);
 // close device end
  return 0;
}

static int tcm_release(struct inode *inode, struct file *file)
{
  debug("%s()", __FUNCTION__);
  down(&tcm_mutex);
  if (tcm_response.data != NULL) {
    kfree(tcm_response.data);
    tcm_response.data = NULL;
  }
//  tcmd_disconnect();
  up(&tcm_mutex);
  clear_bit(TCM_STATE_IS_OPEN, (void*)&module_state);
  return 0;
}

static ssize_t tcm_read(struct file *file, char *buf, size_t count, loff_t *ppos)
{
  debug("%s(%zd)", __FUNCTION__, count);
  down(&tcm_mutex);
  if (tcm_response.data != NULL) {
    count = min(count, (size_t)tcm_response.size - (size_t)*ppos);
    count -= copy_to_user(buf, &tcm_response.data[*ppos], count);
    *ppos += count;
    if ((size_t)tcm_response.size == (size_t)*ppos) {
      kfree(tcm_response.data);
      tcm_response.data = NULL;
    }
  } else {
    count = 0;
  }
  up(&tcm_mutex);
  return count;
}

static ssize_t tcm_write(struct file *file, const char *buf, size_t count, loff_t *ppos)
{
  debug("%s(%zd)", __FUNCTION__, count);
  down(&tcm_mutex);
  *ppos = 0;
  if (tcm_response.data != NULL) {
    kfree(tcm_response.data);
    tcm_response.data = NULL;
  }
  if (tcmd_handle_command(buf, count) != 0) { 
    count = -EILSEQ;
    tcm_response.data = NULL;
  }
  up(&tcm_mutex);
  return count;
}

#define TCMIOC_CANCEL   _IO('T', 0x00)
#define TCMIOC_TRANSMIT _IO('T', 0x01)

static long tcm_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
   int ret;
        unsigned char * pbuf;	
	uint32_t count;
 	pbuf=kmalloc(6,GFP_KERNEL);
	if(pbuf==NULL)
		return -ENOMEM;
    if (cmd == TCMIOC_TRANSMIT) {
	ret=copy_from_user(pbuf,(void *)arg,6);
	if(ret!=0)
	{
    		error("tcm_ioctl() failed: %d\n", ret);
		return ret;
	}			
    	count = ntohl(*(uint32_t *)(pbuf+2));
//  	debug("%s(%d, %d)", __FUNCTION__, cmd, count);
	if(count>6)
	{
		kfree(pbuf);
		pbuf=kmalloc(count,GFP_KERNEL);
		if(pbuf==NULL)
			return -ENOMEM;
	}
	ret=copy_from_user(pbuf,(void *)arg,count);
	if(ret!=0)
	{
    		error("tcm_ioctl() failed: %d\n", ret);
		return ret;
	}			

    	down(&tcm_mutex);
    	if (tcm_response.data != NULL) {
     	 kfree(tcm_response.data);
      	tcm_response.data = NULL;
    }
    if (tcmd_handle_command(pbuf, count) == 0) {
      tcm_response.size -= copy_to_user((char*)arg, tcm_response.data, tcm_response.size);
      kfree(tcm_response.data);
      tcm_response.data = NULL;
    } else {
      tcm_response.size = 0;
      tcm_response.data = NULL;
    }
    up(&tcm_mutex);
    kfree(pbuf);
    return tcm_response.size;
  }
  return -1;
}

struct file_operations fops = {
  .owner   = THIS_MODULE,
  .open    = tcm_open,
  .release = tcm_release,
  .read    = tcm_read,
  .write   = tcm_write,
  .unlocked_ioctl = tcm_ioctl,
};

static struct miscdevice tcm_dev = {
  .minor      = TCM_DEVICE_MINOR, 
  .name       = TCM_DEVICE_ID, 
  .fops       = &fops,
};

int __init init_tcm_module(void)
{
  int res = misc_register(&tcm_dev);
  if (res != 0) {
    error("misc_register() failed for minor %d\n", TCM_DEVICE_MINOR);
    return res;
  }
  printk("tcmd_dev: input parameters %s : %d\n",tcmd_socket_name,tcmd_port);
  /* initialize variables */
  sema_init(&tcm_mutex, 1);
  module_state = 0;
  tcm_response.data = NULL;
  tcm_response.size = 0;
  tcmd_sock = NULL;
  return 0;
}

void __exit cleanup_tcm_module(void)
{
  misc_deregister(&tcm_dev);
  tcmd_disconnect();
  if (tcm_response.data != NULL) kfree(tcm_response.data);
}

module_init(init_tcm_module);
module_exit(cleanup_tcm_module);

