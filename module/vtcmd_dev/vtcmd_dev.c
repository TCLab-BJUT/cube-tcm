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

#include "config.h"

#define DEBUG
#define VTCM_DEVICE_MINOR  224
#define VTCM_DEVICE_ID     "vtcm"
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
static struct semaphore vtcm_mutex;
static int major;

static struct vtcm_device
{
	char * name;
	dev_t  devno;
	BYTE uuid[DIGEST_SIZE];
	struct cdev cdev;
}vtcm_device[VTCM_DEFAULT_NUM];


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
   res = sock_create_kern(&init_net,AF_INET, SOCK_STREAM, 0, &tcmd_sock);
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
  res = tcmd_connect(vtcmd_socket_name,vtcmd_port);
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
  tcm_response.size = VTCM_CMD_BUF_SIZE;
  tcm_response.data = kmalloc(tcm_response.size, GFP_KERNEL);
  memset(tcm_response.data,0,VTCM_CMD_BUF_SIZE);
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
  down(&vtcm_mutex);


  res = tcmd_connect(vtcmd_socket_name,vtcmd_port);
  up(&vtcm_mutex);
  if (res != 0) {
    clear_bit(TCM_STATE_IS_OPEN, (void*)&module_state);
    return -EIO;
  }
// close device start
  down(&vtcm_mutex);
  tcmd_disconnect();
  up(&vtcm_mutex);
 // close device end
  return 0;
}

static int tcm_release(struct inode *inode, struct file *file)
{
  debug("%s()", __FUNCTION__);
  down(&vtcm_mutex);
  if (tcm_response.data != NULL) {
    kfree(tcm_response.data);
    tcm_response.data = NULL;
  }
//  tcmd_disconnect();
  up(&vtcm_mutex);
  clear_bit(TCM_STATE_IS_OPEN, (void*)&module_state);
  return 0;
}

static ssize_t tcm_read(struct file *file, char *buf, size_t count, loff_t *ppos)
{
  debug("%s(%zd)", __FUNCTION__, count);
  down(&vtcm_mutex);
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
  up(&vtcm_mutex);
  return count;
}

static ssize_t tcm_write(struct file *file, const char *buf, size_t count, loff_t *ppos)
{
  debug("%s(%zd)", __FUNCTION__, count);
  down(&vtcm_mutex);
  *ppos = 0;
  if (tcm_response.data != NULL) {
    kfree(tcm_response.data);
    tcm_response.data = NULL;
  }
  if (tcmd_handle_command(buf, count) != 0) { 
    count = -EILSEQ;
    tcm_response.data = NULL;
  }
  up(&vtcm_mutex);
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

    	down(&vtcm_mutex);
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
    up(&vtcm_mutex);
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

//static struct miscdevice vtcm_dev = {
//  .minor      = VTCM_DEVICE_MINOR, 
//  .name       = VTCM_DEVICE_ID, 
//  .fops       = &fops,
//};

struct class *vtcm_class;

static void char_reg_setup_cdev (struct cdev *cdev, dev_t devno)
{
    int error;
 
    cdev_init (cdev, &fops);
    cdev->owner = THIS_MODULE;
    error = cdev_add (cdev, devno , 1);
    if (error)
        printk (KERN_NOTICE "Error %d adding char_reg_setup_cdev", error);
}

int __init init_tcm_module(void)
{
  int i;
  int ret;
  dev_t devno;
/*
  int res = misc_register(&tcm_dev);
  if (res != 0) {
    error("misc_register() failed for minor %d\n", VTCM_DEVICE_MINOR);
    return res;
  }
  printk("tcmd_dev: input parameters %s : %d\n",vtcmd_socket_name,vtcmd_port);
*/
  /* initialize variables */
  sema_init(&vtcm_mutex, 1);
  module_state = 0;
  tcm_response.data = NULL;
  tcm_response.size = 0;
  tcmd_sock = NULL;
  
  ret=alloc_chrdev_region(&devno,0,VTCM_DEFAULT_NUM,VTCM_DEVICE_ID);
  if(ret<0)
	return -EINVAL;
  major=MAJOR(devno);

  printk("vtcm major devno is %d!\n",major);
  vtcm_device[0].name=kmalloc(8*VTCM_DEFAULT_NUM,GFP_KERNEL);
  if(vtcm_device[0].name==NULL)
	return -ENOMEM;
  memset(vtcm_device[0].name,0,8*VTCM_DEFAULT_NUM);


  vtcm_class = class_create(THIS_MODULE,"vtcm_dev_class");
    if(IS_ERR(vtcm_class)) 
    {
        printk("Err: failed in creating class.\n");
        return -1; 
    }

  for(i=0;i<VTCM_DEFAULT_NUM;i++)
  {
	vtcm_device[i].name=vtcm_device[0].name+8*i;
	memcpy(vtcm_device[i].name,VTCM_DEVICE_ID,4);
	vtcm_device[i].name[4]='0'+i;
	vtcm_device[i].devno=MKDEV(major,i);	
	memset(vtcm_device[i].uuid,0,DIGEST_SIZE);
        printk("create vtcm dev %s devno %d!\n",vtcm_device[i].name,vtcm_device[i].devno);
        device_create(vtcm_class,NULL, vtcm_device[i].devno, NULL, vtcm_device[i].name);
        printk("char reg dev %s cdev %p!\n",vtcm_device[i].name,&vtcm_device[i].cdev);
        char_reg_setup_cdev (&vtcm_device[0].cdev, vtcm_device[i].devno);
  }		
 

  return 0;
}

void __exit cleanup_tcm_module(void)
{
//misc_deregister(&tcm_dev);
   int i;
   dev_t devno = MKDEV(major,0);
   for(i=0;i<VTCM_DEFAULT_NUM;i++)
   {
     cdev_del (&vtcm_device[i].cdev);
     device_destroy(vtcm_class, vtcm_device[i].devno);         // delete device node under /dev//必须先删除设备，再删除class类
   }
    class_destroy(vtcm_class);                 // delete class created by us
    unregister_chrdev_region (devno, VTCM_DEFAULT_NUM);
    printk("char device exited\n");

  tcmd_disconnect();
  if (tcm_response.data != NULL) kfree(tcm_response.data);
}

module_init(init_tcm_module);
module_exit(cleanup_tcm_module);

