#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <dirent.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <termios.h>

#include "data_type.h"
#include "errno.h"
#include "alloc.h"
#include "string.h"
#include "basefunc.h"
#include "struct_deal.h"
#include "crypto_func.h"
#include "memdb.h"
#include "message.h"
#include "ex_module.h"

#include "sys_func.h"
#include "file_struct.h"
#include "../../include/app_struct.h"
#include "../../include/connect_struct.h"
#include "../../include/key_manage.h"


//static struct timeval time_val={0,50*1000};

static int  state=0;
static enum TAC_node_type curr_node_type=0;
static enum TAC_layer_type curr_proc_layer=0;


int get_password(const char *prompt,char * passwd);   

int proc_cmd_ioport_start(void * sub_proc,void * para);
int proc_keyset_info(void * sub_proc,void * para);

int cmd_ioport_init(void * sub_proc,void * para)
{
	system("stty erase ^H");
	return 0;
}

int cmd_ioport_start(void * sub_proc,void * para)
{
	int ret;
	int retval;
	void * recv_msg;
	void * send_msg;
	void * context;
	void * sock;
	BYTE uuid[DIGEST_SIZE];
	int i;
	int type;
	int subtype;

	print_cubeaudit("begin cmd_ioport %s!\n",ex_module_getname(sub_proc));
	
	

	while(1)
	{
		usleep(time_val.tv_usec);
		ret=ex_module_recvmsg(sub_proc,&recv_msg);
		if(ret<0)
			continue;
		if(recv_msg==NULL)
			continue;

		if(state == 0)
		{
			state=1;
			ret=proc_cmd_ioport_start(sub_proc,para);
			if(ret<0)
				return ret;
			continue;
		}


 		type=message_get_type(recv_msg);
		subtype=message_get_subtype(recv_msg);
/*		
		if((type==DTYPE_CONNECT_INFO)&&(subtype==SUBTYPE_CONNECT_LOGIN_RESPONSE))
		{
			proc_login_response(sub_proc,recv_msg);
			continue;
		}
*/
		if((type==DTYPE_TAC_KEY_MANAGE)&&(subtype==SUBTYPE_TRUST_REQUEST))
		{
			proc_trust_request(sub_proc,recv_msg);
			continue;
		}
/*
		if((type==DTYPE_TAC_KEY_MANAGE)&&(subtype==SUBTYPE_SESSION_KEYBLOB))
		{
			// the last step of key exchange
			proc_session_keyblob(sub_proc,recv_msg);
			continue;
		}
		if((type==DTYPE_TAC_KEY_MANAGE)&&(subtype==SUBTYPE_QUOTE_REPORT))
		{
			// the beginning of integrity check
			ex_module_sendmsg(sub_proc,recv_msg);
			continue;
		}
*/
		if((type==DTYPE_TAC_KEY_MANAGE)&&(subtype==SUBTYPE_REMOTE_KEYSET))
		{
			// the beginning of integrity check
			proc_keyset_info(sub_proc,recv_msg);
			continue;
		}
		
		
	}

	return 0;
};


int proc_cmd_ioport_start(void * sub_proc,void * para)
{
	int ret;
	int i;
	int len;

	BYTE  buf[DIGEST_SIZE*2];
	BYTE digest[DIGEST_SIZE];
	char proc_name[DIGEST_SIZE];
	void * send_msg;

	struct TAC_login_input * login_input;
	struct TAC_trust_pass * trust_pass;
	struct start_para * start_para=para;

	print_cubeaudit("begin proc cmd_ioport start\n");

	ret=proc_share_data_getvalue("proc_name",proc_name);

	for(i=0;i<3;i++)
	{
		if(Strncmp(proc_name,trust_proc[i],Strlen(trust_proc[i]))==0)
		{
			curr_proc_layer=TAC_LAYER_TRUST;
			curr_node_type=i+1;
			break;
		}	
	}
	if(curr_proc_layer==0)
	{
		for(i=0;i<3;i++)
		{
			if(Strncmp(proc_name,control_proc[i],Strlen(control_proc[i]))==0)
			{
				curr_proc_layer=TAC_LAYER_CONTROL;
				curr_node_type=i+1;
				break;
			}
		}	
	}
	if(curr_proc_layer==0)
	{
		for(i=0;i<3;i++)
		{
			if(Strncmp(proc_name,integrity_proc[i],Strlen(integrity_proc[i]))==0)
			{
				curr_proc_layer=TAC_LAYER_INTEGRITY;
				curr_node_type=i+1;
				break;
			}
		}	
	}
	
	
	if(curr_proc_layer==TAC_LAYER_TRUST)
	{
		trust_pass=Talloc0(sizeof(*trust_pass));
		if(trust_pass==NULL)
			return -ENOMEM;
		if(start_para->argc==1)
		{
			get_password("可信根属主密钥: ",trust_pass->owner_pass);
			printf("\n");
			get_password("存储可信根密钥: ",trust_pass->smk_pass);
			printf("\n");
		}
		else if(start_para->argc==3)
		{
			Strncpy(trust_pass->owner_pass,start_para->argv[1],DIGEST_SIZE);
			Strncpy(trust_pass->smk_pass,start_para->argv[2],DIGEST_SIZE);
			printf("从命令行获取口令,执行登录过程！\n");
		}
		else
		{
			printf("输入格式错误！");
			exit(-EINVAL);
		}
		send_msg=message_create(DTYPE_CONNECT_INFO,SUBTYPE_TRUST_PASS,NULL);
		if(send_msg==NULL)
			return -EINVAL;
		message_add_record(send_msg,trust_pass);
		ex_module_sendmsg(sub_proc,send_msg);
	}	
	else if(curr_proc_layer==TAC_LAYER_CONTROL)
	{
		login_input=Talloc0(sizeof(*login_input));
		if(login_input==NULL)
			return -ENOMEM;
		if(start_para->argc==1)
		{
			switch(curr_node_type)
			{
				case TAC_PM:
					printf("服务器用户名: ");
					break;
				case TAC_AC:
					printf("网关用户名: ");
					break;
				case TAC_AR:
					printf("终端用户名: ");
					break;
				default:
					return -EINVAL;
			}
			fgets(login_input->user,DIGEST_SIZE-1,stdin);
			len=Strlen(login_input->user);
			if(login_input->user[len-1]=='\n')
				login_input->user[len-1]=0;
			get_password("用户口令: ",login_input->passwd);
			printf("\n");
		}
		else if(start_para->argc==3)
		{
			Strncpy(login_input->user,start_para->argv[1],DIGEST_SIZE);
			Strncpy(login_input->passwd,start_para->argv[2],DIGEST_SIZE);
			printf("从命令行获取口令,执行登录过程！\n");
		}
		else
		{
			printf("输入格式错误！");
			exit(-EINVAL);
		}
		send_msg=message_create(DTYPE_CONNECT_INFO,SUBTYPE_LOGIN_INPUT,NULL);
		if(send_msg==NULL)
			return -EINVAL;
		message_add_record(send_msg,login_input);
		ex_module_sendmsg(sub_proc,send_msg);
	}	
	
	return 0;
}

int proc_keyset_info(void * sub_proc,void * recv_msg)
{
	int ret;
	struct TAC_remote_keyset * remote_keyset;
	BYTE local_uuid[DIGEST_SIZE];
	BYTE user_name[DIGEST_SIZE];
	char buf[DIGEST_SIZE*3];

	ret=proc_share_data_getvalue("uuid",local_uuid);
	ret=proc_share_data_getvalue("user_name",user_name);
	
	ret=message_get_record(recv_msg,&remote_keyset,0);
	if(ret<0)
		return ret;
	if(Memcmp(local_uuid,remote_keyset->machine_uuid,DIGEST_SIZE)==0)
	{
		if(Strncmp(user_name,remote_keyset->user_name,DIGEST_SIZE)==0)
		{
			printf("本地密钥检查通过！\n");
		}
		else
		{
//			printf("错误:本地密钥用户名不匹配！\n");
		}
	}	
	else
	{
		Memset(buf,0,DIGEST_SIZE*3);
		digest_to_uuid(remote_keyset->machine_uuid,buf);
		printf("收到远程密钥信息!\n");
		printf("机器UUID %s \n用户名 %s \n",buf,remote_keyset->user_name);
	}
	return 0;
}

int proc_trust_request(void * sub_proc,void * recv_msg)
{
	int ret;
	int i;
	void * send_msg;

	char buf[DIGEST_SIZE*3];

	struct TAC_trust_request * trust_request;
	struct connect_login_data * login_data;

	ret=message_get_record(recv_msg,&trust_request,0);
	if(ret<0)
		return ret;
	
	switch(trust_request->type)
	{
		case TAC_REQUEST_KEYSTATE:
			printf("检查密钥状态!\n");
			break;
		case TAC_REQUEST_PUBKEY:
			printf("请求公钥数据!\n");
			break;
		case TAC_GET_PUBKEY:
			printf("获取公钥数据!\n");
			Memset(buf,0,DIGEST_SIZE*3);
			digest_to_uuid(trust_request->machine_uuid,buf);
			printf("机器UUID %s \n用户名 %s \n",buf,trust_request->user_name);
			break;
		case TAC_REQUEST_SYMMKEY:
			break;
		case TAC_REQUEST_QUOTE:
			break;
		default:
			return -EINVAL;
	}
	
	return 0;
}

char getch()
 {    
    char c;
    system("stty -echo");
    system("stty erase ^H");
    system("stty -icanon");
    c=getchar();
    system("stty icanon");
    system("stty echo");
    return c;
 }    

int get_password(const char *prompt,char * passwd)   
{
    static char buffer[DIGEST_SIZE];
    int i = 0;
    char letter = '\0';

    printf(prompt);
    while((i<DIGEST_SIZE-1)&&(letter!='\n'))
    //如果没有按回车并且达到最大长度 
    {
        letter = getch();
        if(letter == '\b')
        //如果是退格符，表示要删除前面输入的一个字符 
        {
            if(i>0)
            //如果以前输入自符 
            {
                passwd[--i] = '\0'; //从缓冲区中删除最有一个字符 
                putchar('\b'); //光标位置前移一个字符位置 
                putchar(' '); //将要删除的字符(回显的*)从屏幕中置为空白 
                putchar('\b'); //光标位置前移一个字符位置
            } 
            else
            {
                putchar(7); //响铃
            }
        }
        else if(letter != '\n')
        //如果按下回车 
        {
            passwd[i++] = letter;
            putchar('*');
        }
    }
    passwd[i] = '\0'; //设置字符串结束标志 
    return i;
}
