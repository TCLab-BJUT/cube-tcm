#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <dlfcn.h>

#include <sys/ipc.h>
#include <sys/shm.h>


#include "data_type.h"
#include "alloc.h"
#include "list.h"
#include "attrlist.h"
#include "memfunc.h"
#include "basefunc.h"
#include "struct_deal.h"
#include "crypto_func.h"
#include "channel.h"
#include "memdb.h"
#include "message.h"
#include "connector.h"
#include "ex_module.h"
#include "sys_func.h"
#include "tcm_constants.h"
#include "app_struct.h"
#include "pik_struct.h"
#include "sm3.h"
#include "sm4.h"

#include "tsmd.h"


static  BYTE Buf[DIGEST_SIZE*32];
static  BYTE Output[DIGEST_SIZE*32];
Record_List sessions_list;
Record_List contexts_list;
TCM_PUBKEY * pubEK;
TCM_SECRET ownweAuth;
TCM_SECRET smkAuth;
Record_List entitys_list;
static CHANNEL * vtcm_caller;

extern BYTE * CAprikey;
extern unsigned long * CAprilen;
extern BYTE * CApubkey;

    static key_t sem_key;
    static int semid;

    static key_t shm_share_key;
    static int shm_share_id;
    static int shm_size;

TCM_SESSION_DATA * Create_AuthSession_Data(TCM_ENT_TYPE * type,BYTE * auth,BYTE * nonce)
{
  TCM_SESSION_DATA * authdata=Dalloc0(sizeof(*authdata),NULL);
  if(authdata==NULL)
    return NULL;
  authdata->entityTypeByte=*type;
  Memcpy(authdata->nonceEven,nonce,TCM_HASH_SIZE);
  Memcpy(authdata->sharedSecret,auth,TCM_HASH_SIZE);
  return authdata;	
}

TCM_AUTHHANDLE Build_AuthSession(TCM_SESSION_DATA * authdata,void * tcm_out_data)
{
  BYTE auth[TCM_HASH_SIZE];
  struct tcm_out_APCreate * apcreate_out = tcm_out_data;
  authdata->SERIAL=apcreate_out->sernum;

  // Build shareSecret
  Memcpy(Buf,authdata->nonceEven,TCM_HASH_SIZE);
  Memcpy(authdata->nonceEven,apcreate_out->nonceEven,TCM_HASH_SIZE);
  Memcpy(Buf+TCM_HASH_SIZE,apcreate_out->nonceEven,TCM_HASH_SIZE);
  Memcpy(auth,authdata->sharedSecret,TCM_HASH_SIZE);
  sm3_hmac(auth,TCM_HASH_SIZE,Buf,TCM_HASH_SIZE*2,authdata->sharedSecret);

  if(authdata->entityTypeByte!=TCM_ET_NONE)
  {
    //	check the authcode

  }
  authdata->handle=apcreate_out->authHandle;
  // add authdata to the session_list

  Record_List * record = Calloc0(sizeof(*record));
  if(record==NULL)
    return -EINVAL;
  INIT_LIST_HEAD(&record->list);
  record->record=authdata;
  List_add_tail(&record->list,&sessions_list.list);
  return authdata->handle;	
}


TCM_SESSION_DATA * Find_AuthSession(TCM_ENT_TYPE type, TCM_AUTHHANDLE authhandle)
{
  Record_List * record;
  Record_List * head;
  struct List_head * curr;
  TCM_SESSION_DATA * authdata;

  head=&(sessions_list.list);
  curr=head->list.next;

  while(curr!=head)
  {
    record=List_entry(curr,Record_List,list);
    authdata=record->record;
    if(authdata==NULL)
      return NULL;
    if(type==0)
    {
      if(authdata->handle==authhandle)
        return authdata;
    }

    if(authdata->entityTypeByte==type)
    {
      if(type==TCM_ET_NONE)
        return authdata;
      if(authdata->handle==authhandle)
        return authdata;
    }
    curr=curr->next;
  }
  return NULL;
}

struct context_init * share_init_context;

int tsmd_init(void * sub_proc,void * para)
{
    int ret;
    struct tsmd_init_para * init_para=para;
    if(para==NULL)
	return -EINVAL;
    vtcm_caller=channel_find(init_para->channel_name);

    if(vtcm_caller==NULL)
    {
	print_cubeerr("tsm's tcm channel does not exist!,enter no tcm running state!\n");
	return 0;	
    }	

   INIT_LIST_HEAD(&sessions_list.list);
   sessions_list.record=NULL;

   INIT_LIST_HEAD(&contexts_list.list);
   contexts_list.record=NULL;
  
    char * pathname="/tmp";

//   build the sem_key 
    sem_key = ftok(pathname,0x01);

    if(sem_key==-1)

    {
        printf("ftok sem_key error");
        return -1;
    }

    printf("sem_key=%d\n",sem_key) ;
    semid=semget(sem_key,1,IPC_CREAT|IPC_EXCL|0666);
    if(semid<0)
    {
	printf("open share semaphore failed!\n");
	return -EINVAL;
    }

   // build the share shm key
    shm_share_key = ftok(pathname,0x02);

    if(shm_share_key==-1)

    {
        printf("ftok shm_share_key error");
        return -1;
    }

    printf("shm_share_key=%d\n",shm_share_key) ;
    shm_size=sizeof(*share_init_context);
    shm_share_id=shmget(shm_share_key,shm_size,IPC_CREAT|IPC_EXCL|0666);
    if(shm_share_id<0)
    {
	printf("open share memory failed!\n");
	return -EINVAL;
    }
    share_init_context=(struct context_init *)shmat(shm_share_id,NULL,0);
		
    set_semvalue(semid,2);	

    return 0;
}

int tsmd_start(void * sub_proc,void * para)
{

    int ret;
    int retval;
    int i,j;
    int argv_offset;	
    char namebuffer[DIGEST_SIZE*4];


    static void * shm_share_addr;

    static CHANNEL * shm_channel;


    while(1)
    {
           usleep(time_val.tv_usec);

	   if(share_init_context->handle!=0)
	   {
		semaphore_v(semid,1);
	   }
	   
    }	

    return ret;
}
