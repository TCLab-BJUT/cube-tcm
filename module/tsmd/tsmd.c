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
//#include "sm3.h"
//#include "sm4.h"

#include "tsm_typedef.h"
#include "tsm_structs.h"
#include "tspi.h"
#include "tsmd.h"
#include "tspi_internal.h"
#include "tcm_func.h"

#include "tsmd_object.h"

BYTE Buf[DIGEST_SIZE*32];
BYTE Output[DIGEST_SIZE*32];

extern Record_List sessions_list;
/*
TCM_PUBKEY * pubEK;
TCM_SECRET ownerAuth;
TCM_SECRET smkAuth;
*/
struct tsm_object_list
{
	int object_type;
	Record_List object_list;
}__attribute__((packed));

Record_List entitys_list;

CHANNEL * vtcm_caller;

/*
extern BYTE * CAprikey;
extern unsigned long * CAprilen;
extern BYTE * CApubkey;
*/
static key_t sem_key;
static int semid;

static key_t shm_share_key;
static int shm_share_id;
static int shm_size;
char * pathname="/tmp";

//int proc_tcm_GetRandom(void * tcm_in, void * tcm_out, CHANNEL * vtcm_caller);
enum tsmd_context_init_state
{
	TSMD_CONTEXT_INIT_START=0x01,
	TSMD_CONTEXT_INIT_GETREQ,
	TSMD_CONTEXT_INIT_BUILDCHANNEL,
	TSMD_CONTEXT_INIT_WAITCHANNEL,
	TSMD_CONTEXT_INIT_FINISH,
	TSMD_CONTEXT_INIT_TIMEOUT
};

enum tsmd_context_state
{
	TSMD_CONTEXT_INIT=0x01,
	TSMD_CONTEXT_BUILD,
	TSMD_CONTEXT_APICALL,
	TSMD_CONTEXT_SENDDATA,
	TSMD_CONTEXT_RECVDATA,
	TSMD_CONTEXT_APIRETURN,
	TSMD_CONTEXT_CLOSE,
	TSMD_CONTEXT_ERROR
};

typedef struct tsmd_context_struct
{
	int count;
	UINT32 handle;
	int shmid;
	enum tsmd_context_state state;
		
	int tsmd_API;
	int curr_step;
	int shm_size;
	void * tsmd_context; 	
	BYTE * tsmd_send_buf;
	BYTE * tsmd_recv_buf;
	CHANNEL * tsmd_API_channel;
}__attribute__((packed)) TSMD_CONTEXT;

typedef struct tsmd_object_struct
{
	TSM_HANDLE handle;
	TSM_HCONTEXT hContext;
	TSM_FLAG   object_type;
	TSM_FLAG   object_flag;
	void * object_struct;
}__attribute__((packed)) TSMD_OBJECT;

struct tsmd_server_struct
{
	int curr_count;
	enum tsmd_context_init_state init_state;
	Record_List contexts_list;
}__attribute__((packed));

static struct tsmd_server_struct server_context;

TSMD_CONTEXT * Find_TsmdContext(UINT32 tsmd_handle)
{
  Record_List * record;
  Record_List * head;
  struct List_head * curr;
  TSMD_CONTEXT * tsmd_context;

  head=&(server_context.contexts_list.list);
  curr=head->list.next;

  while(curr!=head)
  {
    record=List_entry(curr,Record_List,list);
    tsmd_context=record->record;
    if(tsmd_context==NULL)
       return NULL;
    if(tsmd_context->handle==tsmd_handle)
        return tsmd_context;
    curr=curr->next;
  }
  return NULL;
}

TSMD_CONTEXT * Build_TsmdContext(int count, UINT32 tsmd_nonce)
{

  TSMD_CONTEXT * new_context=NULL;
  UINT32 new_handle;
 
  do{
	RAND_bytes(&new_handle,sizeof(new_handle));
	new_handle^=tsmd_nonce ;
	if(new_handle==0)
		continue; 
	if(new_handle==tsmd_nonce)
		continue;
	new_context=Find_TsmdContext(new_handle);
  }while(new_context!=NULL);

  new_context=Dalloc0(sizeof(*new_context),NULL);
  if(new_context==NULL)
    return NULL;
  new_context->count=count;
  new_context->handle=new_handle;
  new_context->shmid=0;
  new_context->state=TSMD_CONTEXT_INIT;
  new_context->tsmd_API=0;
  new_context->curr_step=0;
  new_context->tsmd_context=NULL;
  new_context->tsmd_send_buf=Dalloc0(1024,NULL);
  new_context->tsmd_recv_buf=Dalloc0(1024,NULL);		
  new_context->tsmd_API_channel=NULL;
	
  // add authdata to the session_list

  Record_List * record = Calloc0(sizeof(*record));
  if(record==NULL)
    return -EINVAL;
  INIT_LIST_HEAD(&record->list);
  record->record=new_context;
  List_add_tail(&record->list,&server_context.contexts_list.list);
  return new_context;	
}


TSMD_OBJECT * Find_TsmdObject(UINT32 tsmd_handle)
{
  Record_List * record;
  Record_List * head;
  struct List_head * curr;
  TSMD_OBJECT * tsmd_object;

  head=&(entitys_list.list);
  curr=head->list.next;

  while(curr!=head)
  {
    record=List_entry(curr,Record_List,list);
    tsmd_object=record->record;
    if(tsmd_object==NULL)
       return NULL;
    if(tsmd_object->handle==tsmd_handle)
        return tsmd_object;
    curr=curr->next;
  }
  return NULL;
}

TSMD_OBJECT * Build_TsmdObject(UINT32 hContext, TSM_FLAG objectType,TSM_FLAG initFlags)
{

  TSMD_OBJECT * new_object=NULL;
  TSMD_CONTEXT * old_context;
  UINT32 new_handle;
 
  do{
	RAND_bytes(&new_handle,sizeof(new_handle));
	if(new_handle==0)
		continue; 
	old_context=Find_TsmdContext(new_handle);
	if(old_context!=NULL)
		continue;
	new_object=Find_TsmdObject(new_handle);	
  }while(new_object!=NULL);

  new_object=Dalloc0(sizeof(*new_object),NULL);
  if(new_object==NULL)
    return NULL;
  new_object->handle=new_handle;
  new_object->hContext=hContext;
  new_object->object_type=objectType;
  new_object->object_flag=initFlags;

  switch(new_object->object_type)
  {
	case TSM_OBJECT_TYPE_TCM:
		new_object->object_struct=Dalloc0(sizeof(struct tsmd_object_tcm),new_object);	
		break;
	case TSM_OBJECT_TYPE_KEY:
		new_object->object_struct=Dalloc0(sizeof(struct tsmd_object_policy),new_object);	
		break;
	case TSM_OBJECT_TYPE_POLICY:
		new_object->object_struct=Dalloc0(sizeof(struct tsmd_object_key),new_object);	
		break;
	case TSM_OBJECT_TYPE_PCRS:
		new_object->object_struct=Dalloc0(sizeof(struct tsmd_object_hpcrs),new_object);	
		{
			TCM_PCR_COMPOSITE * pcrComp=&((struct tsmd_object_hpcrs *)new_object->object_struct)->pcrComposite;
			pcrComp->select.sizeOfSelect=TCM_NUM_PCR/CHAR_BIT;
			
		}
		break;
	default:
		Free0(new_object);		
		return NULL;	
  }	

  // add new object to the entitys_list

  Record_List * record = Calloc0(sizeof(*record));
  if(record==NULL)
    return -EINVAL;
  INIT_LIST_HEAD(&record->list);
  record->record=new_object;
  List_add_tail(&record->list,&entitys_list.list);
  return new_object;	
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

   INIT_LIST_HEAD(&entitys_list.list);
   entitys_list.record=NULL;

   INIT_LIST_HEAD(&server_context.contexts_list.list);
   server_context.contexts_list.record=NULL;
  

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
		

    server_context.curr_count=1;
    INIT_LIST_HEAD(&server_context.contexts_list.list);
    server_context.init_state=TSMD_CONTEXT_INIT_START;
    share_init_context->count=server_context.curr_count;

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
    TSMD_CONTEXT * new_context=NULL;


    while(1)
    {
           usleep(time_val.tv_usec);

	    // do the tspi context init func
	   if(share_init_context->handle!=0)
	   {
		
		if(server_context.init_state==TSMD_CONTEXT_INIT_START)
		{
			server_context.init_state=TSMD_CONTEXT_INIT_GETREQ;
			new_context = Build_TsmdContext(share_init_context->count,share_init_context->handle);
			if(new_context==NULL)
				return -EINVAL;
    			static key_t shm_key;
			shm_key=ftok(pathname,new_context->count+0x02);
			if(shm_key == -1)
    			{
       				 printf("ftok shm_share_key error");
        			return -1;
    			}

    			printf("shm_key=%d\n",shm_key) ;
			new_context->shm_size=4096;
    			new_context->shmid=shmget(shm_key,new_context->shm_size,IPC_CREAT|IPC_EXCL|0666);
    			if(new_context->shmid<0)
    			{
				printf("open context share memory failed!\n");
				return -EINVAL;
    			}
			void * share_addr;
    			share_addr=shmat(new_context->shmid,NULL,0);
    			printf("shm_addr=%x\n",share_addr) ;

			Memset(namebuffer,0,DIGEST_SIZE);
			Memset(share_addr,0,new_context->shm_size);
			Strcpy(namebuffer,"channel");
			Itoa(new_context->count,namebuffer+Strlen(namebuffer));

			new_context->tsmd_API_channel = channel_register_fixmem(namebuffer,CHANNEL_RDWR|CHANNEL_FIXMEM,NULL,
                		new_context->shm_size/2,share_addr,share_addr+new_context->shm_size/2);
		
			share_init_context->handle=new_context->handle;	
			semaphore_v(semid,1);
		}
		else if(server_context.init_state==TSMD_CONTEXT_INIT_GETREQ)
		{
			if(share_init_context->count!=server_context.curr_count)
			{
				channel_inner_write(new_context->tsmd_API_channel,"TSMD",5);
				server_context.init_state=TSMD_CONTEXT_INIT_WAITCHANNEL;
			}
		}
		else if(server_context.init_state==TSMD_CONTEXT_INIT_WAITCHANNEL)
		{
			ret=channel_inner_read(new_context->tsmd_API_channel,Buf,5);
			if(ret==5)
			{	
				if(Strncmp(Buf,"TSPI",5)==0)
				{
					server_context.curr_count++;
					share_init_context->count=server_context.curr_count;	
					share_init_context->handle=0;
					semaphore_v(semid,2);
				}
				else
					return -EINVAL;
				server_context.init_state=TSMD_CONTEXT_INIT_START;
				new_context->state=TSMD_CONTEXT_BUILD;
			}
			else if(ret==0)
				continue;
			else
				return -EINVAL;
		}
	   }

	   // throughout  every context to find function call
           
	   ret=proc_each_tspicalls(sub_proc);
	   if(ret<0)
		break;
    }	
    return ret;
}

int proc_each_tspicalls(void * sub_proc)
{
	int ret;
	struct List_head * curr_head;
	Record_List * curr_record;
  	TSMD_CONTEXT * tsmd_context;

	curr_head=server_context.contexts_list.list.next;

	while(curr_head!=&server_context.contexts_list.list)
	{
		curr_record=(Record_List *)curr_head;
		curr_head=curr_head->next;
		tsmd_context=curr_record->record;
		if(tsmd_context==NULL)
			continue;
		ret=channel_inner_read(tsmd_context->tsmd_API_channel,tsmd_context->tsmd_send_buf,1024);
		if(ret>0)
		{
			int apino=*(int *)tsmd_context->tsmd_send_buf;
			int output_len=0;
			switch(apino)
			{
				case SUBTYPE(TSPI_IN,GETTCMOBJECT):
					output_len=proc_tsmd_GetTcmObject(sub_proc,tsmd_context->tsmd_send_buf,
						tsmd_context->tsmd_recv_buf);	
					break;
				case SUBTYPE(TSPI_IN,GETRANDOM):
					output_len=proc_tsmd_GetRandom(sub_proc,tsmd_context->tsmd_send_buf,
						tsmd_context->tsmd_recv_buf);	
					break;
				case SUBTYPE(TSPI_IN,PCREXTEND):
					output_len=proc_tsmd_PcrExtend(sub_proc,tsmd_context->tsmd_send_buf,
						tsmd_context->tsmd_recv_buf);	
					break;
				case SUBTYPE(TSPI_IN,PCRREAD):
					output_len=proc_tsmd_PcrRead(sub_proc,tsmd_context->tsmd_send_buf,
						tsmd_context->tsmd_recv_buf);	
					break;
                                case SUBTYPE(TSPI_IN,CREATEOBJECT):
                                        output_len=proc_tsmd_CreateObject(sub_proc,tsmd_context->tsmd_send_buf,
                                                tsmd_context->tsmd_recv_buf);
                                        break;
                                case SUBTYPE(TSPI_IN,SELECTPCRINDEX):
                                        output_len=proc_tsmd_SelectPcrIndex(sub_proc,tsmd_context->tsmd_send_buf,
                                                tsmd_context->tsmd_recv_buf);
                                        break;
                                case SUBTYPE(TSPI_IN,PCRRESET):
					output_len=proc_tsmd_PcrReset(sub_proc,tsmd_context->tsmd_send_buf,
						tsmd_context->tsmd_recv_buf);	
					break;
                                case SUBTYPE(TSPI_IN,GETPOLICYOBJECT):
					output_len=proc_tsmd_GetPolicyObject(sub_proc,tsmd_context->tsmd_send_buf,
						tsmd_context->tsmd_recv_buf);	
					break;
                                case SUBTYPE(TSPI_IN,SETSECRET):
					output_len=proc_tsmd_SetSecret(sub_proc,tsmd_context->tsmd_send_buf,
						tsmd_context->tsmd_recv_buf);	
					break;
                                case SUBTYPE(TSPI_IN,LOADKEYBYUUID):
					output_len=proc_tsmd_LoadKeyByUUID(sub_proc,tsmd_context->tsmd_send_buf,
						tsmd_context->tsmd_recv_buf);	
					break;
                                case SUBTYPE(TSPI_IN,ASSIGNTOOBJECT):
					output_len=proc_tsmd_AssignToObject(sub_proc,tsmd_context->tsmd_send_buf,
						tsmd_context->tsmd_recv_buf);	
					break;
                                case SUBTYPE(TSPI_IN,CREATEKEY):
					output_len=proc_tsmd_CreateKey(sub_proc,tsmd_context->tsmd_send_buf,
						tsmd_context->tsmd_recv_buf);	
					break;
				default:
					return -EINVAL;
			}
			ret=channel_inner_write(tsmd_context->tsmd_API_channel,tsmd_context->tsmd_recv_buf,output_len);
		}
	}
	return 0;
}

int proc_tsmd_GetTcmObject(void * sub_proc,BYTE * in_buf,BYTE * out_buf)
{
	int ret;
	RECORD(TSPI_IN, GETTCMOBJECT) tspi_in;	
	RECORD(TSPI_OUT, GETTCMOBJECT) tspi_out;
	TSMD_OBJECT * tcm_object;
	TSMD_OBJECT * policy_object;
	struct tsmd_object_tcm * tcm_struct;
        void * tspi_in_template = memdb_get_template(TYPE_PAIR(TSPI_IN,GETTCMOBJECT));
        if(tspi_in_template == NULL)
        {
                return -EINVAL;
        }
        void * tspi_out_template = memdb_get_template(TYPE_PAIR(TSPI_OUT,GETTCMOBJECT));
        if(tspi_out_template == NULL)
        {
                return -EINVAL;
        }

	ret=blob_2_struct(in_buf,&tspi_in,tspi_in_template);
	if(ret<0)
		return ret;

  	struct tcm_in_GetRandom tcm_in;
  	struct tcm_out_GetRandom tcm_out;

	tcm_in.bytesRequested=0x10;

	ret=proc_tcm_GetRandom(&tcm_in,&tcm_out,vtcm_caller);
	
	if(ret>0)
	{
		tcm_object=Build_TsmdObject(tspi_in.hContext,TSM_OBJECT_TYPE_TCM,0);
		if(tcm_object==NULL)
			tspi_out.returncode=TSM_E_INVALID_HANDLE;
		else
		{
			policy_object=Build_TsmdObject(tspi_in.hContext,TSM_OBJECT_TYPE_POLICY,0);
			if(policy_object==NULL)
				tspi_out.returncode=TSM_E_INVALID_HANDLE;
			else
			{
				tcm_struct=tcm_object->object_struct;
				tcm_struct->policy=policy_object->handle;
				tspi_out.hTCM=tcm_object->handle;
				tspi_out.returncode=0;
			}
		}
			
	}
	else
		tspi_out.returncode=TSM_E_CONNECTION_FAILED;

	
	tspi_out.paramSize=sizeof(tspi_out);
	ret=struct_2_blob(&tspi_out,out_buf,tspi_out_template);
	return ret;
}

int proc_tsmd_GetRandom(void * sub_proc,BYTE * in_buf,BYTE * out_buf)
{
	int ret;
	RECORD(TSPI_IN, GETRANDOM) tspi_in;	
	RECORD(TSPI_OUT, GETRANDOM) tspi_out;
        void * tspi_in_template = memdb_get_template(TYPE_PAIR(TSPI_IN,GETRANDOM));
        if(tspi_in_template == NULL)
        {
                return -EINVAL;
        }
        void * tspi_out_template = memdb_get_template(TYPE_PAIR(TSPI_OUT,GETRANDOM));
        if(tspi_out_template == NULL)
        {
                return -EINVAL;
        }

	ret=blob_2_struct(in_buf,&tspi_in,tspi_in_template);
	if(ret<0)
		return ret;

  	struct tcm_in_GetRandom tcm_in;
  	struct tcm_out_GetRandom tcm_out;

	tcm_in.tag=htons(TCM_TAG_RQU_COMMAND);
	tcm_in.ordinal=SUBTYPE_GETRANDOM_IN;
	tcm_in.bytesRequested=tspi_in.ulRandomDataLength;

	ret=proc_tcm_General(&tcm_in,&tcm_out,vtcm_caller);
	
	if(ret>0)
		tspi_out.returncode=0;
	else
		tspi_out.returncode=TSM_E_CONNECTION_FAILED;
	
	tspi_out.paramSize=sizeof(tspi_out)-sizeof(BYTE *)+tspi_out.ulRandomDataLength;
	tspi_out.ulRandomDataLength=tspi_in.ulRandomDataLength;
	tspi_out.rgbRandomData=Talloc0(tspi_out.ulRandomDataLength);
	if(tspi_out.rgbRandomData==NULL)
		return -ENOMEM;
	Memcpy(tspi_out.rgbRandomData,tcm_out.randomBytes,tspi_out.ulRandomDataLength);
	ret=struct_2_blob(&tspi_out,out_buf,tspi_out_template);
	return ret;
}

int proc_tsmd_PcrExtend(void * sub_proc,BYTE * in_buf,BYTE * out_buf)
{
	int ret;
	RECORD(TSPI_IN, PCREXTEND) tspi_in;	
	RECORD(TSPI_OUT, PCREXTEND) tspi_out;
        void * tspi_in_template = memdb_get_template(TYPE_PAIR(TSPI_IN,PCREXTEND));
	BYTE msghash[DIGEST_SIZE];
        if(tspi_in_template == NULL)
        {
                return -EINVAL;
        }
        void * tspi_out_template = memdb_get_template(TYPE_PAIR(TSPI_OUT,PCREXTEND));
        if(tspi_out_template == NULL)
        {
                return -EINVAL;
        }

	ret=blob_2_struct(in_buf,&tspi_in,tspi_in_template);
	if(ret<0)
		return ret;

  	struct tcm_in_extend tcm_in;
  	struct tcm_out_extend tcm_out;

	tcm_in.tag=htons(TCM_TAG_RQU_COMMAND);
	tcm_in.ordinal=SUBTYPE_EXTEND_IN;
	tcm_in.pcrNum=tspi_in.ulPcrIndex;
	calculate_context_sm3(tspi_in.pbPcrData,tspi_in.ulPcrDataLength,tcm_in.inDigest);

	ret=proc_tcm_Extend(&tcm_in,&tcm_out,vtcm_caller);
	
	if(ret>0)
		tspi_out.returncode=0;
	else
		tspi_out.returncode=TSM_E_CONNECTION_FAILED;
	
	tspi_out.paramSize=sizeof(tspi_out)-sizeof(BYTE *)+tspi_out.ulPcrValueLength;
	tspi_out.ulPcrValueLength=DIGEST_SIZE;
	tspi_out.rgbPcrValue=Talloc0(tspi_out.ulPcrValueLength);
	if(tspi_out.rgbPcrValue==NULL)
		return -ENOMEM;
	Memcpy(tspi_out.rgbPcrValue,tcm_out.outDigest,tspi_out.ulPcrValueLength);
	ret=struct_2_blob(&tspi_out,out_buf,tspi_out_template);
	return ret;
}

int proc_tsmd_PcrRead(void * sub_proc,BYTE * in_buf,BYTE * out_buf)
{
	int ret;
	RECORD(TSPI_IN, PCRREAD) tspi_in;	
	RECORD(TSPI_OUT, PCRREAD) tspi_out;
        void * tspi_in_template = memdb_get_template(TYPE_PAIR(TSPI_IN,PCRREAD));
	BYTE msghash[DIGEST_SIZE];
        if(tspi_in_template == NULL)
        {
                return -EINVAL;
        }
        void * tspi_out_template = memdb_get_template(TYPE_PAIR(TSPI_OUT,PCRREAD));
        if(tspi_out_template == NULL)
        {
                return -EINVAL;
        }

	ret=blob_2_struct(in_buf,&tspi_in,tspi_in_template);
	if(ret<0)
		return ret;

  	struct tcm_in_pcrread tcm_in;
  	struct tcm_out_pcrread tcm_out;

	tcm_in.tag=htons(TCM_TAG_RQU_COMMAND);
	tcm_in.ordinal=SUBTYPE_PCRREAD_IN;
	tcm_in.pcrIndex=tspi_in.ulPcrIndex;

	ret=proc_tcm_General(&tcm_in,&tcm_out,vtcm_caller);
	
	if(ret>0)
		tspi_out.returncode=0;
	else
		tspi_out.returncode=TSM_E_CONNECTION_FAILED;
	
	tspi_out.paramSize=sizeof(tspi_out)-sizeof(BYTE *)+tspi_out.ulPcrValueLength;
	tspi_out.ulPcrValueLength=DIGEST_SIZE;
	tspi_out.rgbPcrValue=Talloc0(tspi_out.ulPcrValueLength);
	if(tspi_out.rgbPcrValue==NULL)
		return -ENOMEM;
	Memcpy(tspi_out.rgbPcrValue,tcm_out.outDigest,tspi_out.ulPcrValueLength);
	ret=struct_2_blob(&tspi_out,out_buf,tspi_out_template);
	return ret;
}

int proc_tsmd_CreateObject(void * sub_proc,BYTE * in_buf,BYTE * out_buf)
{
        int ret;
        RECORD(TSPI_IN, CREATEOBJECT) tspi_in;
        RECORD(TSPI_OUT, CREATEOBJECT) tspi_out;
        TSMD_OBJECT * new_object;
        TSMD_OBJECT * pcrs_object;
    //  TSMD_OBJECT * policy_object;
        struct tsmd_object_hpcrs * tcm_struct;

	//  input data convert
        void * tspi_in_template = memdb_get_template(TYPE_PAIR(TSPI_IN,CREATEOBJECT));
        if(tspi_in_template == NULL)
        {
                return -EINVAL;
        }
        void * tspi_out_template = memdb_get_template(TYPE_PAIR(TSPI_OUT,CREATEOBJECT));
        if(tspi_out_template == NULL)
        {
                return -EINVAL;
        }

        ret=blob_2_struct(in_buf,&tspi_in,tspi_in_template);
        if(ret<0)
                return ret;

	// Create object function
        
        if(ret>0)
        {       
		

                new_object=Build_TsmdObject(tspi_in.hContext,tspi_in.objectType,tspi_in.initFlags);
                if(new_object==NULL)
                      tspi_out.returncode=TSM_E_INVALID_HANDLE;
                else    
                {       
                      tspi_out.phObject=new_object->handle;
                      tspi_out.returncode=0;
                }
         
        }

        else
                tspi_out.returncode=TSM_E_CONNECTION_FAILED;

	// return 

        ret=struct_2_blob(&tspi_out,out_buf,tspi_out_template);
        return ret;
}


int proc_tsmd_SelectPcrIndex(void * sub_proc,BYTE * in_buf,BYTE * out_buf)
{
        int ret;
        RECORD(TSPI_IN, SELECTPCRINDEX) tspi_in;
        RECORD(TSPI_OUT, SELECTPCRINDEX) tspi_out;

       //input data convert
        void * tspi_in_template = memdb_get_template(TYPE_PAIR(TSPI_IN,SELECTPCRINDEX));
        if(tspi_in_template == NULL)
        {
                return -EINVAL;
        }
        void * tspi_out_template = memdb_get_template(TYPE_PAIR(TSPI_OUT,SELECTPCRINDEX));
        if(tspi_out_template == NULL)
        {
                return -EINVAL;
        }

        ret=blob_2_struct(in_buf,&tspi_in,tspi_in_template);
        if(ret<0)
                return ret;

       /*
        struct tcm_in_selectpcrindex tcm_in;
        struct tcm_out_selectpcrindex tcm_out;
    

        tcm_in.tag=htons(TCM_TAG_RQU_COMMAND);
        tcm_in.ordinal=SUBTYPE_SELECTPCRINDEX_IN;
        tcm_in.pcrComposite=tspi_in.hPcrComposite;     
        tcm_in.pcrIndex=tspi_in.ulPcrIndex;
        tcm_in.direction=tspi_in.direction;
        */
        
       // UINT32 tsmd_handle;
	TSMD_OBJECT * pcrs_object;
        if(ret>0){
		pcrs_object=Find_TsmdObject(tspi_in.hPcrComposite);			
		TCM_PCR_COMPOSITE * pcrComp=&((struct tsmd_object_hpcrs *)new_object->object_struct)->pcrComposite;
		bitmap_set(pcrComp->select.pcrSelect,1);	

              //  hPcrComposite=Ischarinset(tspi_in.ulPcrIndex,tspi_in.hPcrComposite);
                tspi_out.returncode=0;
        }else
                tspi_out.returncode=TSM_E_CONNECTION_FAILED;


        //tspi_out.paramSize=sizeof(tspi_out);


        ret=struct_2_blob(&tspi_out,out_buf,tspi_out_template);
        return ret;
} 

int proc_tsmd_PcrReset(void * sub_proc,BYTE * in_buf,BYTE * out_buf) 
{ 
	int ret; 
	RECORD(TSPI_IN, PCRRESET) tspi_in;	 
	RECORD(TSPI_OUT, PCRRESET) tspi_out; 
        void * tspi_in_template = memdb_get_template(TYPE_PAIR(TSPI_IN,PCRRESET)); 
	//BYTE msghash[DIGEST_SIZE]; 
        if(tspi_in_template == NULL) 
        { 
                return -EINVAL; 
        } 
        void * tspi_out_template = memdb_get_template(TYPE_PAIR(TSPI_OUT,PCRRESET)); 
        if(tspi_out_template == NULL) 
        { 
                return -EINVAL; 
        } 
 
	ret=blob_2_struct(in_buf,&tspi_in,tspi_in_template); 
	if(ret<0) 
		return ret; 
 
  	struct tcm_in_pcrreset tcm_in; 
  	struct tcm_out_pcrreset tcm_out; 
 
	tcm_in.tag=htons(TCM_TAG_RQU_COMMAND); 
	tcm_in.ordinal=SUBTYPE_PCRRESET_IN; 
        
        TSMD_OBJECT * pcrs_object;
        pcrs_object=Find_TsmdObject(tspi_in.hPcrComposite);
	//TCM_PCR_COMPOSITE * pcrComp=pcrs_object->object_struct;
        //TCM_PCR_SELECTION * pcr_select=Talloc0(sizeof(TCM_PCR_SELECTION));
        //*pcr_select=pcrComp->select;
        
	TCM_PCR_COMPOSITE * pcrComp=Talloc0(sizeof(TCM_PCR_COMPOSITE));
        *pcrComp=*(TCM_PCR_COMPOSITE *)(pcrs_object->object_struct);
        //TCM_PCR_SELECTION * pcr_select=pcrComp->select.pcrSelect;
        //tcm_in.pcrSelection=pcrComp->select.pcrSelect; 
        //tcm_in.pcrSelection=*pcr_select;
        
        //&tcm_in.pcrSelection==Talloc0(sizeof(TCM_PCR_SELECTION));
        //Memcpy(&tcm_in.pcrSelection,pcr_select,sizeof(TCM_PCR_SELECTION));
        Memcpy(&tcm_in.pcrSelection,&pcrComp->select,sizeof(TCM_PCR_SELECTION));
	
        ret=proc_tcm_General(&tcm_in,&tcm_out,vtcm_caller); 
	 
	if(ret>0) 
		tspi_out.returncode=0; 
	else 
		tspi_out.returncode=TSM_E_CONNECTION_FAILED; 
	 
	/*
        tspi_out.paramSize=sizeof(tspi_out)-sizeof(BYTE *)+tspi_out.ulPcrValueLength; 
	tspi_out.ulPcrValueLength=DIGEST_SIZE; 
	tspi_out.rgbPcrValue=Talloc0(tspi_out.ulPcrValueLength); 
	if(tspi_out.rgbPcrValue==NULL) 
		return -ENOMEM; 
	//Memcpy(tspi_out.rgbPcrValue,tcm_out.outDigest,tspi_out.ulPcrValueLength); 
        */	
        ret=struct_2_blob(&tspi_out,out_buf,tspi_out_template); 
	return ret; 
}

int proc_tsmd_SetSecret(void * sub_proc,BYTE * in_buf,BYTE * out_buf) 
{ 
	int ret; 
	RECORD(TSPI_IN, SETSECRET) tspi_in;	 
	RECORD(TSPI_OUT, SETSECRET) tspi_out; 
        void * tspi_in_template = memdb_get_template(TYPE_PAIR(TSPI_IN,SETSECRET)); 
	BYTE msghash[DIGEST_SIZE]; 
        if(tspi_in_template == NULL) 
        { 
                return -EINVAL; 
        } 
        void * tspi_out_template = memdb_get_template(TYPE_PAIR(TSPI_OUT,SETSECRET)); 
        if(tspi_out_template == NULL) 
        { 
                return -EINVAL; 
        } 
 
	ret=blob_2_struct(in_buf,&tspi_in,tspi_in_template); 
	if(ret<0) 
		return ret; 
//=================================================================        
        TSMD_OBJECT * policy_object;
        policy_object=Find_TsmdObject(tspi_in.hPolicy);
        //policy_object->object_struct
      /*  TSMD_OBJECT * pcrs_object;
        pcrs_object=Find_TsmdObject(tspi_in.hPcrComposite);
	//TCM_PCR_COMPOSITE * pcrComp=pcrs_object->object_struct;
        //TCM_PCR_SELECTION * pcr_select=Talloc0(sizeof(TCM_PCR_SELECTION));
        //*pcr_select=pcrComp->select;
        
	TCM_PCR_COMPOSITE * pcrComp=Talloc0(sizeof(TCM_PCR_COMPOSITE));
        *pcrComp=*(TCM_PCR_COMPOSITE *)(pcrs_object->object_struct);
        //TCM_PCR_SELECTION * pcr_select=pcrComp->select.pcrSelect;
        //tcm_in.pcrSelection=pcrComp->select.pcrSelect; 
        //tcm_in.pcrSelection=*pcr_select;
        
        //&tcm_in.pcrSelection==Talloc0(sizeof(TCM_PCR_SELECTION));
        //Memcpy(&tcm_in.pcrSelection,pcr_select,sizeof(TCM_PCR_SELECTION));
        Memcpy(&tcm_in.pcrSelection,&pcrComp->select,sizeof(TCM_PCR_SELECTION));
	
        ret=proc_tcm_General(&tcm_in,&tcm_out,vtcm_caller); 
*/	 
	if(ret>0) 
		tspi_out.returncode=0; 
	else 
		tspi_out.returncode=TSM_E_CONNECTION_FAILED; 
	 
	/*
        tspi_out.paramSize=sizeof(tspi_out)-sizeof(BYTE *)+tspi_out.ulPcrValueLength; 
	tspi_out.ulPcrValueLength=DIGEST_SIZE; 
	tspi_out.rgbPcrValue=Talloc0(tspi_out.ulPcrValueLength); 
	if(tspi_out.rgbPcrValue==NULL) 
		return -ENOMEM; 
	//Memcpy(tspi_out.rgbPcrValue,tcm_out.outDigest,tspi_out.ulPcrValueLength); 
        */	
        ret=struct_2_blob(&tspi_out,out_buf,tspi_out_template); 
	return ret; 
}

int proc_tsmd_GetPolicyObject(void * sub_proc,BYTE * in_buf,BYTE * out_buf) 
{ 
	int ret; 
	RECORD(TSPI_IN, GETPOLICYOBJECT) tspi_in;	 
	RECORD(TSPI_OUT, GETPOLICYOBJECT) tspi_out; 
        void * tspi_in_template = memdb_get_template(TYPE_PAIR(TSPI_IN,GETPOLICYOBJECT)); 
	//BYTE msghash[DIGEST_SIZE]; 
        if(tspi_in_template == NULL) 
        { 
                return -EINVAL; 
        } 
        void * tspi_out_template = memdb_get_template(TYPE_PAIR(TSPI_OUT,GETPOLICYOBJECT)); 
        if(tspi_out_template == NULL) 
        { 
                return -EINVAL; 
        } 
 
	ret=blob_2_struct(in_buf,&tspi_in,tspi_in_template); 
	if(ret<0) 
		return ret; 
//=================================================================        
      /*  TSMD_OBJECT * pcrs_object;
        pcrs_object=Find_TsmdObject(tspi_in.hPcrComposite);
	//TCM_PCR_COMPOSITE * pcrComp=pcrs_object->object_struct;
        //TCM_PCR_SELECTION * pcr_select=Talloc0(sizeof(TCM_PCR_SELECTION));
        //*pcr_select=pcrComp->select;
       */ 
	if(ret>0) 
		tspi_out.returncode=0; 
	else 
		tspi_out.returncode=TSM_E_CONNECTION_FAILED; 
	 
	/*
        tspi_out.paramSize=sizeof(tspi_out)-sizeof(BYTE *)+tspi_out.ulPcrValueLength; 
	tspi_out.ulPcrValueLength=DIGEST_SIZE; 
	tspi_out.rgbPcrValue=Talloc0(tspi_out.ulPcrValueLength); 
	if(tspi_out.rgbPcrValue==NULL) 
		return -ENOMEM; 
	//Memcpy(tspi_out.rgbPcrValue,tcm_out.outDigest,tspi_out.ulPcrValueLength); 
        */	
        ret=struct_2_blob(&tspi_out,out_buf,tspi_out_template); 
	return ret; 
}

int proc_tsmd_LoadKeyByUUID(void * sub_proc,BYTE * in_buf,BYTE * out_buf) 
{ 
	int ret; 
	RECORD(TSPI_IN, LOADKEYBYUUID) tspi_in;	 
	RECORD(TSPI_OUT, LOADKEYBYUUID) tspi_out; 
        void * tspi_in_template = memdb_get_template(TYPE_PAIR(TSPI_IN,LOADKEYBYUUID)); 
	//BYTE msghash[DIGEST_SIZE]; 
        if(tspi_in_template == NULL) 
        { 
                return -EINVAL; 
        } 
        void * tspi_out_template = memdb_get_template(TYPE_PAIR(TSPI_OUT,LOADKEYBYUUID)); 
        if(tspi_out_template == NULL) 
        { 
                return -EINVAL; 
        } 
 
	ret=blob_2_struct(in_buf,&tspi_in,tspi_in_template); 
	if(ret<0) 
		return ret; 
//=================================================================        
      /*  TSMD_OBJECT * pcrs_object;
        pcrs_object=Find_TsmdObject(tspi_in.hPcrComposite);
	//TCM_PCR_COMPOSITE * pcrComp=pcrs_object->object_struct;
        //TCM_PCR_SELECTION * pcr_select=Talloc0(sizeof(TCM_PCR_SELECTION));
        //*pcr_select=pcrComp->select;
       */ 
	if(ret>0) 
		tspi_out.returncode=0; 
	else 
		tspi_out.returncode=TSM_E_CONNECTION_FAILED; 
	 
	/*
        tspi_out.paramSize=sizeof(tspi_out)-sizeof(BYTE *)+tspi_out.ulPcrValueLength; 
	tspi_out.ulPcrValueLength=DIGEST_SIZE; 
	tspi_out.rgbPcrValue=Talloc0(tspi_out.ulPcrValueLength); 
	if(tspi_out.rgbPcrValue==NULL) 
		return -ENOMEM; 
	//Memcpy(tspi_out.rgbPcrValue,tcm_out.outDigest,tspi_out.ulPcrValueLength); 
        */	
        ret=struct_2_blob(&tspi_out,out_buf,tspi_out_template); 
	return ret; 
}

int proc_tsmd_AssignToObject(void * sub_proc,BYTE * in_buf,BYTE * out_buf) 
{ 
	int ret; 
	RECORD(TSPI_IN, ASSIGNTOOBJECT) tspi_in;	 
	RECORD(TSPI_OUT, ASSIGNTOOBJECT) tspi_out; 
        void * tspi_in_template = memdb_get_template(TYPE_PAIR(TSPI_IN,ASSIGNTOOBJECT)); 
	//BYTE msghash[DIGEST_SIZE]; 
        if(tspi_in_template == NULL) 
        { 
                return -EINVAL; 
        } 
        void * tspi_out_template = memdb_get_template(TYPE_PAIR(TSPI_OUT,ASSIGNTOOBJECT)); 
        if(tspi_out_template == NULL) 
        { 
                return -EINVAL; 
        } 
 
	ret=blob_2_struct(in_buf,&tspi_in,tspi_in_template); 
	if(ret<0) 
		return ret; 
//=================================================================        
      /*  TSMD_OBJECT * pcrs_object;
        pcrs_object=Find_TsmdObject(tspi_in.hPcrComposite);
	//TCM_PCR_COMPOSITE * pcrComp=pcrs_object->object_struct;
        //TCM_PCR_SELECTION * pcr_select=Talloc0(sizeof(TCM_PCR_SELECTION));
        //*pcr_select=pcrComp->select;
       */ 
	if(ret>0) 
		tspi_out.returncode=0; 
	else 
		tspi_out.returncode=TSM_E_CONNECTION_FAILED; 
	 
	/*
        tspi_out.paramSize=sizeof(tspi_out)-sizeof(BYTE *)+tspi_out.ulPcrValueLength; 
	tspi_out.ulPcrValueLength=DIGEST_SIZE; 
	tspi_out.rgbPcrValue=Talloc0(tspi_out.ulPcrValueLength); 
	if(tspi_out.rgbPcrValue==NULL) 
		return -ENOMEM; 
	//Memcpy(tspi_out.rgbPcrValue,tcm_out.outDigest,tspi_out.ulPcrValueLength); 
        */	
        ret=struct_2_blob(&tspi_out,out_buf,tspi_out_template); 
	return ret; 
}

int proc_tsmd_CreateKey(void * sub_proc,BYTE * in_buf,BYTE * out_buf) 
{ 
	int ret; 
	RECORD(TSPI_IN, CREATEKEY) tspi_in;	 
	RECORD(TSPI_OUT, CREATEKEY) tspi_out; 
        void * tspi_in_template = memdb_get_template(TYPE_PAIR(TSPI_IN,CREATEKEY)); 
	//BYTE msghash[DIGEST_SIZE]; 
        if(tspi_in_template == NULL) 
        { 
                return -EINVAL; 
        } 
        void * tspi_out_template = memdb_get_template(TYPE_PAIR(TSPI_OUT,CREATEKEY)); 
        if(tspi_out_template == NULL) 
        { 
                return -EINVAL; 
        } 
 
	ret=blob_2_struct(in_buf,&tspi_in,tspi_in_template); 
	if(ret<0) 
		return ret; 
//=================================================================        
      /*  TSMD_OBJECT * pcrs_object;
        pcrs_object=Find_TsmdObject(tspi_in.hPcrComposite);
	//TCM_PCR_COMPOSITE * pcrComp=pcrs_object->object_struct;
        //TCM_PCR_SELECTION * pcr_select=Talloc0(sizeof(TCM_PCR_SELECTION));
        //*pcr_select=pcrComp->select;
       */ 
	if(ret>0) 
		tspi_out.returncode=0; 
	else 
		tspi_out.returncode=TSM_E_CONNECTION_FAILED; 
	 
	/*
        tspi_out.paramSize=sizeof(tspi_out)-sizeof(BYTE *)+tspi_out.ulPcrValueLength; 
	tspi_out.ulPcrValueLength=DIGEST_SIZE; 
	tspi_out.rgbPcrValue=Talloc0(tspi_out.ulPcrValueLength); 
	if(tspi_out.rgbPcrValue==NULL) 
		return -ENOMEM; 
	//Memcpy(tspi_out.rgbPcrValue,tcm_out.outDigest,tspi_out.ulPcrValueLength); 
        */	
        ret=struct_2_blob(&tspi_out,out_buf,tspi_out_template); 
	return ret; 
}

