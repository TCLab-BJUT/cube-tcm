#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <sys/ioctl.h>


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

#include "tcmfunc.h"

#define TCMIOC_CANCEL   _IO('T', 0x00)
#define TCMIOC_TRANSMIT _IO('T', 0x01)

Record_List sessions_list;
TCM_PUBKEY * pubEK;
TCM_SECRET ownerAuth;
TCM_SECRET smkAuth;
BYTE Buf[DIGEST_SIZE*32];

enum vtcm_trans_type
{
        DRV_IOCTL=1,
        DRV_RW
};
static enum vtcm_trans_type trans_type=DRV_IOCTL;
                                         
char * tcm_devname="/dev/tcm";
int dev_fd;
static char main_config_file[DIGEST_SIZE*2]="./main_config.cfg";
static char sys_config_file[DIGEST_SIZE*2]="./sys_config.cfg";

extern BYTE * CAprikey;
extern unsigned long * CAprilen;
extern BYTE * CApubkey;

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

int _TSMD_Init()
{
    int ret;
    int retval;
    int i,j;
    int argv_offset;	
    char namebuffer[DIGEST_SIZE*4];
    void * main_proc; // point to the main proc's subject struct
    char * sys_plugin;		
    char * app_plugin;		
    char * base_define;

    int readlen;
    int json_offset;
    void * memdb_template ;
    BYTE uuid[DIGEST_SIZE];
    char local_uuid[DIGEST_SIZE*2];

    FILE * fp;
    char audit_text[4096];
    char buffer[4096];
    void * root_node;
    void * temp_node;
    int fd;	

    char * baseconfig[] =
    {
	"namelist.json",
	"dispatchnamelist.json",
	"typelist.json",
	"subtypelist.json",
	"memdb.json",
	"msghead.json",
	"msgrecord.json",
	"expandrecord.json",
	"base_msg.json",
	"dispatchrecord.json",
	"exmoduledefine.json",
	 NULL
    };

    sys_plugin=getenv("CUBE_SYS_PLUGIN");
    // process the command argument

    int ifmerge=0;

//	alloc_init(alloc_buffer);
	struct_deal_init();
	memdb_init();

    	base_define=getenv("CUBE_BASE_DEFINE");
	for(i=0;baseconfig[i]!=NULL;i++)
	{
		Strcpy(namebuffer,base_define);
		Strcat(namebuffer,"/");
		Strcat(namebuffer,baseconfig[i]);
		ret=read_json_file(namebuffer);
		if(ret<0)
			return ret;
		printf("read %d elem from file %s!\n",ret,namebuffer);
	}


	msgfunc_init();


    struct lib_para_struct * lib_para=NULL;
    fd=open(sys_config_file,O_RDONLY);
    if(fd>0)
    {

   	 ret=read_json_node(fd,&root_node);
  	 if(ret<0)
		return ret;	
    	 close(fd);
	

    	 ret=read_sys_cfg(&lib_para,root_node,NULL);
    	 if(ret<0)
		return ret;
    }	 		
    fd=open(main_config_file,O_RDONLY);
    if(fd<0)
	return -EINVAL;

    ret=read_json_node(fd,&root_node);
    if(ret<0)
	return ret;	
    close(fd);
	
    ret=read_main_cfg(lib_para,root_node);
    if(ret<0)
	return ret; 		

    ret=get_local_uuid(local_uuid);
    printf("this machine's local uuid is %s\n",local_uuid);
    return 0;	
}

UINT32 TCM_LibInit(void)
{
    int ret;

    dev_fd=open(tcm_devname,O_RDWR);
    if(dev_fd<0)
	return dev_fd;
    
  INIT_LIST_HEAD(&sessions_list.list);
  sessions_list.record=NULL;

  return 0;

}


int proc_tcm_General(void * tcm_in, void * tcm_out)
{
  int i=0;
  int ret=0;
  struct vtcm_external_input_command *vtcm_input=tcm_in;
  struct vtcm_external_output_command *vtcm_output=tcm_out;
  void * vtcm_template;
  int cmd_type,out_type;
  int inlen,outlen;

  if(vtcm_input->tag == htons(TCM_TAG_RQU_COMMAND))
  {	
	cmd_type=DTYPE_VTCM_IN;	
	out_type=DTYPE_VTCM_OUT;
  }
  else if(vtcm_input->tag == htons(TCM_TAG_RQU_AUTH1_COMMAND))
  {
	cmd_type=DTYPE_VTCM_IN_AUTH1;	
	out_type=DTYPE_VTCM_OUT_AUTH1;	
  }
  else if(vtcm_input->tag == htons(TCM_TAG_RQU_AUTH2_COMMAND))
  {
	cmd_type=DTYPE_VTCM_IN_AUTH2;	
	out_type=DTYPE_VTCM_IN_AUTH2;	
  }
  else
  {	
	return -EINVAL;
  }	

  ret = vtcm_Build_CmdBlob(vtcm_input,cmd_type,vtcm_input->ordinal,Buf);
  if(ret<0)
     return -EINVAL;
  printf("Send command for getRandom:\n");
  print_bin_data(Buf,ret,8);
  inlen=ret;
  ret = vtcmutils_transmit(inlen,Buf,&outlen,Buf);
  if(ret<0)
    return ret; 
  printf("Receive  output is:\n");
  print_bin_data(Buf,outlen,8);

  vtcm_template=memdb_get_template(out_type,vtcm_input->ordinal);
  if(vtcm_template==NULL)
    return -EINVAL;
  ret = blob_2_struct(Buf,vtcm_output,vtcm_template);
  return ret;
}

int vtcmutils_transmit(int in_len,BYTE * in, int * out_len, BYTE * out)
{
  	int ret;
	int len;
	BYTE TransBuf[DIGEST_SIZE*32];


        if(trans_type==DRV_IOCTL)
        {
		Memcpy(TransBuf,in,in_len);
                len = ioctl(dev_fd, TCMIOC_TRANSMIT, TransBuf);
                if(len==-1)
                        return -EINVAL;
        }
        else
        {
                ret=write(dev_fd,in,in_len);
                if(ret>0)
		{
                        len=read(dev_fd,TransBuf,DIGEST_SIZE*32);
                	if(len<0)
               		{
                        	printf("libtcm read return data error!\n");
                        	return len;
                	}
		}
		return ret;
        }
	Memcpy(out,TransBuf,len);
	*out_len=len;
	return len;
}

UINT32 TCM_CreateEndorsementKeyPair(BYTE * pubkeybuf,UINT32 * pubkeybuflen)
{
  int outlen;
  int i=1;
  int ret = 0;
  struct tcm_in_CreateEKPair * vtcm_input;
  struct tcm_out_CreateEKPair * vtcm_output;
  TCM_SM2_ASYMKEY_PARAMETERS * key_parms_in;
  void * vtcm_template;
  void * vtcm_template1;

  unsigned char nonce[TCM_HASH_SIZE];
  printf("Begin Create EK Pair:\n");
  vtcm_input = Talloc0(sizeof(*vtcm_input));
  if(vtcm_input==NULL)
      return -ENOMEM;
  vtcm_output = Talloc0(sizeof(*vtcm_output));
  if(vtcm_output==NULL)
      return -ENOMEM;
  key_parms_in = Talloc0(sizeof(*key_parms_in));
  if(key_parms_in==NULL)
      return -ENOMEM;
  vtcm_input->tag = htons(TCM_TAG_RQU_COMMAND);
  vtcm_input->ordinal=SUBTYPE_CREATEEKPAIR_IN;
  RAND_bytes(vtcm_input->antiReplay,DIGEST_SIZE);
 
  vtcm_input->keyInfo.algorithmID=TCM_ALG_SM2;
  vtcm_input->keyInfo.encScheme=TCM_ES_SM2;
  vtcm_input->keyInfo.sigScheme=TCM_SS_SM2;
  key_parms_in->keyLength=256;
  vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_SM2_ASYMKEY_PARAMETERS);
  if(vtcm_template==NULL)
       return -EINVAL;
  vtcm_input->keyInfo.parmSize=4;
  ret = struct_2_blob(key_parms_in,Buf,vtcm_template);
  if(ret<0)
       return ret;
  vtcm_input->keyInfo.parms=Buf;

  ret=proc_tcm_General(vtcm_input,vtcm_output);

  if(ret<0)
	return ret;
  if(vtcm_output->returnCode!=0)
	return vtcm_output->returnCode;

  vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_PUBKEY);
  ret = struct_2_blob(&(vtcm_output->pubEndorsementKey),pubkeybuf,vtcm_template);
  if(ret<0)
     return -EIO;
  *pubkeybuflen=ret;
  return 0;
} 

