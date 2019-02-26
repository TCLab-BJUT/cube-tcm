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
#include "tcm_global.h"
#include "tcm_authlib.h"
#include "sm4.h"
#include "vtcm_alg.h"

#include "tcmfunc.h"

#define TCMIOC_CANCEL   _IO('T', 0x00)
#define TCMIOC_TRANSMIT _IO('T', 0x01)

Record_List sessions_list;
TCM_PUBKEY * pubEK=NULL;
TCM_SECRET ownerAuth;
TCM_SECRET smkAuth;
BYTE Buf[DIGEST_SIZE*32];

enum vtcm_trans_type
{
        DRV_IOCTL=1,
        DRV_RW
};
static enum vtcm_trans_type trans_type=DRV_RW;
                                         
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
  vtcm_ex_hmac_sm3(authdata->sharedSecret,auth,TCM_HASH_SIZE,1,Buf,TCM_HASH_SIZE*2);

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
	// deal with special command
	if(vtcm_input->ordinal==SUBTYPE_APTERMINATE_IN)
		out_type=DTYPE_VTCM_OUT;
	else
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
  inlen=ret;
  ret = vtcmutils_transmit(inlen,Buf,&outlen,Buf);
  if(ret<0)
    return ret; 
  printf("Receive  output lentgh %d:\n",outlen);

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
        }
	Memcpy(out,TransBuf,len);
	*out_len=len;
	return len;
}

UINT32 TCM_CreateEndorsementKeyPair(BYTE * pubkeybuf,UINT32 * pubkeybuflen)
{
  int outlen;
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

UINT32 TCM_Extend(UINT32 pcrIndex,
                    BYTE * event,
                    BYTE * pcrvalue)
{
  int ret = 0;
  struct tcm_in_extend * vtcm_input;
  struct tcm_out_extend * vtcm_output;
  void * vtcm_template;

  printf("Begin TCM Extend:\n");
  vtcm_input = Talloc0(sizeof(*vtcm_input));
  if(vtcm_input==NULL)
      return -ENOMEM;
  vtcm_output = Talloc0(sizeof(*vtcm_output));
  if(vtcm_output==NULL)
      return -ENOMEM;
  vtcm_input->tag = htons(TCM_TAG_RQU_COMMAND);
  vtcm_input->ordinal=SUBTYPE_EXTEND_IN;
  Memcpy(vtcm_input->inDigest,event,DIGEST_SIZE); 
  vtcm_input->pcrNum=pcrIndex;

  ret=proc_tcm_General(vtcm_input,vtcm_output);

  if(ret<0)
	return ret;
  if(vtcm_output->returnCode!=0)
	return vtcm_output->returnCode;
  Memcpy(pcrvalue,vtcm_output->outDigest,DIGEST_SIZE);
  return 0;
}

UINT32 TCM_PcrRead(UINT32 pcrindex, BYTE * pcrvalue)
{
  int ret = 0;
  struct tcm_in_pcrread * vtcm_input;
  struct tcm_out_pcrread * vtcm_output;
  void * vtcm_template;

  printf("Begin TCM pcrread:\n");
  vtcm_input = Talloc0(sizeof(*vtcm_input));
  if(vtcm_input==NULL)
      return -ENOMEM;
  vtcm_output = Talloc0(sizeof(*vtcm_output));
  if(vtcm_output==NULL)
      return -ENOMEM;
  vtcm_input->tag = htons(TCM_TAG_RQU_COMMAND);
  vtcm_input->ordinal=SUBTYPE_PCRREAD_IN;
  vtcm_input->pcrIndex=pcrindex;

  ret=proc_tcm_General(vtcm_input,vtcm_output);

  if(ret<0)
	return ret;
  if(vtcm_output->returnCode!=0)
	return vtcm_output->returnCode;
  Memcpy(pcrvalue,vtcm_output->outDigest,DIGEST_SIZE);
  return 0;
}

UINT32 TCM_ReadPubek(TCM_PUBKEY *key)
{
  int outlen;
  int ret = 0;
  struct tcm_in_ReadPubek * vtcm_input;
  struct tcm_out_ReadPubek * vtcm_output;
  void * vtcm_template;

  printf("Begin ReadPubek:\n");
  vtcm_input = Talloc0(sizeof(*vtcm_input));
  if(vtcm_input==NULL)
      return -ENOMEM;
  vtcm_output = Talloc0(sizeof(*vtcm_output));
  if(vtcm_output==NULL)
      return -ENOMEM;
  vtcm_input->tag = htons(TCM_TAG_RQU_COMMAND);
  vtcm_input->ordinal=SUBTYPE_READPUBEK_IN;
  RAND_bytes(vtcm_input->antiReplay,DIGEST_SIZE);
 
  deep_debug=1;
  ret=proc_tcm_General(vtcm_input,vtcm_output);
  deep_debug=0;
  if(ret<0)
	return ret;
  if(vtcm_output->returnCode!=0)
	return vtcm_output->returnCode;

  vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_PUBKEY);
  ret = struct_clone(key,&vtcm_output->pubEndorsementKey,vtcm_template);
  if(ret<0)
     return -EINVAL;
  printf("finish struct clone!\n");

  if(pubEK==NULL)
  {
	pubEK=Dalloc0(sizeof(*pubEK),NULL);
	if(pubEK==NULL)
		return -ENOMEM;
  	ret = struct_clone(pubEK,&vtcm_output->pubEndorsementKey,vtcm_template);
 	 if(ret<0)
		return -EINVAL;
  }
  printf("Read Pubek finish!\n");
  return 0;
}
UINT32 TCM_APCreate(UINT32 entityType, UINT32 entityValue, char * pwd, UINT32 * authHandle)
{
  int ret = 0;
  struct tcm_in_APCreate * vtcm_input;
  struct tcm_out_APCreate * vtcm_output;
  void * vtcm_template;
  TCM_AUTHHANDLE authhandle;
  int outlen;
  int i=1;
  unsigned char nonce[TCM_HASH_SIZE];
  unsigned char nonce1[TCM_HASH_SIZE];
  unsigned char key[TCM_HASH_SIZE];
  unsigned char auth[TCM_HASH_SIZE];
  TCM_SESSION_DATA * authdata;

  printf("Begin TCM APCreate:\n");
  vtcm_input = Talloc0(sizeof(*vtcm_input));
  if(vtcm_input==NULL)
      return -ENOMEM;
  vtcm_output = Talloc0(sizeof(*vtcm_output));
  if(vtcm_output==NULL)
      return -ENOMEM;
  vtcm_input->tag = htons(TCM_TAG_RQU_AUTH1_COMMAND);
  vtcm_input->ordinal = SUBTYPE_APCREATE_IN;
  vtcm_input->entityType=entityType;
  vtcm_input->entityValue=entityValue;
  RAND_bytes(vtcm_input->nonce,TCM_HASH_SIZE);
  vtcm_ex_sm3(auth,1,pwd,strlen(pwd));
  Memcpy(vtcm_input->authCode, auth, TCM_HASH_SIZE);
  ret=vtcm_Compute_AuthCode(vtcm_input,DTYPE_VTCM_IN_AUTH1,SUBTYPE_APCREATE_IN,NULL,vtcm_input->authCode);
  authdata=Create_AuthSession_Data(&(vtcm_input->entityType),vtcm_input->authCode,vtcm_input->nonce);

  ret=proc_tcm_General(vtcm_input,vtcm_output);

  memcpy(authdata->sharedSecret, auth, TCM_NONCE_SIZE);
  authhandle=Build_AuthSession(authdata,vtcm_output);
  if(vtcm_input->entityType==0x12){
    memset(authdata->sharedSecret,0,TCM_HASH_SIZE);
  }
  if(authhandle==0)
    return -EINVAL;	
  // check authdata

  BYTE CheckData[TCM_HASH_SIZE];
  ret=vtcm_Compute_AuthCode(vtcm_output,DTYPE_VTCM_OUT_AUTH1,SUBTYPE_APCREATE_OUT,authdata,CheckData);
  if(ret<0)
    return -EINVAL;
  if(Memcmp(CheckData,vtcm_output->authCode,DIGEST_SIZE)!=0)
  {
    printf("APCreate check output authCode failed!\n");
    return -EINVAL;
  }	
  if(ret<0)
	return ret;
  if(vtcm_output->returnCode!=0)
	return vtcm_output->returnCode;
  *authHandle=vtcm_output->authHandle;
  printf("Output para: %d %x\n\n",vtcm_output->returnCode,vtcm_output->authHandle);
  return 0;
}

UINT32 TCM_APTerminate(UINT32 authHandle)
{
  int outlen;
  int i=1;
  int ret=0;
  void *vtcm_template;
  struct tcm_in_APTerminate *vtcm_input;
  struct tcm_out_APTerminate *vtcm_output;
  unsigned char key[TCM_HASH_SIZE];
  unsigned char checknum[TCM_HASH_SIZE];
  unsigned char hashout[TCM_HASH_SIZE];
  TCM_SESSION_DATA * authdata;
  printf("Begin TCM APTerminate:\n");
  vtcm_input = Talloc0(sizeof(*vtcm_input));
  if(vtcm_input==NULL)
    return -ENOMEM;
  vtcm_output = Talloc0(sizeof(*vtcm_output));
  if(vtcm_output==NULL)
    return -ENOMEM;
  vtcm_input->tag = htons(TCM_TAG_RQU_AUTH1_COMMAND);
  vtcm_input->ordinal = SUBTYPE_APTERMINATE_IN;
  vtcm_input->authHandle=authHandle;
  int ordinal = htonl(vtcm_input->ordinal);
  vtcm_ex_sm3(checknum,1,&ordinal,4);
  authdata=Find_AuthSession(0x00,vtcm_input->authHandle);
  int serial = htonl(authdata->SERIAL);

  vtcm_ex_hmac_sm3(hashout,authdata->sharedSecret,32,2,checknum,32,&serial,4);
  memcpy(vtcm_input->authCode,hashout,TCM_HASH_SIZE);
  vtcm_input->paramSize=sizeof(*vtcm_input);

  ret=proc_tcm_General(vtcm_input,vtcm_output);

  if(ret<0)
	return ret;
  if(vtcm_output->returnCode!=0)
	return vtcm_output->returnCode;
  printf("Output para: %d\n",vtcm_output->returnCode);
  return 0;
}

UINT32 TCM_EvictKey(UINT32 keyHandle)
{
  int outlen;
  int i=1;
  int ret=0;
  void *vtcm_template;
  struct tcm_in_EvictKey *vtcm_input;
  struct tcm_out_EvictKey *vtcm_output;

  unsigned char digest[TCM_HASH_SIZE];
  TCM_SESSION_DATA * authdata;
  printf("Begin TCM EvictKey:\n");
  vtcm_input = Talloc0(sizeof(*vtcm_input));
  if(vtcm_input==NULL)
    return -ENOMEM;
  vtcm_output = Talloc0(sizeof(*vtcm_output));
  if(vtcm_output==NULL)
    return -ENOMEM;

  vtcm_input->evictHandle = keyHandle;
  vtcm_input->tag = htons(TCM_TAG_RQU_COMMAND);
  vtcm_input->ordinal = SUBTYPE_EVICTKEY_IN;
  int ordinal = htonl(vtcm_input->ordinal);

  vtcm_input->paramSize=sizeof(*vtcm_input);

  ret=proc_tcm_General(vtcm_input,vtcm_output);

  if(ret<0)
	return ret;
  if(vtcm_output->returnCode!=0)
	return vtcm_output->returnCode;
  printf("Output para: %d\n",vtcm_output->returnCode);
  return 0;
}


UINT32 TCM_CreateWrapKey(int parentHandle,int authHandle,char * select,char * keyfile,char *pwdk)
{
  int outlen;
  int i=1;
  int fd;
  int ret = 0;
  int offset=0;
  void * vtcm_template;
  TCM_AUTHHANDLE authhandle;
  unsigned char ownerauth[TCM_HASH_SIZE];
  unsigned char migrationauth[TCM_HASH_SIZE];
  unsigned char nonce[TCM_HASH_SIZE];
  unsigned char hashout[TCM_HASH_SIZE];
  unsigned char pubAuth[TCM_HASH_SIZE];
  unsigned char APKey[TCM_HASH_SIZE];
  unsigned char hmacout[TCM_HASH_SIZE];
  unsigned char authdata1[TCM_HASH_SIZE];
  unsigned char migrationdata[TCM_HASH_SIZE];
  TCM_SESSION_DATA * authdata;
  struct tcm_in_CreateWrapKey *vtcm_input;
  struct tcm_out_CreateWrapKey *vtcm_output;
  char * index_para;
  char * value_para;

  TCM_SYMMETRIC_KEY_PARMS *sm4_parms;
  TCM_SM2_ASYMKEY_PARAMETERS *sm2_parms;
  vtcm_input = Talloc0(sizeof(*vtcm_input));
  if(vtcm_input==NULL)
    return -ENOMEM;
  vtcm_output = Talloc0(sizeof(*vtcm_output));
  if(vtcm_output==NULL)
    return -ENOMEM;
  vtcm_input->tag = htons(TCM_TAG_RQU_AUTH1_COMMAND);
  vtcm_input->ordinal = SUBTYPE_CREATEWRAPKEY_IN;
  vtcm_input->parentHandle=parentHandle;
  vtcm_input->authHandle=authHandle;
//Fill keyInfo information
  vtcm_input->keyInfo.tag=htons(TCM_TAG_KEY);
  vtcm_input->keyInfo.keyFlags=0;
  vtcm_input->keyInfo.authDataUsage=TCM_AUTH_ALWAYS;

  if(!strcmp("sm4",select))
  {
    if(vtcm_input->keyInfo.keyUsage==0)
    	vtcm_input->keyInfo.keyUsage=TCM_SM4KEY_STORAGE;
    vtcm_input->keyInfo.algorithmParms.algorithmID=TCM_ALG_SM4;
    vtcm_input->keyInfo.algorithmParms.encScheme=TCM_ES_SM4_CBC;
    vtcm_input->keyInfo.algorithmParms.sigScheme=TCM_SS_NONE;
    printf("this is sm4\n");
    // add smkparms's sm4 key parms
    sm4_parms=Talloc0(sizeof(*sm4_parms));
    if(sm4_parms==NULL)
      return -ENOMEM;
    sm4_parms->keyLength=0x80;
    sm4_parms->blockSize=0x80;
    sm4_parms->ivSize=0x10;
    sm4_parms->IV=Talloc0(sm4_parms->ivSize);
    vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_SYMMETRIC_KEY_PARMS);
    if(vtcm_template==NULL)
      return -EINVAL;
    ret=struct_2_blob(sm4_parms,Buf,vtcm_template);
    if(ret<0)
      return ret; 
    vtcm_input->keyInfo.algorithmParms.parmSize=ret;
    vtcm_input->keyInfo.algorithmParms.parms=Talloc0(ret);
    if(vtcm_input->keyInfo.algorithmParms.parms==NULL)
      return -ENOMEM;
    Memcpy(vtcm_input->keyInfo.algorithmParms.parms,Buf,ret);
  }else
  {
    if(vtcm_input->keyInfo.keyUsage==0)
    	vtcm_input->keyInfo.keyUsage=TCM_SM2KEY_SIGNING;
    //add smkparms's sm2 key parms
    sm2_parms=Talloc0(sizeof(*sm2_parms));
    if(sm2_parms==NULL)
      return -ENOMEM;
    sm2_parms->keyLength=0x80;
    vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_SM2_ASYMKEY_PARAMETERS);
    if(vtcm_template==NULL)
      return -EINVAL;
    ret=struct_2_blob(sm2_parms,Buf,vtcm_template);
    if(ret<0)
      return ret;
    vtcm_input->keyInfo.algorithmParms.parmSize=ret;
    vtcm_input->keyInfo.algorithmParms.parms=Talloc0(ret);
    if(vtcm_input->keyInfo.algorithmParms.parms==NULL)
      return -ENOMEM;
    Memcpy(vtcm_input->keyInfo.algorithmParms.parms,Buf,ret);
    vtcm_input->keyInfo.algorithmParms.algorithmID=TCM_ALG_SM2;
    vtcm_input->keyInfo.algorithmParms.encScheme=TCM_ES_SM2;
    vtcm_input->keyInfo.algorithmParms.sigScheme=TCM_SS_SM2;
    printf("this is sm2\n");
  }
  BYTE *Buffer=(BYTE*)malloc(sizeof(BYTE)*256);
  vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_KEY);
  if(vtcm_template==NULL)
    return -EINVAL;
  int ret1=0;
  ret1=struct_2_blob(&(vtcm_input->keyInfo),Buffer,vtcm_template);
  if(ret1<0)
    return ret1;
  vtcm_template=memdb_get_template(DTYPE_VTCM_IN_AUTH1,SUBTYPE_CREATEWRAPKEY_IN);
  if(vtcm_template==NULL)
    return -EINVAL;
  offset=struct_2_blob(vtcm_input,Buf,vtcm_template);
  printf("%d\n",offset);
   if(pwdk!=NULL)
  {
	vtcm_ex_sm3(ownerauth,1,pwdk,Strlen(pwdk));
  }
  else
  {
	Memset(ownerauth,0,TCM_HASH_SIZE);		
  }		

  authdata=Find_AuthSession(0x04,vtcm_input->authHandle);
  vtcm_AuthSessionData_Encrypt(vtcm_input->dataUsageAuth,authdata,ownerauth);
  vtcm_AuthSessionData_Encrypt(vtcm_input->dataMigrationAuth,authdata,migrationauth);
  
  // compute authcode
  ret=vtcm_Compute_AuthCode(vtcm_input,DTYPE_VTCM_IN_AUTH1,SUBTYPE_CREATEWRAPKEY_IN,authdata,vtcm_input->pubAuth);

  vtcm_input->paramSize=offset;
  printf("Begin input for CreateWrapKey\n");

  ret=proc_tcm_General(vtcm_input,vtcm_output);

  if(ret<0)
	return ret;
  if(vtcm_output->returnCode!=0)
	return vtcm_output->returnCode;
  BYTE CheckData[TCM_HASH_SIZE];
  ret=vtcm_Compute_AuthCode(vtcm_output,DTYPE_VTCM_OUT_AUTH1,SUBTYPE_CREATEWRAPKEY_OUT,authdata,CheckData);

  if(ret<0)
    return -EINVAL;
  if(Memcmp(CheckData,vtcm_output->resAuth,DIGEST_SIZE)!=0)
  {
    printf("createwrapkey check output authCode failed!\n");
    return -EINVAL;
  }	
   vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_KEY);
  if(vtcm_template==NULL)
    return -EINVAL;	

  // write keyfile	

  ret=struct_2_blob(&vtcm_output->wrappedKey,Buf,vtcm_template);
  if(ret<0)
    return -EINVAL;
  fd=open(keyfile,O_CREAT|O_TRUNC|O_WRONLY,0666);
  if(fd<0)
    return -EIO;
  write(fd,Buf,ret);
  close(fd);
  printf("Output para: %d \n\n",vtcm_output->returnCode);
  return 0;
}

UINT32 TCM_SM2LoadPubkey(char *keyfile,BYTE * key, int *keylen )
{
  TCM_KEY *keyOut;
  int ret=0;
  int keyLength=0;
  void * vtcm_template;
  int fd;
  int datasize;

  // read file
  fd=open(keyfile,O_RDONLY);
  if(fd<0)
      return -EIO;
  ret=read(fd,Buf,DIGEST_SIZE*32+1);
  if(ret<0)
      return -EIO;
  if(ret>DIGEST_SIZE*32)
  {
      printf("key file too large!\n");
      return -EINVAL;
  }
  close(fd);
  int length=512;
  BYTE * keyFile=(BYTE*)malloc(sizeof(BYTE)*keyLength);

  //  load key

  vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_KEY);
  if(vtcm_template==NULL)
      return -EINVAL;

  datasize=ret;

  keyOut=Talloc0(sizeof(*keyOut));
  if(keyOut==NULL)
    return -ENOMEM;

  ret=blob_2_struct(Buf,keyOut,vtcm_template);
  if(ret<0||ret>datasize){
       printf("read key file error!\n");
       return -EINVAL;
  }

  *keylen=keyOut->pubKey.keyLength;
  Memcpy(key,keyOut->pubKey.key,*keylen);
  return 0;
}

UINT32 TCM_SM2Encrypt(BYTE * pubkey, int pubkey_len, BYTE * out, int * out_len,BYTE * in ,int in_len)
{
  int i=1;
  int ret=0;
  int fd;
  int datasize;

  //  load key

  // proc_vtcmutils_ReadFile(keyLength,keyFile);
  // read data

  *out_len=in_len+65+32+4;
  ret = GM_SM2Encrypt(out,out_len,in,in_len,pubkey,pubkey_len);
  if(ret!=0){
      printf("SM2Encrypt is fail\n");
      return -EINVAL;
  }
  return 0;
}

UINT32 TCM_LoadKey(UINT32 authHandle,char * keyfile,UINT32 *KeyHandle)
{
  int outlen;
  int i=1;
  int ret = 0;
  int offset=0;
  void * vtcm_template;
  unsigned char loadkey[TCM_HASH_SIZE];
  unsigned char nonce[TCM_HASH_SIZE];
  unsigned char hashout[TCM_HASH_SIZE];
  unsigned char pubAuth[TCM_HASH_SIZE];
  unsigned char APKey[TCM_HASH_SIZE];
  unsigned char hmacout[TCM_HASH_SIZE];
  TCM_SESSION_DATA * authdata;
  struct tcm_in_LoadKey * vtcm_input;
  struct tcm_out_LoadKey * vtcm_output;
  vtcm_input = Talloc0(sizeof(*vtcm_input));
  if(vtcm_input==NULL)
    return -ENOMEM;
  vtcm_output = Talloc0(sizeof(*vtcm_output));
  if(vtcm_output==NULL)
    return -ENOMEM;
  vtcm_input->tag = htons(TCM_TAG_RQU_AUTH1_COMMAND);
  vtcm_input->ordinal = SUBTYPE_LOADKEY_IN;
  vtcm_input->parentHandle=0x40;
  vtcm_input->authHandle=authHandle;
  int fd;
  int datasize;
  fd=open(keyfile,O_RDONLY);
  if(fd<0)
    return -EIO;
  ret=read(fd,Buf,DIGEST_SIZE*32+1);
  if(ret<0)
    return -EIO;
  if(ret>DIGEST_SIZE*32)
  {
    printf("key file too large!\n");
    return -EINVAL;
  }
  datasize=ret;
  vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_KEY);
  if(vtcm_template==NULL)
  {
    return -EINVAL;
  }
  ret=blob_2_struct(Buf,&vtcm_input->inKey,vtcm_template);
  if((ret<0)||(ret>datasize))
  {
    printf("read key file error!\n");
    return -EINVAL;
  }
  authdata=Find_AuthSession(0x04,vtcm_input->authHandle);
  ret = vtcm_Compute_AuthCode(vtcm_input,DTYPE_VTCM_IN_AUTH1,SUBTYPE_LOADKEY_IN,authdata,vtcm_input->parentAuth);

  vtcm_template=memdb_get_template(DTYPE_VTCM_IN_AUTH1,SUBTYPE_LOADKEY_IN);
  if(vtcm_template==NULL)
    return -EINVAL;
  offset=struct_2_blob(vtcm_input,Buf,vtcm_template);
  if(offset<0)
    return offset;
  vtcm_input->paramSize=offset;

  offset=struct_2_blob(vtcm_input,Buf,vtcm_template);


  ret=proc_tcm_General(vtcm_input,vtcm_output);
  if(ret<0)
	return ret;
  if(vtcm_output->returnCode!=0)
	return vtcm_output->returnCode;
  BYTE CheckData[TCM_HASH_SIZE];
  ret = vtcm_Compute_AuthCode(vtcm_output,DTYPE_VTCM_OUT_AUTH1,SUBTYPE_LOADKEY_OUT,authdata,CheckData);
  if(ret<0)
    return -EINVAL;
  if(Memcmp(CheckData,vtcm_output->resAuth,DIGEST_SIZE)!=0)
  {
    printf("Loadkey check output authcode failed!\n");
    return -EINVAL;
  }
  *KeyHandle=vtcm_output->inKeyHandle;
  printf("KeyHandle: %x\n",vtcm_output->inKeyHandle);
  printf("Output para: %d %x\n\n",vtcm_output->returnCode,vtcm_output->inKeyHandle);
  return 0;
}

UINT32 TCM_SM2Decrypt(UINT32 keyHandle,UINT32 DecryptAuthHandle,BYTE * out, int * out_len,BYTE * in, int in_len)
{
  unsigned char *encData=NULL;
  int i=1;
  int outlen;
  int ret=0;
  void * vtcm_template;
  unsigned char hashout[TCM_HASH_SIZE];
  unsigned char hmacout[TCM_HASH_SIZE];
  struct tcm_in_Sm2Decrypt *vtcm_input;
  struct tcm_out_Sm2Decrypt *vtcm_output;
  TCM_SESSION_DATA * authdata;
  vtcm_input = Talloc0(sizeof(*vtcm_input));
  if(vtcm_input==NULL)
    return -ENOMEM;
  vtcm_output = Talloc0(sizeof(*vtcm_output));
  if(vtcm_output==NULL)
    return -ENOMEM;
  vtcm_input->tag = htons(TCM_TAG_RQU_AUTH1_COMMAND);
  vtcm_input->ordinal = SUBTYPE_SM2DECRYPT_IN;
  vtcm_input->keyHandle=keyHandle;
  vtcm_input->DecryptAuthHandle=DecryptAuthHandle;
  int datasize;
  authdata=Find_AuthSession(0x01,vtcm_input->DecryptAuthHandle);
  if(authdata==NULL)
  {
	printf("can't find decrypt session!\n");
	return -EINVAL;
  }
  if(in_len>DIGEST_SIZE*24)
  {
    printf("decrypt data too large!\n");
    return -EINVAL;     
  }
  vtcm_input->DecryptDataSize =in_len ; 
  vtcm_input->paramSize = in_len+54;
  vtcm_input->DecryptData = Talloc0(vtcm_input->DecryptDataSize);
  if(vtcm_input->DecryptData==NULL)
    return -EINVAL;
  Memcpy(vtcm_input->DecryptData,in,vtcm_input->DecryptDataSize); 
  //
  //compute DecryptAuthVerfication
  ret=vtcm_Compute_AuthCode(vtcm_input,DTYPE_VTCM_IN_AUTH1,SUBTYPE_SM2DECRYPT_IN,authdata,vtcm_input->DecryptAuthVerfication);
 
  printf("Begin Input for SM2Decrypt:\n");

  ret=proc_tcm_General(vtcm_input,vtcm_output);
  if(ret<0)
	return ret;
  if(vtcm_output->returnCode!=0)
	return vtcm_output->returnCode;
  // Check authdata
  BYTE CheckData[TCM_HASH_SIZE];
  ret=vtcm_Compute_AuthCode(vtcm_output,DTYPE_VTCM_OUT_AUTH1,SUBTYPE_SM2DECRYPT_OUT,authdata,CheckData);
  if(ret<0)
  {
    	return -EINVAL;
  }
  if(Memcmp(CheckData,vtcm_output->DecryptedAuthVerfication,DIGEST_SIZE)!=0)
  {
    	printf("SM2Decrypt check output failed!\n");
    	return -EINVAL;
  }

  *out_len=vtcm_output->DecryptedDataSize;
  Memcpy(out,vtcm_output->DecryptedData,vtcm_output->DecryptedDataSize);
  return 0;
}

int TCM_SM3Start(){
  int outlen;
  int i=0;
  int ret=0;
  void *vtcm_template;
  struct tcm_in_Sm3Start *vtcm_input;
  struct tcm_out_Sm3Start *vtcm_output;
  vtcm_input = Talloc0(sizeof(*vtcm_input));
  if(vtcm_input==NULL)
    return -ENOMEM;
  vtcm_output = Talloc0(sizeof(*vtcm_output));
  if(vtcm_output==NULL)
    return -ENOMEM;
  vtcm_input->tag = htons(TCM_TAG_RQU_COMMAND);
  vtcm_input->ordinal = SUBTYPE_SM3START_IN;
  ret=proc_tcm_General(vtcm_input,vtcm_output);
  if(ret<0)
	return ret;
  return vtcm_output->returnCode;
}

int TCM_SM3Update(BYTE * data, int data_len){
  int outlen;
  int i=1;
  int ret=0;
  int offset=0;
  void *vtcm_template;
  char *datablock=NULL;
  unsigned char nonce[TCM_HASH_SIZE];
  struct tcm_in_Sm3Update *vtcm_input;
  struct tcm_out_Sm3Update *vtcm_output;
  vtcm_input = Talloc0(sizeof(*vtcm_input));
  if(vtcm_input==NULL)
      return -ENOMEM;
  vtcm_output = Talloc0(sizeof(*vtcm_output));
  if(vtcm_output==NULL)
      return -ENOMEM;
  vtcm_input->tag = htons(TCM_TAG_RQU_COMMAND);
  vtcm_input->ordinal = SUBTYPE_SM3UPDATE_IN;

  vtcm_input->dataBlockSize=data_len;

  vtcm_input->dataBlock=Talloc0(data_len);
  if(vtcm_input->dataBlock==NULL)
	return -ENOMEM;
  Memcpy(vtcm_input->dataBlock,data,data_len);

  ret=proc_tcm_General(vtcm_input,vtcm_output);
  if(ret<0)
	return ret;
  ret=vtcm_output->returnCode;
  Free(vtcm_input->dataBlock);
  Free(vtcm_input);
  Free(vtcm_output);
  return ret;
}

int TCM_SM3Complete(BYTE * in, int in_len,BYTE * out){

  int ret=0;
  void *vtcm_template;
  struct tcm_in_Sm3Complete *vtcm_input;
  struct tcm_out_Sm3Complete *vtcm_output;
  vtcm_input = Talloc0(sizeof(*vtcm_input));
  if(vtcm_input==NULL)
  	return -ENOMEM;
  vtcm_output = Talloc0(sizeof(*vtcm_output));
  if(vtcm_output==NULL)
  	return -ENOMEM;
  vtcm_input->tag = htons(TCM_TAG_RQU_COMMAND);
  vtcm_input->ordinal = SUBTYPE_SM3COMPLETE_IN;
  vtcm_input->dataBlockSize=in_len;
  vtcm_input->dataBlock=Talloc0(in_len);
  if(vtcm_input->dataBlock==NULL)
	return -ENOMEM;
  Memcpy(vtcm_input->dataBlock,in,in_len);

  ret=proc_tcm_General(vtcm_input,vtcm_output);
  if(ret<0)
	return ret;
  if(vtcm_output->returnCode ==0)
  {
	Memcpy(out,vtcm_output->calResult,DIGEST_SIZE);
  }	
  ret=vtcm_output->returnCode;
  Free(vtcm_input->dataBlock);
  Free(vtcm_input);
  Free(vtcm_output);
  return ret;
}
