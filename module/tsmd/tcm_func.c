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

#include "tspi.h"
#include "tsmd.h"
#include "tspi_internal.h"

extern BYTE Buf[DIGEST_SIZE*32];
extern BYTE Output[DIGEST_SIZE*32];
Record_List sessions_list;
TCM_PUBKEY * pubEK;
TCM_SECRET ownerAuth;
TCM_SECRET smkAuth;

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
  //sm3_hmac(auth,TCM_HASH_SIZE,Buf,TCM_HASH_SIZE*2,authdata->sharedSecret);
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

int proc_tcm_GetRandom(void * tcm_in, void * tcm_out, CHANNEL * vtcm_caller)
{
  int outlen;
  int i=0;
  int ret=0;
  struct tcm_in_GetRandom *vtcm_input=tcm_in;
  struct tcm_out_GetRandom *vtcm_output=tcm_out;
  void * vtcm_template;

  vtcm_input->tag = htons(TCM_TAG_RQU_COMMAND);
  vtcm_input->ordinal = SUBTYPE_GETRANDOM_IN;
  vtcm_input->bytesRequested=0x10;
  vtcm_template=memdb_get_template(DTYPE_VTCM_IN,SUBTYPE_GETRANDOM_IN);
  if(vtcm_template==NULL)
    return -EINVAL;
  vtcm_input->paramSize=sizeof(*vtcm_input);
  ret = struct_2_blob(vtcm_input,Buf,vtcm_template);
  if(ret<0)
    return ret;
  printf("Send command for getRandom:\n");
  print_bin_data(Buf,ret,8);
  ret = vtcmutils_transmit(vtcm_input->paramSize,Buf,&outlen,Buf,vtcm_caller);
  if(ret<0)
    return ret; 
  printf("Receive  output is:\n");
  print_bin_data(Buf,outlen,8);

  vtcm_template=memdb_get_template(DTYPE_VTCM_OUT,SUBTYPE_GETRANDOM_OUT);
  if(vtcm_template==NULL)
    return -EINVAL;
  ret = blob_2_struct(Buf,vtcm_output,vtcm_template);
  return ret;
}

int proc_tcm_Extend(void * tcm_in, void * tcm_out, CHANNEL * vtcm_caller)
{
  int outlen;
  int i=0;
  int ret=0;
  struct tcm_in_extend *vtcm_input=tcm_in;
  struct tcm_out_extend *vtcm_output=tcm_out;
  void * vtcm_template;

  vtcm_input->paramSize=sizeof(*vtcm_input);
  vtcm_template=memdb_get_template(DTYPE_VTCM_IN,SUBTYPE_EXTEND_IN);
  if(vtcm_template==NULL)
    return -EINVAL;
  vtcm_input->paramSize=sizeof(*vtcm_input);
  ret = struct_2_blob(vtcm_input,Buf,vtcm_template);
  if(ret<0)
    return ret;
  printf("Send command for getRandom:\n");
  print_bin_data(Buf,ret,8);
  ret = vtcmutils_transmit(vtcm_input->paramSize,Buf,&outlen,Buf,vtcm_caller);
  if(ret<0)
    return ret; 
  printf("Receive  output is:\n");
  print_bin_data(Buf,outlen,8);

  vtcm_template=memdb_get_template(DTYPE_VTCM_OUT,SUBTYPE_EXTEND_OUT);
  if(vtcm_template==NULL)
    return -EINVAL;
  ret = blob_2_struct(Buf,vtcm_output,vtcm_template);
  return ret;
}

int proc_tcm_General(void * tcm_in, void * tcm_out, CHANNEL * vtcm_caller)
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
	return -TSM_E_INVALID_HANDLE;
		
  }	

 // vtcm_input->ordinal = SUBTYPE_PCRREAD_IN;
  vtcm_input->paramSize=sizeof(*vtcm_input);
  ret = vtcm_Build_CmdBlob(vtcm_input,cmd_type,vtcm_input->ordinal,Buf);
  if(ret<0)
     return -TSM_E_INVALID_HANDLE;
  printf("Send command for getRandom:\n");
  print_bin_data(Buf,ret,8);
  inlen=ret;
  ret = vtcmutils_transmit(inlen,Buf,&outlen,Buf,vtcm_caller);
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
int proc_tcm_PcrRead(void * tcm_in, void * tcm_out, CHANNEL * vtcm_caller)
{
  int outlen;
  int i=0;
  int ret=0;
  struct tcm_in_pcrread *vtcm_input=tcm_in;
  struct tcm_out_pcrread *vtcm_output=tcm_out;
  void * vtcm_template;

  vtcm_input->tag = htons(TCM_TAG_RQU_COMMAND);
  vtcm_input->ordinal = SUBTYPE_PCRREAD_IN;
  vtcm_input->paramSize=sizeof(*vtcm_input);
  vtcm_template=memdb_get_template(DTYPE_VTCM_IN,SUBTYPE_PCRREAD_IN);
  if(vtcm_template==NULL)
    return -EINVAL;
  vtcm_input->paramSize=sizeof(*vtcm_input);
  ret = struct_2_blob(vtcm_input,Buf,vtcm_template);
  if(ret<0)
    return ret;
  printf("Send command for getRandom:\n");
  print_bin_data(Buf,ret,8);
  ret = vtcmutils_transmit(vtcm_input->paramSize,Buf,&outlen,Buf,vtcm_caller);
  if(ret<0)
    return ret; 
  printf("Receive  output is:\n");
  print_bin_data(Buf,outlen,8);

  vtcm_template=memdb_get_template(DTYPE_VTCM_OUT,SUBTYPE_PCRREAD_OUT);
  if(vtcm_template==NULL)
    return -EINVAL;
  ret = blob_2_struct(Buf,vtcm_output,vtcm_template);
  return ret;
}

int proc_tcm_PcrReset(void * tcm_in, void * tcm_out, CHANNEL * vtcm_caller)
{
  int outlen;
  int i=0;
  int ret=0;
  struct tcm_in_pcrreset *vtcm_input=tcm_in;
  struct tcm_out_pcrreset *vtcm_output=tcm_out;
  void * vtcm_template;

  vtcm_input->tag = htons(TCM_TAG_RQU_COMMAND);
  vtcm_input->ordinal = SUBTYPE_PCRRESET_IN;
  vtcm_input->paramSize=sizeof(*vtcm_input);
  vtcm_template=memdb_get_template(DTYPE_VTCM_IN,SUBTYPE_PCRREAD_IN);
  if(vtcm_template==NULL)
    return -EINVAL;
  vtcm_input->paramSize=sizeof(*vtcm_input);
  ret = struct_2_blob(vtcm_input,Buf,vtcm_template);
  if(ret<0)
    return ret;
  printf("Send command for getRandom:\n");
  print_bin_data(Buf,ret,8);
  ret = vtcmutils_transmit(vtcm_input->paramSize,Buf,&outlen,Buf,vtcm_caller);
  if(ret<0)
    return ret; 
  printf("Receive  output is:\n");
  print_bin_data(Buf,outlen,8);

  vtcm_template=memdb_get_template(DTYPE_VTCM_OUT,SUBTYPE_PCRRESET_OUT);
  if(vtcm_template==NULL)
    return -EINVAL;
  ret = blob_2_struct(Buf,vtcm_output,vtcm_template);
  return ret;
}

int vtcmutils_transmit(int in_len,BYTE * in, int * out_len, BYTE * out,CHANNEL * vtcm_caller)
{
  	int ret;
        ret=channel_write(vtcm_caller,in,in_len);
	if(ret!=in_len)
		return -EINVAL;
	for(;;)
	{
        	usleep(time_val.tv_usec);
		ret=channel_read(vtcm_caller,out,DIGEST_SIZE*32);
		if(ret<0)
			return ret;
		if(ret>0)
		{
			*out_len=ret;
			break;
		}	
	}	
	
  	return ret;
}
