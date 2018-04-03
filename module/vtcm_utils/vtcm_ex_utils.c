#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <dirent.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "data_type.h"
#include "errno.h"
#include "alloc.h"
#include "list.h"
#include "attrlist.h"
#include "memfunc.h"
#include "basefunc.h"
#include "struct_deal.h"
#include "crypto_func.h"
#include "memdb.h"
#include "message.h"
#include "ex_module.h"
#include "tcm_constants.h"
#include "vtcm_utils.h"
#include "app_struct.h"
#include "pik_struct.h"
#include "sm2.h"
#include "sm3.h"
#include "sm4.h"

static BYTE Buf[DIGEST_SIZE*32];

extern Record_List sessions_list;
extern TCM_PUBKEY *pubEK;
extern TCM_SECRET ownerAuth;
extern TCM_SECRET smkAuth;
extern Record_List entitys_list;

// Ex CA Module

BYTE * CAprikey=NULL;
unsigned long CAprilen=0;
BYTE * CApubkey=NULL;
 
int proc_vtcmutils_ExCreateSm2Key(void * sub_proc,void * para);
int proc_vtcmutils_ExLoadCAKey(void * sub_proc,void * para);
int proc_vtcmutils_ExCaSign(void * sub_proc,void * para);
int proc_vtcmutils_ExVerify(void * sub_proc,void * para);
void * vtcm_auto_build_outputmsg(char * out_line, void * active_msg);


int proc_vtcmutils_ExCreateSm2Key(void * sub_proc,void * para)
{
	int ret=0;
    	struct tcm_utils_input * input_para=para;
	char * index_para;
	char * value_para;
	int i;

	//  cmd's params
	char * pubkey_file=NULL;
	char * privkey_file=NULL;
	char * passwd=NULL;
    	printf("Begin ex Create sm2 key:\n");
	
	if((input_para->param_num>0)&&
		(input_para->param_num%2==1))
	{
		for(i=1;i<input_para->param_num;i+=2)
		{
        		index_para=input_para->params+i*DIGEST_SIZE;
        		value_para=index_para+DIGEST_SIZE;
			if(!Strcmp("-pubkey",index_para))
			{
        			pubkey_file=value_para;
			}	
			else if(!Strcmp("-prikey",index_para))
			{
				privkey_file=value_para;
			}
			else if(!Strcmp("-pwd",index_para))
			{
				passwd=value_para;
			}
			else
			{
				printf("Error cmd format! should be %s -pubkey pubkeyfile -prikey prikeyfile"
					"[-pwd passwd]",input_para->params);
				return -EINVAL;
			}
		}
	}	
	
	BYTE prikey[DIGEST_SIZE*2];
	BYTE pubkey_XY[64];
	unsigned long prilen=DIGEST_SIZE*2;
	int fd;

	ret=GM_GenSM2keypair(prikey,&prilen,pubkey_XY);	
	if(ret!=0)
		return -EINVAL;
	fd=open(pubkey_file,O_CREAT|O_TRUNC|O_WRONLY,0666);
	if(fd<0)
		return -EIO;	
	
	ret=write(fd,pubkey_XY,64);
	if(ret<0)
	{
		printf("write pubkey file error!\n");
		return -EIO;	
	}
	close(fd);

	fd=open(privkey_file,O_CREAT|O_TRUNC|O_WRONLY,0666);
	if(fd<0)
		return -EIO;	
	
	ret=write(fd,prikey,prilen);
	if(ret<0)
	{
		printf("write prikey file error!\n");
		return -EIO;	
	}

	close(fd);
	ret=0;
	printf("proceed  create Sm2 key succeed!\n");
    	sprintf(Buf,"%d \n",ret);
   	void * send_msg =vtcm_auto_build_outputmsg(Buf,NULL);
   	if(send_msg==NULL)
		return -EINVAL;
   	ex_module_sendmsg(sub_proc,send_msg);		

	return ret;
}

int proc_vtcmutils_ExLoadCAKey(void * sub_proc,void * para)
{
	int ret=0;
    	struct tcm_utils_input * input_para=para;
	char * index_para;
	char * value_para;
	int i;

	//  cmd's params
	char * pubkey_file=NULL;
	char * privkey_file=NULL;
	char * passwd=NULL;
    	printf("Begin ex Load CA Key:\n");
	
	if((input_para->param_num>0)&&
		(input_para->param_num%2==1))
	{
		for(i=1;i<input_para->param_num;i+=2)
		{
        		index_para=input_para->params+i*DIGEST_SIZE;
        		value_para=index_para+DIGEST_SIZE;
			if(!Strcmp("-pubkey",index_para))
			{
        			pubkey_file=value_para;
			}	
			else if(!Strcmp("-prikey",index_para))
			{
				privkey_file=value_para;
			}
			else if(!Strcmp("-pwd",index_para))
			{
				passwd=value_para;
			}
			else
			{
				printf("Error cmd format! should be %s -pubkey pubkeyfile -prikey prikeyfile"
					"[-pwd passwd]",input_para->params);
				return -EINVAL;
			}
		}
	}	
	
	int fd;

	if(pubkey_file!=NULL)
	{
		fd=open(pubkey_file,O_RDONLY);
		if(fd<0)
			return -EIO;	
	
		ret=read(fd,Buf,DIGEST_SIZE*16+1);
		if(ret<0)
		{
			printf("read  pubkey file error!\n");
			return -EIO;	
		}
		if(ret>DIGEST_SIZE*16)
		{
			printf("pubkey is too long!\n");
			return -EIO;
		}
		CApubkey=malloc(ret);
		if(CApubkey==NULL)
			return -ENOMEM;
		Memcpy(CApubkey,Buf,ret);
		close(fd);
	}
	if(privkey_file!=NULL)
	{
		fd=open(privkey_file,O_RDONLY);
		if(fd<0)
			return -EIO;	
	
		ret=read(fd,Buf,DIGEST_SIZE*16+1);
		if(ret<0)
		{
			printf("read  privkey file error!\n");
			return -EIO;	
		}
		if(ret>DIGEST_SIZE*16)
		{
			printf("privkey is too long!\n");
			return -EIO;
		}
		CAprilen=ret;
		CAprikey=malloc(ret);
		if(CAprikey==NULL)
			return -ENOMEM;
		Memcpy(CAprikey,Buf,ret);
		close(fd);
	}

	printf("proceed  load ca key succeed!\n");

	ret=0;
    	sprintf(Buf,"%d \n",ret);
   	void * send_msg =vtcm_auto_build_outputmsg(Buf,NULL);
   	if(send_msg==NULL)
		return -EINVAL;
   	ex_module_sendmsg(sub_proc,send_msg);		

	return ret;
}


int proc_vtcmutils_ExCaSign(void * sub_proc,void * para)
{
	int ret=0;
    	struct tcm_utils_input * input_para=para;
	char * index_para;
	char * value_para;
	int i;
	TCM_KEY pik;
	TCM_KEY ek;
	TCM_ASYM_CA_CONTENTS ca_conts;
	TCM_SYMMETRIC_KEY * symm_key=&ca_conts.sessionKey;
	TCM_PIK_CERT * pik_cert;
	void * vtcm_template;
	

	//  cmd's params
	char * user_file=NULL;
	char * pik_file=NULL;
	char * cert_file=NULL;
	char * symmkey_file=NULL;
    	printf("Begin ex CA Sign:\n");
	
	if((input_para->param_num>0)&&
		(input_para->param_num%2==1))
	{
		for(i=1;i<input_para->param_num;i+=2)
		{
        		index_para=input_para->params+i*DIGEST_SIZE;
        		value_para=index_para+DIGEST_SIZE;
			if(!Strcmp("-user",index_para))
			{
        			user_file=value_para;
			}	
			else if(!Strcmp("-pik",index_para))
			{
				pik_file=value_para;
			}
			else if(!Strcmp("-cert",index_para))
			{
				cert_file=value_para;
			}
			else if(!Strcmp("-symm",index_para))
			{
				symmkey_file=value_para;
			}
			else
			{
				printf("Error cmd format! should be %s -user user_info_file -pik pik_file -ek ek.file"
					" -cert cert_file",input_para->params);
				return -EINVAL;
			}
		}
	}	
	
	BYTE prikey[DIGEST_SIZE*2];
	BYTE pubkey_XY[64];
	unsigned long prilen=DIGEST_SIZE*2;
	int fd;

	// malloc space for pik
	pik_cert=Talloc0(sizeof(*pik_cert));
	if(pik_cert==NULL)
		return -ENOMEM;

	pik_cert->payLoad=0x19;   // add pik_cert's payload
	//  compute  userinfo's digest
    	fd=open(user_file,O_RDONLY);
    	if(fd<0)
    	{
  		printf("No userinfo file %s!\n",user_file);
		return -EINVAL;
    	}
    
    	ret=read(fd,Buf,DIGEST_SIZE*31+1);
    	if(ret<0)
    	{
		printf("can't read userinfo data!\n");
		return -EINVAL;
    	}
    	if(ret>DIGEST_SIZE*31)
    	{
		printf("user info too long!\n");
		return -EINVAL;
    	}
    	sm3(Buf,ret,pik_cert->userDigest); 	

	// read pik file 
    	fd=open(pik_file,O_RDONLY);
    	if(fd<0)
    	{
  		printf("No pik file %s!\n",pik_file);
		return -EINVAL;
    	}
    
    	ret=read(fd,Buf,DIGEST_SIZE*31+1);
    	if(ret<0)
    	{
		printf("can't read pik data!\n");
		return -EINVAL;
    	}
    	if(ret>DIGEST_SIZE*31)
    	{
		printf("pik data too long!\n");
		return -EINVAL;
	}

	vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_KEY);
	if(vtcm_template==NULL)
		return -EINVAL;

	ret=blob_2_struct(Buf, &pik,vtcm_template);
	if(ret<0)
		return ret;
		
        // compute pik's digest

       vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_STORE_PUBKEY);
       if(vtcm_template==NULL)
		return -EINVAL;
       ret=struct_2_blob(&pik.pubKey,Buf,vtcm_template);
       if(ret<0)
		return ret;
	sm3(Buf,ret,pik_cert->pubDigest);		
	Memcpy(&ca_conts.idDigest,pik_cert->pubDigest,DIGEST_SIZE);
   
       // sign data with CAprikey

    	if(CAprikey==NULL)
    	{
		printf("can't find CA's private key!\n");
		return -EINVAL;
    	}
	
	BYTE SignBuf[DIGEST_SIZE*4];	
    	BYTE UserID[DIGEST_SIZE];
    	unsigned long lenUID = DIGEST_SIZE;
    	Memset(UserID, 'A', 32);

	Memcpy(Buf,pik_cert->userDigest,DIGEST_SIZE);
	Memcpy(Buf+DIGEST_SIZE,pik_cert->pubDigest,DIGEST_SIZE);
	
	pik_cert->signLen=DIGEST_SIZE*4;

	GM_SM2Sign(SignBuf,&pik_cert->signLen,
		Buf,DIGEST_SIZE*2,
		UserID,lenUID,
		CAprikey,CAprilen);	

	pik_cert->signData=Talloc0(pik_cert->signLen);
	Memcpy(pik_cert->signData,SignBuf,pik_cert->signLen);
   	
	// Create symmetric key
	Memset(symm_key,0,sizeof(*symm_key));
        symm_key->algId=TCM_ALG_SM4;
        symm_key->encScheme=TCM_ES_SM4_CBC;
	symm_key->size=0x80/8;
	symm_key->data=Talloc0(symm_key->size);
	RAND_bytes(symm_key->data,symm_key->size);

	// Convert cert to blob 
	vtcm_template=memdb_get_template(DTYPE_VTCM_UTILS,SUBTYPE_TCM_PIK_CERT);
	if(vtcm_template==NULL)
		return -EINVAL;
	Memset(Buf,0,DIGEST_SIZE/2);
	ret=struct_2_blob(pik_cert,Buf+DIGEST_SIZE/2,vtcm_template);
	if(ret<0)
		return ret;
	//Crypt the cert blob with symm_key and write it 
	int offset=DIGEST_SIZE/2;
	int blobsize=ret;
    	sm4_context ctx;
	BYTE EncBuf[512];
	int Enclen=512;

	ret=blobsize%(DIGEST_SIZE/2);
	offset-=ret;
	blobsize+=ret;	
    	sm4_setkey_enc(&ctx, symm_key->data);
    	sm4_crypt_ecb(&ctx, 1, blobsize, Buf,EncBuf);

    	fd=open(cert_file,O_CREAT|O_TRUNC|O_WRONLY,0666);
    	if(fd<0){
        	printf("cert file open error!\n");
        	return -EIO;     
    	}
    	print_bin_data(EncBuf,blobsize,8);
    	write(fd,EncBuf,blobsize);
    	close(fd);
		
	// Convert ca_conts to blob 
	vtcm_template=memdb_get_template(DTYPE_VTCM_IDENTITY,SUBTYPE_TCM_ASYM_CA_CONTENTS);
	if(vtcm_template==NULL)
		return -EINVAL;
	ret=struct_2_blob(&ca_conts,Buf,vtcm_template);
	if(ret<0)
		return ret;
	// Crypt the symm_key blob with pubek and write it
        if(pubEK==NULL)
	{
		printf("can't find pubEK, perhaps you should run readpubek first!\n");
	}

	ret=GM_SM2Encrypt(EncBuf,&Enclen,Buf,ret,pubEK->pubKey.key,pubEK->pubKey.keyLength);
	if(ret!=0)	
	{
        	printf("pubek's SM2Encrypt is fail\n");
		return -EINVAL;	
	}

    	fd=open(symmkey_file,O_CREAT|O_TRUNC|O_WRONLY,0666);
    	if(fd<0){
        	printf("symmkey file open error!\n");
        	return -EIO;     
    	}
    	print_bin_data(EncBuf,Enclen,8);
    	write(fd,EncBuf,Enclen);
    	close(fd);

    	sprintf(Buf,"%d \n",ret);
   	void * send_msg =vtcm_auto_build_outputmsg(Buf,NULL);
   	if(send_msg==NULL)
		return -EINVAL;
   	ex_module_sendmsg(sub_proc,send_msg);		

	return ret;
}
