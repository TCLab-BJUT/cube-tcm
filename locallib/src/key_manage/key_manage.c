#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <dirent.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>

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
#include "tcm_global.h"
#include "tcm_error.h"
#include "key_manage.h"
#include "sm2.h"
#include "sm3.h"
#include "key_struct.h"

static BYTE Buf[DIGEST_SIZE*64];

int RAND_bytes(unsigned char *buffer, size_t len) 
{
    int ret, fd;
    const char * randomfile = "/dev/urandom";
    fd = open(randomfile, O_RDONLY);
    if (fd < 0) { 
        perror("open urandom device:");
        return fd;
    }    
    int readn = 0; 
    while (readn != len) {
        ret = read(fd, buffer + readn, len - readn);
        if (ret < 0) { 
            perror("read urandom device:");
            return ret; 
        }    
        readn += ret; 
    }    
    return 0;
}                                                                                                                                                                                                                
int get_short_uuidstr(int len,BYTE * digest,char * uuidstr)
{
	int ret;
	char uuid_buf[DIGEST_SIZE*2];
	
	if(len<0)
		return -EINVAL;
	if(len>32)
		len=32;
	ret=len*2;
	digest_to_uuid(digest,uuid_buf);
	Memcpy(uuidstr,uuid_buf,ret);
	uuidstr[ret]=0;
	return ret;
}

int convert_uuidname(char * name,int len,BYTE * digest,char * newfilename)
{
	int i;
	int lastsplit;
	int offset;
	int ret;
	char uuidstr[DIGEST_SIZE*2];
	char filename[DIGEST_SIZE*4];

	if((len<0)||(len>32))
		return -EINVAL;
	if(len==0)
		len=DIGEST_SIZE;

	lastsplit=0;
	for(i=0;name[i]!=0;i++)
	{
		if(name[i]=='/')
			lastsplit=i;	
	}
	
	ret=calculate_sm3(name,digest);
	if(ret<0)
		return ret;

	len=get_short_uuidstr(len,digest,uuidstr);

	offset=lastsplit;
	if(offset!=0)
	{
		Memcpy(newfilename,name,offset+1);
		offset++;
	}
	Strncpy(newfilename+offset,uuidstr,DIGEST_SIZE*2);
	
	ret=rename(name,newfilename);
	if(ret<0)
		return ret;
	return 1;	
} 
/*
void * create_key_certify_struct(void * key_cert_file,BYTE * keyuuid,BYTE * pikuuid)
{

	char digest[DIGEST_SIZE];
	int  len;
	char filename[256];
	FILE * file;
	BYTE * buf;
	TCM_CERTIFY_INFO key_info;
	
	void * struct_template;
	KEY_CERT * key_cert;
	key_cert = malloc(sizeof(KEY_CERT));
	if(key_cert==NULL)
		return NULL;
	
	memset(key_cert,0,sizeof(KEY_CERT));

	if((keyuuid!=NULL))
		memcpy(key_cert->keyuuid,keyuuid,DIGEST_SIZE);
	if((pikuuid!=NULL))
		memcpy(key_cert->pikuuid,pikuuid,DIGEST_SIZE);


	sprintf(filename,"%s.val",key_cert_file);

	if(calculate_sm3(filename,digest)!=0)
		return NULL;
	digest_to_uuid(digest,key_cert->uuid);

	result=ReadValidation(&valData,key_cert_file);

	if(result!=TSS_SUCCESS)
		return NULL;

	UINT16 offset=0;
	result= TestSuite_UnloadBlob_KEY_CERTIFY(&offset,valData.rgbData,&key_info);
	if(result!=TSS_SUCCESS)
		return NULL;

	key_cert->keyusage=key_info.keyUsage;
	key_cert->keyflags=key_info.keyFlags;
	key_cert->authdatausage=key_info.authDataUsage;
	key_cert->keydigestsize=20; // SHA1's digest size
	key_cert->pubkeydigest=malloc(key_cert->keydigestsize);
	if(key_cert->pubkeydigest==NULL)
	{
		free(key_cert);
		return NULL;
	}
	memcpy(key_cert->pubkeydigest,key_info.pubkeyDigest.digest,key_cert->keydigestsize);
	key_cert->PCRinfosize=key_info.PCRInfoSize;
	if(key_cert->PCRinfosize!=0)
	{
		key_cert->PCRinfos=malloc(key_cert->PCRinfosize);
		if(key_cert->PCRinfos==NULL)
		{
			free(key_cert->pubkeydigest);
			free(key_cert);
			return NULL;
		}
		memcpy(key_cert->PCRinfos,key_info.PCRInfo,key_cert->PCRinfosize);
		
	}	
	key_cert->filename=malloc(strlen(key_cert_file)+1);
	if(key_cert->filename==NULL)
	{
		free(key_cert);
		return NULL;
	}
	memcpy(key_cert->filename,key_cert_file,strlen(key_cert_file)+1);
	return key_cert;

}
*/

int create_blobkey_struct(struct vTCM_wrappedkey * blobkey,char * wrapkey_uuid,char * vtcm_uuid,char * keypass,char * keyfile)
{

	char digest[DIGEST_SIZE];
	int  len;
	char filename[256];

	memset(blobkey,0,sizeof(struct vTCM_wrappedkey));
	if((vtcm_uuid!=NULL)&&(!IS_ERR(vtcm_uuid)))
		memcpy(blobkey->vtcm_uuid,vtcm_uuid,DIGEST_SIZE*2);

	sprintf(filename,"%s.key",keyfile);
	if(calculate_sm3(filename,digest)!=0)
		return -EINVAL;
	digest_to_uuid(digest,blobkey->uuid);
	if(wrapkey_uuid==NULL)
	{
		blobkey->issmkwrapped=1;
	}
	else
	{
		len=strlen(wrapkey_uuid);
		if(len>DIGEST_SIZE*2)
			memcpy(blobkey->wrapkey_uuid,wrapkey_uuid,DIGEST_SIZE*2);
		else
			memcpy(blobkey->wrapkey_uuid,wrapkey_uuid,len);

	}
	blobkey->keypass=dup_str(keypass,0);
	blobkey->key_filename=dup_str(keyfile,0);
	return 0;
}

int create_pubkey_struct(struct vTCM_publickey * pubkey,char * privatekey_uuid,char * vtcm_uuid,char * keyfile)
{

	char digest[DIGEST_SIZE];
	int  len;
	char filename[256];

	memset(pubkey,0,sizeof(struct vTCM_publickey));
	if((vtcm_uuid!=NULL)&&(!IS_ERR(vtcm_uuid)))
		memcpy(pubkey->vtcm_uuid,vtcm_uuid,DIGEST_SIZE*2);

	sprintf(filename,"%s.pem",keyfile);
	if(calculate_sm3(filename,digest)!=0)
		return -EINVAL;
	digest_to_uuid(digest,pubkey->uuid);
	if(privatekey_uuid==NULL)
	{
		pubkey->ispubek=0;
	}
	else
	{
		len=strlen(privatekey_uuid);
		if(len>DIGEST_SIZE*2)
			memcpy(pubkey->privatekey_uuid,privatekey_uuid,DIGEST_SIZE*2);
		else
			memcpy(pubkey->privatekey_uuid,privatekey_uuid,len);

	}
	pubkey->key_filename=dup_str(keyfile,0);
	return 0;
}
