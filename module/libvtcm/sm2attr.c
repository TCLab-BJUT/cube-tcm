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
#include <sys/sem.h>


#include "data_type.h"
#include "alloc.h"
#include "memfunc.h"
#include "basefunc.h"
#include "struct_deal.h"
#include "crypto_func.h"
#include "channel.h"
#include "memdb.h"
#include "message.h"
#include "connector.h"
#include "ex_module.h"
#include "tcm_constants.h"
#include "app_struct.h"
#include "pik_struct.h"
#include "sm4.h"
#include "tcmfunc.h"
#include "vtcm_alg.h"

int main(int argc,char **argv)
{

    int ret;
   
    UINT32 handle;
    int PcrLength;
    BYTE * PcrValue;
    BYTE *Buf;
    BYTE *CryptBuf;
    BYTE *OutBuf;
    int  Buflen;
    int CryptBuflen;	
    int  OutBuflen;
    UINT32 authHandle;
    UINT32 keyHandle;
    UINT32 keyAuthHandle;

    BYTE inDigest[DIGEST_SIZE];
    BYTE outDigest[DIGEST_SIZE];
    int i,j;

    struct timeval start, end;
    int crypttime,decrypttime;
    float encrypt_speed, decrypt_speed;
    int  encrypt_len=DIGEST_SIZE*8;
    int  total_decrypt=0;
    int  repeattime=20;

    ret=_TSMD_Init();

    ret= TCM_LibInit(); 

    Buf=malloc(DIGEST_SIZE*256);
    if(Buf==NULL)
	return -ENOMEM;
    CryptBuf=Buf+DIGEST_SIZE*72;
    OutBuf=CryptBuf+DIGEST_SIZE*72;  

    TCM_PUBKEY * pubek;
    pubek=malloc(sizeof(*pubek));
    if(pubek==NULL)
	return -EINVAL;

    BYTE pubkey[DIGEST_SIZE*8];
    int pubkey_len;    
 
    ret=TCM_SM2LoadPubkey("sm2.key",pubkey, &pubkey_len);

    Memset(Buf,DIGEST_SIZE*16,'A');

    ret=TCM_APCreate(TCM_ET_SMK, NULL, "sss", &authHandle);
    printf("authHandle is : %x\n",authHandle);
    if(ret<0)
    {
	printf("TCM_APCreate failed!\n");
	return -EINVAL;	
    }	
    ret=TCM_LoadKey(authHandle,"sm2.key",&keyHandle);
    if(ret<0)
    {
	printf("TCM_LoadKey failed!\n");
	return -EINVAL;	
    }	
    ret=TCM_APCreate(TCM_ET_KEYHANDLE, keyHandle, "sm2", &keyAuthHandle);
    if(ret<0)
    {
	printf("TCM_APCreate %dfailed!\n",12);
	return -EINVAL;	
    }	
    printf("keyAuthHandle is : %x\n",keyAuthHandle);

    for(j=0;j<20;j++)
    { 
	printf("SM2 Encryt\n");
    	gettimeofday( &start, NULL );
    	for(i=0;i<repeattime;i++)
	{
    		ret=TCM_SM2Encrypt(pubkey,pubkey_len,CryptBuf,&CryptBuflen,Buf,encrypt_len);
	}
    	gettimeofday( &end, NULL );

    	crypttime = 1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec;
        encrypt_speed = (float)(encrypt_len*repeattime)*1000/crypttime;
    	printf("encrypt speed %f Gbps \n", encrypt_speed/100);

    	
	printf("SM2 Decryt\n");
    	gettimeofday( &start, NULL );
    	for(i=0;i<repeattime;i++)
	{
    		ret=TCM_SM2Decrypt(keyHandle,keyAuthHandle,OutBuf,&OutBuflen,CryptBuf,CryptBuflen);
	}
    	gettimeofday( &end, NULL );
    	decrypttime = 1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec;
	
        decrypt_speed = (float)(CryptBuflen*repeattime)*1000/decrypttime;

    	printf("decrypt speed %f Gbps \n",decrypt_speed/100);
	usleep(1000);
    }
    ret=TCM_APTerminate(authHandle);
    if(ret<0)
    {
	printf("TCM_APTerminate %x failed!\n",authHandle);
	return -EINVAL;	
    }	
    ret=TCM_APTerminate(keyAuthHandle);
    if(ret<0)
    {
	printf("TCM_APTerminate %x failed!\n",keyAuthHandle);
	return -EINVAL;	
    }	
    ret=TCM_EvictKey(keyHandle);
    if(ret<0)
    {
	printf("TCM_EvictKey %x failed!\n",keyHandle);
	return -EINVAL;	
    }	

    return ret;	

}

