#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
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
#include "sm2.h"

#define MAX_SM3_ARGS 30
#define MAX_SM3_LEN  1024
static BYTE Buf[DIGEST_SIZE*64];

int vtcm_sm3(char * hashout,int elem_no,...)
{
   BYTE *hash_buf;
   int hash_len;
   int total_len=0;
   int argno=0;
   BYTE * hash_elem;	
   int i;

   if((elem_no<0)||(elem_no>=MAX_SM3_ARGS))
	return -EINVAL;
   hash_buf=Talloc0(MAX_SM3_LEN);
   if(hash_buf==NULL)
	return -EINVAL; 	   

   va_list ap ;
   va_start(ap,elem_no);

    for (i=0;i<elem_no;i++)
    {
        hash_elem = va_arg(ap, BYTE *);
	argno++;
	if(hash_elem==0)
	{
		Free(hash_buf);
		return -EINVAL;
	}
	hash_len = va_arg(ap,int);
	argno++;
	if(total_len+hash_len>MAX_SM3_LEN)
		return -EINVAL;
	Memcpy(hash_buf+total_len,hash_elem,hash_len);
	total_len+=hash_len;
    }
    va_end(ap);
    calculate_context_sm3(hash_buf,total_len,hashout);
    Free(hash_buf);
    return total_len;	
}

int vtcm_Random(BYTE* buffer, size_t bytes)
{
    printf("vtcm_Random : Start\n");

    int ret = 0;

    if (ret == 0) { /* openSSL call */
        ret = RAND_bytes(buffer, bytes);
        if (ret < 0) { 
            printf("TCM_Random: Error (fatal) calling RAND_bytes()\n");
            ret = -EINVAL;
        }
    }
    return ret;
}

int vtcm_hmac_sm3(char * hashout,BYTE * key, int keylen,int elem_no,...)
{
   BYTE *hash_buf;
   int hash_len;
   int total_len=0;
   int argno=0;
   BYTE * hash_elem;
   int i;	

   if((elem_no<0)||(elem_no>=MAX_SM3_ARGS))
	return -EINVAL;
   hash_buf=Talloc0(MAX_SM3_LEN);
   if(hash_buf==NULL)
	return -EINVAL; 	   

   va_list ap ;
   va_start(ap,elem_no);

    for(i=0;i<elem_no;i++)
    {
        hash_elem = va_arg(ap, BYTE *);
	argno++;
	if(hash_elem==0)
	{
		Free(hash_buf);
		return -EINVAL;
	}
	hash_len = va_arg(ap,int);
	argno++;
	if(total_len+hash_len>MAX_SM3_LEN)
		return -EINVAL;
	Memcpy(hash_buf+total_len,hash_elem,hash_len);
	total_len+=hash_len;
    }
    va_end(ap);
    SM3_hmac(key,keylen,hash_buf,total_len,hashout);
    Free(hash_buf);
    return total_len;	
}
