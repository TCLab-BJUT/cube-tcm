#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <dirent.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

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
//#include "tesi.h"

#include "file_struct.h"
#include "tesi_key.h"
#include "tesi_aik_struct.h"
#include "vtpm_key.h"

#include "app_struct.h"
#include "tpm_global.h"
#include "tpm_error.h"
static struct timeval time_val={0,50*1000};
struct vtpm_key_scene * key_scenes;







/* TPM_Malloc() is a general purpose wrapper around malloc()
 */

TPM_RESULT TPM_Malloc(unsigned char **buffer, uint32_t size)
{
    TPM_RESULT          rc = 0;

    /* assertion test.  The coding style requires that all allocated pointers are initialized to
       NULL.  A non-NULL value indicates either a missing initialization or a pointer reuse (a
       memory leak). */
    if (rc == 0) {
        if (*buffer != NULL) {
            printf("TPM_Malloc: Error (fatal), *buffer %p should be NULL before malloc\n", *buffer);
            rc = TPM_FAIL;
        }
    }
    /* verify that the size is not "too large" */
    if (rc == 0) {
        if (size > TPM_ALLOC_MAX) {
            printf("TPM_Malloc: Error, size %u greater than maximum allowed\n", size);
            rc = TPM_SIZE;
        }
    }
    /* verify that the size is not 0, this would be implementation defined and should never occur */
    if (rc == 0) {
        if (size == 0) {
            printf("TPM_Malloc: Error (fatal), size is zero\n");
            rc = TPM_FAIL;
        }
    }
    if (rc == 0) {
        *buffer = malloc(size);
        if (*buffer == NULL) {
            printf("TPM_Malloc: Error allocating %u bytes\n", size);
            rc = TPM_SIZE;
        }
    }
    return rc;
}



/* TPM_BN_num_bytes() wraps the openSSL function in a TPM error handler
 
   Returns number of bytes in the input
*/

TPM_RESULT TPM_BN_num_bytes(unsigned int *numBytes, TPM_BIGNUM bn_in)
{
    TPM_RESULT  rc = 0;
    int         i;
    BIGNUM      *bn = (BIGNUM *)bn_in;

    i = BN_num_bytes(bn);
    if (i >= 0) {
        *numBytes = (unsigned int)i;
    }
    else {
        printf("TPM_BN_num_bytes: Error (fatal), bytes in BIGNUM is negative\n");
        TPM_OpenSSL_PrintError();
        rc = TPM_FAIL;
    }
    return rc;
}

/* TPM_bn2bin wraps the openSSL function in a TPM error handler.

   Converts a bignum to char array

   'bin' must already be checked for sufficient size.

   int BN_bn2bin(const BIGNUM *a, unsigned char *to);
   BN_bn2bin() returns the length of the big-endian number placed at to
*/

TPM_RESULT TPM_bn2bin(unsigned char *bin,
                      TPM_BIGNUM bn_in)
{
    TPM_RESULT  rc = 0;
    BN_bn2bin((BIGNUM *)bn_in, bin);
    return rc;
}




/* TPM_bn2binArray() loads the array 'bin' of size 'bytes' from 'bn'

   The data from 'bn' is right justified and zero padded.
*/

TPM_RESULT TPM_bn2binArray(unsigned char *bin,
                           unsigned int bytes,
                           TPM_BIGNUM bn)
{
    TPM_RESULT          rc = 0;
    unsigned int        numBytes;

    printf("   TPM_bn2binArray: size %u\n", bytes);
    if (rc == 0) {
        /* zero pad */
        memset(bin, 0, bytes);
        /* bytes required for the bignum */
        rc = TPM_BN_num_bytes(&numBytes, bn);
    }
    /* if the array is less than the number of bytes required by the bignum, this function fails */
    if (rc == 0) {
        printf("   TPM_bn2binArray: numBytes in bignum %u\n", numBytes);
        if (numBytes > bytes) {
            printf("TPM_bn2binArray: Error, "
                   "BN bytes %u greater than array bytes %u\n", numBytes, bytes);
            rc = TPM_SIZE;
        }
    }
    if (rc == 0) {
        /* if there are bytes in the bignum (it is not zero) */
        if (numBytes  > 0) {
            rc = TPM_bn2bin(bin + bytes - numBytes,     /* store right justified */
                            bn);
        }
    }
    return rc;
}



/* TPM_bn2binMalloc() allocates a buffer 'bin' and loads it from 'bn'.
   'bytes' is set to the allocated size of 'bin'.

   If padBytes is non-zero, 'bin' is padded with leading zeros if necessary, so that 'bytes' will
   equal 'padBytes'.  This is used when TPM data structures expect a fixed length while the crypto
   library 'bn to bin' function might truncates leading zeros.

   '*bin' must be freed by the caller
*/

TPM_RESULT TPM_bn2binMalloc(unsigned char **bin,        /* freed by caller */
                            unsigned int *bytes,
                            TPM_BIGNUM bn,
                            uint32_t padBytes)
{
    TPM_RESULT  rc = 0;

    printf("   TPM_bn2binMalloc: padBytes %u\n", padBytes);
    /* number of bytes required in the bin array */
    if (rc == 0) {
        rc = TPM_BN_num_bytes(bytes, bn);// bn = ras->n
    }
    /* calculate the array size to malloc */
    if (rc == 0) {
        /* padBytes 0 says that no padding is required */
        if (padBytes == 0) {
            padBytes = *bytes;  /* setting equal yields no padding */
        }
        /* if the array with padding is still less than the number of bytes required by the bignum,
           this function fails */
        if (padBytes < *bytes) {
            printf("TPM_bn2binMalloc: Error, "
                   "padBytes %u less than BN bytes %u\n", padBytes, *bytes);
            rc = TPM_SIZE;
        }
        /* log if padding is occurring */
        if (padBytes != *bytes) {
            printf("   TPM_bn2binMalloc: padBytes %u bytes %u\n", padBytes, *bytes);
        }
    }
    /* allocate for the padded array */
    if (rc == 0) {
        rc = TPM_Malloc(bin, padBytes);
        *bytes = padBytes;
    }
    /* call the bignum to bin conversion */
    if (rc == 0) {
        rc = TPM_bn2binArray(*bin, padBytes, bn);
    }
    return rc;
}
                                       




/*
  RSA Functions
*/

/* Generate an RSA key pair.

   'n', 'p', 'q', 'd' must be freed by the caller
*/

TPM_RESULT TPM_RSAGenerateKeyPair(unsigned char **n,            /* public key - modulus */
                                  unsigned char **p,            /* private key prime */
                                  unsigned char **q,            /* private key prime */
                                  unsigned char **d,            /* private key (private exponent) */
                                  int num_bits,                 /* key size in bits */
                                  const unsigned char *earr,    /* public exponent as an array */
                                  uint32_t e_size)
{
    TPM_RESULT rc = 0;
    RSA *rsa = NULL;
    uint32_t nbytes;
    uint32_t pbytes;
    uint32_t qbytes;
    uint32_t dbytes;

    unsigned long e;

    /* initialize in case of error */
    printf(" TPM_RSAGenerateKeyPair:\n");
    *n = NULL;
    *p = NULL;
    *q = NULL;
    *d = NULL;

    /* check that num_bits is a multiple of 16.  If not, the primes p and q will not be a multiple of
       8 and will not fit well in a byte */
    if (rc == 0) {
        if ((num_bits % 16) != 0) {
            printf("TPM_RSAGenerateKeyPair: Error, num_bits %d is not a multiple of 16\n",
                   num_bits);
            rc = TPM_BAD_KEY_PROPERTY;
        }
    }
    /* convert the e array to an unsigned long */
    if (rc == 0) {
        rc = TPM_LoadLong(&e, earr, e_size);
    }
    /* validate the public exponent against a list of legal values.  Some values (e.g. even numbers)
       will hang the key generator. */
                                             
    if (rc == 0) {
        rc = TPM_RSA_exponent_verify(e);
    }
    if (rc == 0) {
        printf("  TPM_RSAGenerateKeyPair: num_bits %d exponent %08lx\n", num_bits, e);
        rsa = RSA_generate_key(num_bits, e, NULL, NULL);                /* freed @1 */
        if (rsa == NULL) {
            printf("TPM_RSAGenerateKeyPair: Error calling RSA_generate_key()\n");
            rc = TPM_BAD_KEY_PROPERTY;
        }
    }
    /* load n */
    if (rc == 0) {
        rc = TPM_bn2binMalloc(n, &nbytes, (TPM_BIGNUM)rsa->n, num_bits/8); /* freed by caller */
    }
    /* load p */
    if (rc == 0) {
        rc = TPM_bn2binMalloc(p, &pbytes, (TPM_BIGNUM)rsa->p, num_bits/16); /* freed by caller */
    }
    /* load q */
    if (rc == 0) {
        rc = TPM_bn2binMalloc(q, &qbytes, (TPM_BIGNUM)rsa->q, num_bits/16); /* freed by caller */
    }
    /* load d */
    if (rc == 0) {
        rc = TPM_bn2binMalloc(d, &dbytes, (TPM_BIGNUM)rsa->d, num_bits/8); /* freed by caller */
    }
    if (rc == 0) {
        printf("  TPM_RSAGenerateKeyPair: length of n,p,q,d = %d / %d / %d / %d\n",
               nbytes, pbytes, qbytes, dbytes);
    }
    if (rc != 0) {
        free(*n);
        free(*p);
        free(*q);
        free(*d);
        *n = NULL;
        *p = NULL;
        *q = NULL;
        *d = NULL;
    }
    if (rsa != NULL) {
        RSA_free(rsa);  /* @1 */
    }
    return rc;
}




int vtpm_BN_num_bytes(unsigned int *numBytes ,unsigned char * bn_in)
{
	int ret = 0 ;
	int i ;
	BIGNUM *bn = (BIGNUM *)bn_in ;
	
	i = BN_num_bytes(bn) ;
	
	if(i >= 0){
	    *numBytes = (unsigned int) i ;
	}
	else{
	    ret = 1 ;
	}
	return ret ;
}

 

/* TPM_bn2bin wraps the openSSL function in a TPM error handler.

   Converts a bignum to char array

   'bin' must already be checked for sufficient size.

   int BN_bn2bin(const BIGNUM *a, unsigned char *to);
   BN_bn2bin() returns the length of the big-endian number placed at to
*/

int vtpm_bn2bin(unsigned char *bin ,unsigned char * bn_in)
{
        int ret = 0 ;
        
	BN_bn2bin((BIGNUM *)bn_in, bin);
    
	return ret ;
}




/* TPM_bn2binArray() loads the array 'bin' of size 'bytes' from 'bn'

   The data from 'bn' is right justified and zero padded.
*/

int vtpm_bn2binArray(unsigned char *bin ,unsigned int bytes ,unsigned char * bn)
{
    int ret  = 0 ;
    unsigned int numBytes ;

    printf("   TPM_bn2binArray: size %u\n", bytes);
    if (ret == 0) {
        /* zero pad */
        memset(bin, 0, bytes);
        /* bytes required for the bignum */
        ret = vtpm_BN_num_bytes(&numBytes, bn);
    }
    /* if the array is less than the number of bytes required by the bignum, this function fails */
    if (ret == 0) {
        printf("   TPM_bn2binArray: numBytes in bignum %u\n", numBytes);
        if (numBytes > bytes) {
            printf("TPM_bn2binArray: Error, "
                   "BN bytes %u greater than array bytes %u\n", numBytes, bytes);
            ret = 1 ;
        }
    }
    if (ret == 0) {
        /* if there are bytes in the bignum (it is not zero) */
        if (numBytes  > 0) {
            ret = vtpm_bn2bin(bin + bytes - numBytes,     /* store right justified */
                            bn);
        }
    }
    return ret ;
}

/* TPM_Malloc() is a general purpose wrapper around malloc()
 */

int vtpm_Malloc(unsigned char **buffer, uint32_t size)
{
    int ret = 0 ;

    /* assertion test.  The coding style requires that all allocated pointers are initialized to
       NULL.  A non-NULL value indicates either a missing initialization or a pointer reuse (a
       memory leak). */
    if (ret == 0) {
        if (*buffer != NULL) {
            printf("TPM_Malloc: Error (fatal), *buffer %p should be NULL before malloc\n", *buffer);
            ret = 1 ;
        }
    }
    /* verify that the size is not "too large" */
    if (ret == 0) {
        if (size > TPM_ALLOC_MAX) {
            printf("TPM_Malloc: Error, size %u greater than maximum allowed\n", size);
            ret = 1 ;
        }
    }
    /* verify that the size is not 0, this would be implementation defined and should never occur */
    if (ret == 0) {
        if (size == 0) {
            printf("TPM_Malloc: Error (fatal), size is zero\n");
            ret = 1 ;
        }
    }
    if (ret == 0) {
        *buffer = malloc(size);
        if (*buffer == NULL) {
            printf("TPM_Malloc: Error allocating %u bytes\n", size);
            ret = 1 ;
        }
    }
    return ret;
}





int vtpm_bn2binMalloc(unsigned char ** bin ,unsigned int *bytes ,unsigned char * bn ,uint32_t padBytes)
{
	int ret = 0;

        printf("   TPM_bn2binMalloc: padBytes %u\n", padBytes);
        
	/* number of bytes required in the bin array */
        ret = vtpm_BN_num_bytes(bytes, bn);// bn = rsa->n 
       
	 /* calculate the array size to malloc */
        if (ret == 0) {
            /* padBytes 0 says that no padding is required */
            if (padBytes == 0) {// padBytes = num_bits/8
                padBytes = *bytes;  /* setting equal yields no padding */
            }
            /* if the array with padding is still less than the number of bytes required by the bignum,
               this function fails */
            if (padBytes < *bytes) {
                printf("TPM_bn2binMalloc: Error, "
                       "padBytes %u less than BN bytes %u\n", padBytes, *bytes) ;
                ret = 1 ;
            }
            /* log if padding is occurring */
            if (padBytes != *bytes) {
                printf("   TPM_bn2binMalloc: padBytes %u bytes %u\n", padBytes, *bytes);
            }
        }
        /* allocate for the padded array */
        if (ret == 0) {
            ret = vtpm_Malloc(bin, padBytes);
            *bytes = padBytes;
        }
        /* call the bignum to bin conversion */
        if (ret == 0) {
            ret = vtpm_bn2binArray(*bin, padBytes, bn);
        }
        return ret ;
	
}

int vtpm_key_init(void * sub_proc,void * para)
{
 	
	int num_bits ;// key size in bits
	unsigned long e ;
	RSA *rsa = NULL ;

	unsigned char **n ;
	unsigned char **p ;
	unsigned char **q ;
	unsigned char **d ;
		
	uint32_t nbytes ;
	uint32_t pbytes ;
	uint32_t qbytes ;
	uint32_t dbytes ;
	

	rsa = RSA_generate_key(num_bits, e, NULL, NULL);//generate	
   
	// load n 
        ret = vtpm_bn2binMalloc(n ,&nbytes ,(unsigned char *)rsa->n ,num_bits/8) ;


	return 0;
}

int vtpm_key_start(void * sub_proc,void * para)
{
    return 0;
};


