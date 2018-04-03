/********************************************************************************/
/*                                                                              */
/*                              TCM Structures                                  */
/*                           Written by Ken Goldman                             */
/*                     IBM Thomas J. Watson Research Center                     */
/*            $Id: tcm_structures.h 4528 2011-03-29 22:16:28Z kgoldman $        */
/*                                                                              */
/* (c) Copyright IBM Corporation 2006, 2010.					*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

#ifndef TCM_STRUCTURES_H
#define TCM_STRUCTURES_H

#include <limits.h>
#include "tcm_constants.h"
#include "tcm_types.h"
//#include "tcm_nvram_const.h"

/* Sanity check on build macros are centralized here, since any TCM will use this header */
/*
#if !defined (TCM_POSIX) && !defined (TCM_WINDOWS) && !defined(TCM_SYSTEM_P)
#error "Must define either TCM_POSIX or TCM_WINDOWS or TCM_SYSTEM_P"
#endif

#if defined (TCM_NV_XCRYPTO_FLASH) && defined (TCM_NV_DISK)
#error "Cannot define TCM_NV_XCRYPTO_FLASH and TCM_NV_DISK"
#endif

#if defined (TCM_WINDOWS) && defined (TCM_UNIX_DOMAIN_SOCKET)
#error "Cannot define TCM_WINDOWS and TCM_UNIX_DOMAIN_SOCKET"
#endif

#if defined (TCM_USE_CHARDEV) && defined (TCM_UNIX_DOMAIN_SOCKET)
#error "Cannot define TCM_USE_CHARDEV and TCM_UNIX_DOMAIN_SOCKET"
#endif

#if defined (TCM_NV_XCRYPTO_FLASH) && defined (TCM_UNIX_DOMAIN_SOCKET)
#error "Cannot define TCM_NV_XCRYPTO_FLASH and TCM_UNIX_DOMAIN_SOCKET"
#endif

#if defined (TCM_XCRYPTO_USE_HW) && !defined(TCM_NV_XCRYPTO_FLASH)
#error "TCM_XCRYPTO_USE_HW requires TCM_NV_XCRYPTO_FLASH"
#endif

#if defined (TCM_VTCM) && defined (TCM_UNIX_DOMAIN_SOCKET)
#error "Cannot define TCM_VTCM and TCM_UNIX_DOMAIN_SOCKET"
#endif



#if defined (TCM_V11) && defined (TCM_V12)
#error "Cannot define TCM_V12 and TCM_V11"
#endif

#if !defined (TCM_V11) && !defined (TCM_V12)
#error "Must define either TCM_V12 or TCM_V11"
#endif


#if defined (TCM_DES) && defined (TCM_AES)
#error "Cannot define TCM_DES and TCM_AES"
#endif
#if !defined (TCM_DES) && !defined (TCM_AES)
#error "Must define either TCM_DES or TCM_AES"
#endif
*/

/* This structure is typically a cast from a subset of a larger TCM structure.  Two members - a 4
   bytes size followed by a 4 bytes pointer to the data is a common TCM structure idiom. */

typedef struct tdTCM_SIZED_BUFFER {
    uint32_t size;
    BYTE *buffer;
}__attribute__((packed)) TCM_SIZED_BUFFER;

/* This structure implements a safe storage buffer, used throughout the code when serializing
   structures to a stream.
*/

typedef struct tdTCM_STORE_BUFFER {
    unsigned char *buffer;              /* beginning of buffer */
    unsigned char *buffer_current;      /* first empty position in buffer */
    unsigned char *buffer_end;          /* one past last valid position in buffer */
}__attribute__((packed)) TCM_STORE_BUFFER;

/* 5.1 TCM_STRUCT_VER rev 100

   This indicates the version of the structure or TCM. 

   Version 1.2 deprecates the use of this structure in all other structures. The structure is not
   deprecated as many of the structures that contain this structure are not deprecated.
*/

#define TCM_MAJOR       0x01

//#if defined TCM_V12
#define TCM_MINOR       0x02
//#endif

//#if defined TCM_V11
//#define TCM_MINOR       0x01
//#endif

typedef struct tdTCM_STRUCT_VER { 
    BYTE major;         /* This SHALL indicate the major version of the structure. MUST be 0x01 */
    BYTE minor;         /* This SHALL indicate the minor version of the structure. MUST be 0x01 */
    BYTE revMajor;      /* This MUST be 0x00 on output, ignored on input */
    BYTE revMinor;      /* This MUST be 0x00 on output, ignored on input */
}__attribute__((packed))TCM_STRUCT_VER; 

/* 5.2 TCM_VERSION_BYTE rev 87

   Allocating a byte for the version information is wasteful of space. The current allocation does
   not provide sufficient resolution to indicate completely the version of the TCM. To allow for
   backwards compatibility the size of the structure does not change from 1.1.
   
   To enable minor version, or revision, numbers with 2-digit resolution, the byte representing a
   version splits into two BDC encoded nibbles. The ordering of the low and high order provides
   backwards compatibility with existing numbering.
   
   An example of an implementation of this is; a version of 1.23 would have the value 2 in bit
   positions 3-0 and the value 3 in bit positions 7-4.

   TCM_VERSION_BYTE is a byte. The byte is broken up according to the following rule

   7-4 leastSigVer Least significant nibble of the minor version. MUST be values within the range of
        0000-1001
   3-0 mostSigVer Most significant nibble of the minor version. MUST be values within the range of
        0000-1001
*/

/* 5.3 TCM_VERSION rev 116

   This structure provides information relative the version of the TCM. This structure should only
   be in use by TCM_GetCapability to provide the information relative to the TCM.
*/

typedef struct tdTCM_VERSION { 
    BYTE major;     /* This SHALL indicate the major version of the TCM, mostSigVer MUST
                                   be 0x1, leastSigVer MUST be 0x0 */
    BYTE minor;     /* This SHALL indicate the minor version of the TCM, mostSigVer MUST
                                   be 0x1 or 0x2, leastSigVer MUST be 0x0 */
    BYTE revMajor;              /* This SHALL be the value of the TCM_PERMANENT_DATA -> revMajor */
    BYTE revMinor;              /* This SHALL be the value of the TCM_PERMANENT_DATA -> revMinor */
} TCM_VERSION; 

/* 5.4 TCM_DIGEST rev 111

   The digest value reports the result of a hash operation.

   In version 1 the hash algorithm is SHA-1 with a resulting hash result being 20 bytes or 160 bits.

   It is understood that algorithm agility is lost due to fixing the hash at 20 bytes and on
   SHA-1. The reason for fixing is due to the internal use of the digest. It is the authorization
   values, it provides the secrets for the HMAC and the size of 20 bytes determines the values that
   can be stored and encrypted. For this reason, the size is fixed and any changes to this value
   require a new version of the specification.

   The digestSize parameter MUST indicate the block size of the algorithm and MUST be 20 or greater.

   For all TCM v1 hash operations, the hash algorithm MUST be SHA-1 and the digestSize parameter is
   therefore equal to 20.
*/

#define TCM_DIGEST_SIZE 32
/* typedef BYTE TCM_DIGEST[TCM_DIGEST_SIZE]; */


/* kgold - This was designed as a structure with one element.  Changed to a simple BYTE array, like
   TCM_SECRET. */
typedef struct tdTCM_DIGEST {
    BYTE digest[TCM_DIGEST_SIZE];       /* This SHALL be the actual digest information */
}__attribute__((packed)) TCM_DIGEST;

/* Redefinitions */

typedef TCM_DIGEST TCM_CHOSENID_HASH;   /* This SHALL be the digest of the chosen identityLabel and
                                           privacyCA for a new TCM identity.*/

typedef TCM_DIGEST TCM_COMPOSITE_HASH;  /* This SHALL be the hash of a list of PCR indexes and PCR
                                           values that a key or data is bound to. */

typedef TCM_DIGEST TCM_DIRVALUE;        /* This SHALL be the value of a DIR register */

typedef TCM_DIGEST TCM_HMAC;            /* This shall be the output of the HMAC algorithm */

typedef TCM_DIGEST TCM_PCRVALUE;        /* The value inside of the PCR */

typedef TCM_DIGEST TCM_AUDITDIGEST;     /* This SHALL be the value of the current internal audit
                                           state */

/* 5.5 TCM_NONCE rev 99

   A nonce is a random value that provides protection from replay and other attacks.  Many of the
   commands and protocols in the specification require a nonce. This structure provides a consistent
   view of what a nonce is.
*/

#define TCM_NONCE_SIZE 32
typedef BYTE TCM_NONCE[TCM_NONCE_SIZE]; 

typedef TCM_NONCE TCM_DAA_TCM_SEED;     /* This SHALL be a random value generated by a TCM
                                           immediately after the EK is installed in that TCM,
                                           whenever an EK is installed in that TCM */
typedef TCM_NONCE TCM_DAA_CONTEXT_SEED; /* This SHALL be a random value */

/* 5.6 TCM_AUTHDATA rev 87

   The authorization data is the information that is saved or passed to provide proof of ownership
   of an entity.  For version 1 this area is always 20 bytes.
*/

#define TCM_AUTHDATA_SIZE 32
typedef struct tdTCM_AUTHDATA
{
    BYTE authdata[TCM_AUTHDATA_SIZE];
}__attribute__((packed)) TCM_AUTHDATA;

#define TCM_SECRET_SIZE 32
typedef BYTE TCM_SECRET[TCM_SECRET_SIZE];

#if 0   /* kgold - define TCM_SECRET directly, so the size can be defined */
typedef TCM_AUTHDATA TCM_SECRET; /* A secret plain text value used in the authorization process. */
#endif

typedef TCM_AUTHDATA TCM_ENCAUTH; /* A cipher text (encrypted) version of authorization data. The
                                     encryption mechanism depends on the context. */

/* 5.7 TCM_KEY_HANDLE_LIST rev 87

   TCM_KEY_HANDLE_LIST is a structure used to describe the handles of all keys currently loaded into
   a TCM.
*/

#if 0   /* This is the version from the specification part 2 */
typedef struct tdTCM_KEY_HANDLE_LIST {
    uint16_t loaded;                      /* The number of keys currently loaded in the TCM. */
    [size_is(loaded)] TCM_KEY_HANDLE handle[];  /* An array of handles, one for each key currently
                                                   loaded in the TCM */
} TCM_KEY_HANDLE_LIST; 
#endif

/* 5.11 TCM_CHANGEAUTH_VALIDATE rev 87

   This structure provides an area that will stores the new authorization data and the challenger's
   nonce.
*/

typedef struct tdTCM_CHANGEAUTH_VALIDATE { 
    TCM_SECRET newAuthSecret;   /* This SHALL be the new authorization data for the target entity */
    TCM_NONCE n1;               /* This SHOULD be a nonce, to enable the caller to verify that the
                                   target TCM is on-line. */
} TCM_CHANGEAUTH_VALIDATE; 



/* PCR */

/* NOTE: The TCM requires and the code assumes a multiple of CHAR_BIT (8).  48 registers (6 bytes)
   may be a bad number, as it makes TCM_PCR_INFO and TCM_PCR_INFO_LONG indistinguishable in the
   first two bytes. */

//#if defined TCM_V11
//#define TCM_NUM_PCR 16          /* Use PC Client specification values */
//#endif

//#if defined TCM_V12
#define TCM_NUM_PCR 24          /* Use PC Client specification values */
//#endif

#if (CHAR_BIT != 8)
#error "CHAR_BIT must be 8"
#endif

#if ((TCM_NUM_PCR % 8) != 0)
#error "TCM_NUM_PCR must be a multiple of 8"
#endif

/* 8.1 TCM_PCR_SELECTION rev 110

   This structure provides a standard method of specifying a list of PCR registers.
*/

typedef struct tdTCM_PCR_SELECTION { 
    uint16_t sizeOfSelect;			/* The size in bytes of the pcrSelect structure */
    BYTE  pcrSelect[TCM_NUM_PCR/CHAR_BIT];       /* This SHALL be a bit map that indicates if a PCR
                                                   is active or not */
}__attribute__((packed))TCM_PCR_SELECTION; 

/* 8.2 TCM_PCR_COMPOSITE rev 97

   The composite structure provides the index and value of the PCR register to be used when creating
   the value that SEALS an entity to the composite.
*/

typedef struct tdTCM_PCR_COMPOSITE { 
    TCM_PCR_SELECTION select;   /* This SHALL be the indication of which PCR values are active */
    uint32_t valueSize;           /* This SHALL be the size of the pcrValue field (not the number of
				     PCR's) */
    BYTE *pcrValue;     /* This SHALL be an array of TCM_PCRVALUE structures. The values
                                   come in the order specified by the select parameter and are
                                   concatenated into a single blob */
}__attribute__((packed))  TCM_PCR_COMPOSITE; 

/* 8.3 TCM_PCR_INFO rev 87 

   The TCM_PCR_INFO structure contains the information related to the wrapping of a key or the
   sealing of data, to a set of PCRs.
*/

typedef struct tdTCM_PCR_INFO { 
    TCM_PCR_SELECTION pcrSelection ;             /* This SHALL be the selection of PCRs to which the
                                                   data or key is bound. */
    TCM_COMPOSITE_HASH digestAtRelease ;         /* This SHALL be the digest of the PCR indices and
                                                   PCR values to verify when revealing Sealed Data
                                                   or using a key that was wrapped to PCRs.  NOTE:
                                                   This is passed in by the host, and used as
                                                   authorization to use the key */
    TCM_COMPOSITE_HASH digestAtCreation ;        /* This SHALL be the composite digest value of the
                                                   PCR values, at the time when the sealing is
                                                   performed. NOTE: This is generated at key
                                                   creation, but is just informative to the host,
                                                   not used for authorization */
}__attribute__((packed)) TCM_PCR_INFO ; 

/* 8.6 TCM_LOCALITY_SELECTION rev 87 

   When used with localityAtCreation only one bit is set and it corresponds to the locality of the
   command creating the structure.

   When used with localityAtRelease the bits indicate which localities CAN perform the release.
*/

typedef BYTE TCM_LOCALITY_SELECTION;

#define TCM_LOC_FOUR    0x10    /* Locality 4 */
#define TCM_LOC_THREE   0x08    /* Locality 3  */
#define TCM_LOC_TWO     0x04    /* Locality 2  */
#define TCM_LOC_ONE     0x02    /* Locality 1  */
#define TCM_LOC_ZERO    0x01    /* Locality 0. This is the same as the legacy interface.  */

#define TCM_LOC_ALL     0x1f    /* kgold - added all localities */
#define TCM_LOC_MAX     4       /* kgold - maximum value for TCM_MODIFIER_INDICATOR */


/* 8.4 TCM_PCR_INFO_LONG rev 109

   The TCM_PCR_INFO structure contains the information related to the wrapping of a key or the
   sealing of data, to a set of PCRs.

   The LONG version includes information necessary to properly define the configuration that creates
   the blob using the PCR selection.
*/

typedef struct tdTCM_PCR_INFO_LONG { 
//#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;                      /* This SHALL be TCM_TAG_PCR_INFO_LONG  */
//#endif
    TCM_LOCALITY_SELECTION localityAtCreation;  /* This SHALL be the locality modifier of the
                                                   function that creates the PCR info structure */
    TCM_LOCALITY_SELECTION localityAtRelease;   /* This SHALL be the locality modifier required to
                                                   reveal Sealed Data or use a key that was wrapped
                                                   to PCRs */
    TCM_PCR_SELECTION creationPCRSelection;     /* This SHALL be the selection of PCRs active when
                                                   the blob is created */
    TCM_PCR_SELECTION releasePCRSelection;      /* This SHALL be the selection of PCRs to which the
                                                   data or key is bound. */
    TCM_COMPOSITE_HASH digestAtCreation;        /* This SHALL be the composite digest value of the
                                                   PCR values, at the time when the sealing is
                                                   performed. */
    TCM_COMPOSITE_HASH digestAtRelease;         /* This SHALL be the digest of the PCR indices and
                                                   PCR values to verify when revealing Sealed Data
                                                   or using a key that was wrapped to PCRs. */
} TCM_PCR_INFO_LONG; 

/* 8.5 TCM_PCR_INFO_SHORT rev 87

   This structure is for defining a digest at release when the only information that is necessary is
   the release configuration.
*/

typedef struct tdTCM_PCR_INFO_SHORT { 
    TCM_PCR_SELECTION pcrSelection;     /* This SHALL be the selection of PCRs that specifies the
                                           digestAtRelease */
    TCM_LOCALITY_SELECTION localityAtRelease;   /* This SHALL be the locality modifier required to
                                                   release the information.  This value must not be
                                                   zero (0). */
    TCM_COMPOSITE_HASH digestAtRelease;         /* This SHALL be the digest of the PCR indices and
                                                   PCR values to verify when revealing auth data */
} TCM_PCR_INFO_SHORT; 

/* 8.8 TCM_PCR_ATTRIBUTES rev 107

   These attributes are available on a per PCR basis.

   The TCM is not required to maintain this structure internally to the TCM.

   When a challenger evaluates a PCR an understanding of this structure is vital to the proper
   understanding of the platform configuration. As this structure is static for all platforms of the
   same type the structure does not need to be reported with each quote.
*/

typedef struct tdTCM_PCR_ATTRIBUTES { 
    TCM_BOOL pcrReset;          /* A value of TRUE SHALL indicate that the PCR register can be reset
                                   using the TCM_PCR_RESET command. */
    TCM_LOCALITY_SELECTION pcrExtendLocal;      /* An indication of which localities can perform
                                                   extends on the PCR. */
    TCM_LOCALITY_SELECTION pcrResetLocal;       /* An indication of which localities can reset the
                                                   PCR */
} TCM_PCR_ATTRIBUTES; 

/*
  9. Storage Structures 
*/

/* 9.1 TCM_STORED_DATA rev 87 

   The definition of this structure is necessary to ensure the enforcement of security properties.
   
   This structure is in use by the TCM_Seal and TCM_Unseal commands to identify the PCR index and
   values that must be present to properly unseal the data.

   This structure only provides 1.1 data store and uses PCR_INFO

   1. This structure is created during the TCM_Seal process. The confidential data is encrypted
   using a nonmigratable key. When the TCM_Unseal decrypts this structure the TCM_Unseal uses the
   public information in the structure to validate the current configuration and release the
   decrypted data

   2. When sealInfoSize is not 0 sealInfo MUST be TCM_PCR_INFO
*/

typedef struct tdTCM_STORED_DATA { 
    TCM_STRUCTURE_TAG tag;
    TCM_ENTITY_TYPE et;
    uint32_t sealInfoSize;	/* Size of the sealInfo parameter */
    BYTE* sealInfo;             /* This SHALL be a structure of type TCM_PCR_INFO or a 0 length
                                   array if the data is not bound to PCRs. */
    uint32_t encDataSize;	/* This SHALL be the size of the encData parameter */
    BYTE* encData;              /* This shall be an encrypted TCM_SEALED_DATA structure containing
                                   the confidential part of the data. */
    /* NOTE: kgold - Added this structure, a cache of PCRInfo when not NULL */
}__attribute__((packed)) TCM_STORED_DATA; 


/* 9.2 TCM_STORED_DATA12 rev 101

   The definition of this structure is necessary to ensure the enforcement of security properties.
   This structure is in use by the TCM_Seal and TCM_Unseal commands to identify the PCR index and
   values that must be present to properly unseal the data.

   1. This structure is created during the TCM_Seal process. The confidential data is encrypted
   using a nonmigratable key. When the TCM_Unseal decrypts this structure the TCM_Unseal uses the
   public information in the structure to validate the current configuration and release the
   decrypted data.

   2. If sealInfoSize is not 0 then sealInfo MUST be TCM_PCR_INFO_LONG
*/

typedef struct tdTCM_STORED_DATA12 { 
    TCM_STRUCTURE_TAG tag;      /* This SHALL be TCM_TAG_STORED_DATA12 */
    TCM_ENTITY_TYPE et;         /* The type of blob */
    TCM_SIZED_BUFFER sealInfo;
#if 0
    uint32_t sealInfoSize;	/* Size of the sealInfo parameter */
    BYTE* sealInfo;             /* This SHALL be a structure of type TCM_PCR_INFO_LONG or a 0 length
                                   array if the data is not bound to PCRs. */
#endif
    TCM_SIZED_BUFFER encData;
#if 0
    uint32_t encDataSize;	/* This SHALL be the size of the encData parameter */
    BYTE* encData;              /* This shall be an encrypted TCM_SEALED_DATA structure containing
                                   the confidential part of the data. */
#endif
    /* NOTE: kgold - Added this structure, a cache of PCRInfo when not NULL */
    TCM_PCR_INFO_LONG *tcm_seal_info_long;
} TCM_STORED_DATA12; 

/* 9.3 TCM_SEALED_DATA rev 87 

   This structure contains confidential information related to sealed data, including the data
   itself.

   1. To tie the TCM_STORED_DATA structure to the TCM_SEALED_DATA structure this structure contains
   a digest of the containing TCM_STORED_DATA structure.

   2. The digest calculation does not include the encDataSize and encData parameters.
*/

typedef struct tdTCM_SEALED_DATA { 
    TCM_PAYLOAD_TYPE payload;   /* This SHALL indicate the payload type of TCM_PT_SEAL */
    TCM_SECRET authData;        /* This SHALL be the authorization data for this value */
    TCM_SECRET tcmProof;        /* This SHALL be a copy of TCM_PERMANENT_FLAGS -> tcmProof */
    TCM_DIGEST storedDigest;    /* This SHALL be a digest of the TCM_STORED_DATA structure,
                                   excluding the fields TCM_STORED_DATA -> encDataSize and
                                   TCM_STORED_DATA -> encData.  */
    uint32_t dataSize;		    /* This SHALL be the size of the data parameter */
    BYTE* data;                 /* This SHALL be the data to be sealed */
}__attribute__((packed))TCM_SEALED_DATA; 


/* 9.4 TCM_SYMMETRIC_KEY rev 87 

   This structure describes a symmetric key, used during the process "Collating a Request for a
   Trusted Platform Module Identity".
*/

typedef struct tdTCM_SYMMETRIC_KEY { 
    TCM_ALGORITHM_ID algId;     /* This SHALL be the algorithm identifier of the symmetric key. */
    TCM_ENC_SCHEME encScheme;   /* This SHALL fully identify the manner in which the key will be
                                   used for encryption operations.  */
    uint16_t size;		/* This SHALL be the size of the data parameter in bytes */
    BYTE* data;                 /* This SHALL be the symmetric key data */
    /* NOTE Cannot make this a TCM_SIZED_BUFFER because uint16_t */
} TCM_SYMMETRIC_KEY; 

/* 9.5 TCM_BOUND_DATA rev 87 

   This structure is defined because it is used by a TCM_UnBind command in a consistency check.

   The intent of TCG is to promote "best practice" heuristics for the use of keys: a signing key
   shouldn't be used for storage, and so on. These heuristics are used because of the potential
   threats that arise when the same key is used in different ways. The heuristics minimize the
   number of ways in which a given key can be used.

   One such heuristic is that a key of type TCM_KEY_BIND, and no other type of key, should always be
   used to create the blob that is unwrapped by TCM_UnBind. Binding is not a TCM function, so the
   only choice is to perform a check for the correct payload type when a blob is unwrapped by a key
   of type TCM_KEY_BIND. This requires the blob to have internal structure.

   Even though payloadData has variable size, TCM_BOUND_DATA deliberately does not include the size
   of payloadData. This is to maximise the size of payloadData that can be encrypted when
   TCM_BOUND_DATA is encrypted in a single block. When using TCM-UnBind to obtain payloadData, the
   size of payloadData is deduced as a natural result of the (RSA) decryption process.

   1. This structure MUST be used for creating data when (wrapping with a key of type TCM_KEY_BIND)
   or (wrapping using the encryption algorithm TCM_ES_RSAESOAEP_SHA1_MGF1). If it is not, the
   TCM_UnBind command will fail.
*/

typedef struct tdTCM_BOUND_DATA { 
    TCM_STRUCT_VER ver;                 /* This MUST be 1.1.0.0  */
    TCM_PAYLOAD_TYPE payload;           /* This SHALL be the value TCM_PT_BIND  */
    uint32_t payloadDataSize;		/* NOTE: added, not part of serialization */
    BYTE *payloadData;                  /* The bound data */
} TCM_BOUND_DATA; 

/*
  10. TCM_KEY Complex
*/

/* 10.1.1 TCM_RSA_KEY_PARMS rev 87 

   This structure describes the parameters of an RSA key.
*/

/* TCM_RSA_KEY_LENGTH_MAX restricts the maximum size of an RSA key.  It has two uses:
   - bounds the size of the TCM state
   - protects against a denial of service attack where the attacker creates a very large key
*/

#ifdef TCM_RSA_KEY_LENGTH_MAX		/* if the builder defines a value */
#if ((TCM_RSA_KEY_LENGTH_MAX % 16) != 0)
#error "TCM_RSA_KEY_LENGTH_MAX must be a multiple of 16"
#endif
#if (TCM_RSA_KEY_LENGTH_MAX < 2048)
#error "TCM_RSA_KEY_LENGTH_MAX must be at least 2048"
#endif
#endif		/* TCM_RSA_KEY_LENGTH_MAX */

#ifndef TCM_RSA_KEY_LENGTH_MAX		/* default if the builder does not define a value */
#define TCM_RSA_KEY_LENGTH_MAX 2048
#endif

typedef struct tdTCM_RSA_KEY_PARMS {
    uint32_t keyLength;   /* This specifies the size of the RSA key in bits */
    uint32_t numPrimes;   /* This specifies the number of prime factors used by this RSA key. */
    uint32_t exponentSize;      /* This SHALL be the size of the exponent. If the key is using the
                                   default exponent then the exponentSize MUST be 0. */
    BYTE   *exponent;           /* The public exponent of this key */

} __attribute__((packed)) TCM_RSA_KEY_PARMS;


/* 10.1 TCM_KEY_PARMS rev 87

   This provides a standard mechanism to define the parameters used to generate a key pair, and to
   store the parts of a key shared between the public and private key parts.
*/

typedef struct tdTCM_KEY_PARMS { 
    TCM_ALGORITHM_ID algorithmID;       /* This SHALL be the key algorithm in use */
    TCM_ENC_SCHEME encScheme;   /* This SHALL be the encryption scheme that the key uses to encrypt
                                   information */
    TCM_SIG_SCHEME sigScheme;   /* This SHALL be the signature scheme that the key uses to perform
                                   digital signatures */
    int  parmSize;
    BYTE * parms;	
}__attribute__((packed)) TCM_KEY_PARMS; 

/* 10.1.2 TCM_SYMMETRIC_KEY_PARMS rev 87

   This structure describes the parameters for symmetric algorithms 
*/

typedef struct tdTCM_SM2_ASYMKEY_PARAMETERS { 
    uint32_t keyLength;	/* This SHALL indicate the length of the key in bits */
}__attribute__((packed)) TCM_SM2_ASYMKEY_PARAMETERS; 

typedef struct tdTCM_SYMMETRIC_KEY_PARMS { 
    uint32_t keyLength;	/* This SHALL indicate the length of the key in bits */
    uint32_t blockSize;	/* This SHALL indicate the block size of the algorithm*/
    uint32_t ivSize;	/* This SHALL indicate the size of the IV */
    BYTE *IV;		/* The initialization vector */
}__attribute__((packed)) TCM_SYMMETRIC_KEY_PARMS; 


/* 10.4 TCM_STORE_PUBKEY rev 99

   This structure can be used in conjunction with a corresponding TCM_KEY_PARMS to construct a
   public key which can be unambiguously used.
*/

typedef struct tdTCM_STORE_PUBKEY { 
    uint32_t keyLength;	/* This SHALL be the length of the key field. */
    BYTE   *key;        /* This SHALL be a structure interpreted according to the algorithm Id in
                           the corresponding TCM_KEY_PARMS structure. */
}__attribute__((packed)) TCM_STORE_PUBKEY; 


/* 10.7 TCM_STORE_PRIVKEY rev 87

   This structure can be used in conjunction with a corresponding TCM_PUBKEY to construct a private
   key which can be unambiguously used.
*/

typedef struct tdTCM_STORE_PRIVKEY { 
    uint32_t keyLength;	/* This SHALL be the length of the key field. */
    BYTE* key;          /* This SHALL be a structure interpreted according to the algorithm Id in
                           the corresponding TCM_KEY structure. */
}__attribute__((packed)) TCM_STORE_PRIVKEY; 

/* NOTE: Hard coded for RSA keys.  This will change if other algorithms are supported */


/* 10.6 TCM_STORE_ASYMKEY rev 87

   The TCM_STORE_ASYMKEY structure provides the area to identify the confidential information
   related to a key.  This will include the private key factors for an asymmetric key.

   The structure is designed so that encryption of a TCM_STORE_ASYMKEY structure containing a 2048
   bit RSA key can be done in one operation if the encrypting key is 2048 bits.

   Using typical RSA notation the structure would include P, and when loading the key include the
   unencrypted P*Q which would be used to recover the Q value.

   To accommodate the future use of multiple prime RSA keys the specification of additional prime
   factors is an optional capability.

   This structure provides the basis of defining the protection of the private key.  Changes in this
   structure MUST be reflected in the TCM_MIGRATE_ASYMKEY structure (section 10.8).
*/

typedef struct tdTCM_STORE_ASYMKEY {    
    TCM_PAYLOAD_TYPE payload;           /* This SHALL set to TCM_PT_ASYM to indicate an asymmetric
                                           key. If used in TCM_CMK_ConvertMigration the value SHALL
                                           be TCM_PT_MIGRATE_EXTERNAL. If used in TCM_CMK_CreateKey
                                           the value SHALL be TCM_PT_MIGRATE_RESTRICTED  */
    TCM_SECRET usageAuth;               /* This SHALL be the authorization data necessary to
                                           authorize the use of this value */
    TCM_SECRET migrationAuth;           /* This SHALL be the migration authorization data for a
                                           migratable key, or the TCM secret value tcmProof for a
                                           non-migratable key created by the TCM.

                                           If the TCM sets this parameter to the value tcmProof,
                                           then the TCM_KEY.keyFlags.migratable of the corresponding
                                           TCM_KEY structure MUST be set to 0.

                                           If this parameter is set to the migration authorization
                                           data for the key in parameter PrivKey, then the
                                           TCM_KEY.keyFlags.migratable of the corresponding TCM_KEY
                                           structure SHOULD be set to 1. */
    TCM_DIGEST pubDataDigest;           /* This SHALL be the digest of the corresponding TCM_KEY
                                           structure, excluding the fields TCM_KEY.encSize and
                                           TCM_KEY.encData.

                                           When TCM_KEY -> pcrInfoSize is 0 then the digest
                                           calculation has no input from the pcrInfo field. The
                                           pcrInfoSize field MUST always be part of the digest
                                           calculation.
                                        */
    TCM_STORE_PRIVKEY privKey;          /* This SHALL be the private key data. The privKey can be a
                                           variable length which allows for differences in the key
                                           format. The maximum size of the area would be 151
                                           bytes. */
}__attribute__((packed)) TCM_STORE_ASYMKEY;            

/* 10.7 TCM_STORE_SYMKEY rev 87

   The TCM_STORE_SYMKEY structure provides the area to identify the confidential information
   related to a key.  This will include the symmetric key .

   The structure is designed so that encryption of a TCM_STORE_SYMKEY structure containing a 256
   bit SM4 key can be done in one operation .

   To accommodate the future use of multiple prime RSA keys the specification of additional prime
   factors is an optional capability.

*/

typedef struct tdTCM_STORE_SYMKEY {    
    TCM_PAYLOAD_TYPE payload;           /* This SHALL set to TCM_PT_ASYM to indicate an asymmetric
                                           key. If used in TCM_CMK_ConvertMigration the value SHALL
                                           be TCM_PT_MIGRATE_EXTERNAL. If used in TCM_CMK_CreateKey
                                           the value SHALL be TCM_PT_MIGRATE_RESTRICTED  */
    TCM_SECRET usageAuth;               /* This SHALL be the authorization data necessary to
                                           authorize the use of this value */
    TCM_SECRET migrationAuth;           /* This SHALL be the migration authorization data for a
                                           migratable key, or the TCM secret value tcmProof for a
                                           non-migratable key created by the TCM.

                                           If the TCM sets this parameter to the value tcmProof,
                                           then the TCM_KEY.keyFlags.migratable of the corresponding
                                           TCM_KEY structure MUST be set to 0.

                                           If this parameter is set to the migration authorization
                                           data for the key in parameter PrivKey, then the
                                           TCM_KEY.keyFlags.migratable of the corresponding TCM_KEY
                                           structure SHOULD be set to 1. */
    UINT16 size;
    BYTE * data;  			   /* This SHALL be the private key data. The privKey can be a
                                           variable length which allows for differences in the key
                                           format. The maximum size of the area would be 151
                                           bytes. */
}__attribute__((packed)) TCM_STORE_SYMKEY;            

/* 10.8 TCM_MIGRATE_ASYMKEY rev 87

   The TCM_MIGRATE_ASYMKEY structure provides the area to identify the private key factors of a
   asymmetric key while the key is migrating between TCM's.

   This structure provides the basis of defining the protection of the private key.

   k1k2 - 132 privkey.key (128 + 4)
   k1 - 20, OAEP seed
   k2 - 112, partPrivKey
   TCM_STORE_PRIVKEY 4 partPrivKey.keyLength
                     108 partPrivKey.key (128 - 20)
*/

typedef struct tdTCM_MIGRATE_ASYMKEY {
    TCM_PAYLOAD_TYPE payload;   /* This SHALL set to TCM_PT_MIGRATE or TCM_PT_CMK_MIGRATE to
                                   indicate an migrating asymmetric key or TCM_PT_MAINT to indicate
                                   a maintenance key. */
    TCM_SECRET usageAuth;       /* This SHALL be a copy of the usageAuth from the TCM_STORE_ASYMKEY
                                   structure. */
    TCM_DIGEST pubDataDigest;   /* This SHALL be a copy of the pubDataDigest from the
                                   TCM_STORE_ASYMKEY structure. */
#if 0
    uint32_t partPrivKeyLen;	/* This SHALL be the size of the partPrivKey field */
    BYTE *partPrivKey;          /* This SHALL be the k2 area as described in TCM_CreateMigrationBlob
                                   */
#endif
    TCM_SIZED_BUFFER partPrivKey;
} TCM_MIGRATE_ASYMKEY; 

/* 10.2 TCM_KEY rev 87 

   The TCM_KEY structure provides a mechanism to transport the entire asymmetric key pair. The
   private portion of the key is always encrypted.

   The reason for using a size and pointer for the PCR info structure is save space when the key is
   not bound to a PCR. The only time the information for the PCR is kept with the key is when the
   key needs PCR info.

   The 1.2 version has a change in the PCRInfo area. For 1.2 the structure uses the
   TCM_PCR_INFO_LONG structure to properly define the PCR registers in use.
*/

typedef struct tdTCM_KEY { 
    TCM_STRUCTURE_TAG tag;         /* This MUST be 1.1.0.0 */
    UINT16  fill;	
    TCM_KEY_USAGE keyUsage;     /* This SHALL be the TCM key usage that determines the operations
                                   permitted with this key */
    TCM_KEY_FLAGS keyFlags;     /* This SHALL be the indication of migration, redirection etc.*/
    TCM_AUTH_DATA_USAGE authDataUsage;  /* This SHALL Indicate the conditions where it is required
                                           that authorization be presented.*/
    TCM_KEY_PARMS algorithmParms;       /* This SHALL be the information regarding the algorithm for
                                           this key*/

    uint32_t PCRInfoSize;	/* This SHALL be the length of the pcrInfo parameter. If the key is
                                   not bound to a PCR this value SHOULD be 0.*/
    BYTE* PCRInfo;              /* This SHALL be a structure of type TCM_PCR_INFO, or an empty array
                                   if the key is not bound to PCRs.*/
    TCM_STORE_PUBKEY pubKey;    /* This SHALL be the public portion of the key */
    uint32_t encDataSize;	/* This SHALL be the size of the encData parameter. */
    BYTE* encData;              /* This SHALL be an encrypted TCM_STORE_ASYMKEY structure or
                                   TCM_MIGRATE_ASYMKEY structure */
}__attribute__((packed)) TCM_KEY; 

/* 10.3 TCM_KEY12 rev 87

   This provides the same functionality as TCM_KEY but uses the new PCR_INFO_LONG structures and the
   new structure tagging. In all other aspects this is the same structure.
*/

/* NOTE: The TCM_KEY12 structure is never instantiated.  It is just needed for the cast of TCM_KEY
   to get the TCM_KEY12->tag member. */

typedef struct tdTCM_KEY12 { 
    TCM_STRUCTURE_TAG tag;      /* MUST be TCM_TAG_KEY12 */
    uint16_t fill;		/* MUST be 0x0000 */
    TCM_KEY_USAGE keyUsage;     /* This SHALL be the TCM key usage that determines the operations
                                   permitted with this key */
    TCM_KEY_FLAGS keyFlags;     /* This SHALL be the indication of migration, redirection etc. */
    TCM_AUTH_DATA_USAGE authDataUsage;  /* This SHALL Indicate the conditions where it is required
                                           that authorization be presented. */
    TCM_KEY_PARMS algorithmParms;       /* This SHALL be the information regarding the algorithm for
                                           this key */
#if 0
    uint32_t PCRInfoSize;	/* This SHALL be the length of the pcrInfo parameter. If the key is
                                   not bound to a PCR this value SHOULD be 0. */
    BYTE* PCRInfo;              /* This SHALL be a structure of type TCM_PCR_INFO_LONG, or an empty
                                   array if the key is not bound to PCRs. */
    TCM_STORE_PUBKEY pubKey;    /* This SHALL be the public portion of the key */
    uint32_t encDataSize;	/* This SHALL be the size of the encData parameter. */
    BYTE* encData;              /* This SHALL be an encrypted TCM_STORE_ASYMKEY structure
                                   TCM_MIGRATE_ASYMKEY structure */
#endif
    TCM_SIZED_BUFFER pcrInfo;
    TCM_SIZED_BUFFER pubKey;
    TCM_SIZED_BUFFER encData;
} TCM_KEY12; 


/* 10.5 TCM_PUBKEY rev 99

   The TCM_PUBKEY structure contains the public portion of an asymmetric key pair. It contains all
   the information necessary for its unambiguous usage. It is possible to construct this structure
   from a TCM_KEY, using the algorithmParms and pubKey fields.

   The pubKey member of this structure shall contain the public key for a specific algorithm.
*/

typedef struct tdTCM_PUBKEY { 
    TCM_KEY_PARMS algorithmParms;       /* This SHALL be the information regarding this key */

    TCM_STORE_PUBKEY pubKey;

} __attribute__((packed))TCM_PUBKEY; 

/* 5.b. The TCM must support a minimum of 2 key slots. */

#ifdef TCM_KEY_HANDLES
#if (TCM_KEY_HANDLES < 2)
#error "TCM_KEY_HANDLES minimum is 2"
#endif
#endif 

/* Set the default to 3 so that there can be one owner evict key */

#ifndef TCM_KEY_HANDLES 
#define TCM_KEY_HANDLES 3     /* entries in global TCM_KEY_HANDLE_ENTRY array */
#endif

/* TCM_GetCapability uses a uint_16 for the number of key slots */

#if (TCM_KEY_HANDLES > 0xffff)
#error "TCM_KEY_HANDLES must be less than 0x10000"
#endif

/* The TCM does not have to support any minumum number of owner evict keys.  Adjust this value to
   match the amount of NV space available.  An owner evict key consumes about 512 bytes.

   A value greater than (TCM_KEY_HANDLES - 2) is useless, as the TCM reserves 2 key slots for
   non-owner evict keys to avoid blocking.
*/

#ifndef TCM_OWNER_EVICT_KEY_HANDLES 
#define TCM_OWNER_EVICT_KEY_HANDLES 1 
#endif

#if (TCM_OWNER_EVICT_KEY_HANDLES > (TCM_KEY_HANDLES - 2))
#error "TCM_OWNER_EVICT_KEY_HANDLES too large for TCM_KEY_HANDLES"
#endif

/* This is the version used by the TCM implementation.  It is part of the global TCM state */

/* kgold: Added TCM_KEY member.  There needs to be a mapping between a key handle
   and the pointer to TCM_KEY objects, and this seems to be the right place for it. */

typedef struct tdTCM_KEY_HANDLE_ENTRY {
    TCM_KEY_HANDLE handle;      /* Handles for a key currently loaded in the TCM */
    TCM_KEY *key;               /* Pointer to the key object */
    TCM_BOOL parentPCRStatus;   /* TRUE if parent of this key uses PCR's */
    TCM_KEY_CONTROL keyControl; /* Attributes that can control various aspects of key usage and
                                   manipulation. */
}__attribute__((packed)) TCM_KEY_HANDLE_ENTRY; 

/* 5.12 TCM_MIGRATIONKEYAUTH rev 87

   This structure provides the proof that the associated public key has TCM Owner authorization to
   be a migration key.
*/

typedef struct tdTCM_MIGRATIONKEYAUTH { 
    TCM_PUBKEY migrationKey;            /* This SHALL be the public key of the migration facility */
    TCM_MIGRATE_SCHEME migrationScheme; /* This shall be the type of migration operation.*/
    TCM_DIGEST digest;                  /* This SHALL be the digest value of the concatenation of
                                           migration key, migration scheme and tcmProof */
} TCM_MIGRATIONKEYAUTH; 

/* 5.13 TCM_COUNTER_VALUE rev 87

   This structure returns the counter value. For interoperability, the value size should be 4 bytes.
*/

#define TCM_COUNTER_LABEL_SIZE  4
#define TCM_COUNT_ID_NULL 0xffffffff    /* unused value TCM_CAP_PROP_ACTIVE_COUNTER expects this
                                           value if no counter is active */
#define TCM_COUNT_ID_ILLEGAL 0xfffffffe /* after releasing an active counter */

typedef struct tdTCM_COUNTER_VALUE {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;              /* TCM_TAG_COUNTER_VALUE */
#endif
    BYTE label[TCM_COUNTER_LABEL_SIZE]; /* The label for the counter */
    TCM_ACTUAL_COUNT counter;           /* The 32-bit counter value. */
    /* NOTE: Added.  TCMWG email says the specification structure is the public part, but these are
       vendor specific private members. */
    TCM_SECRET authData;                /* Authorization secret for counter */
    TCM_BOOL valid;
    TCM_DIGEST digest;                  /* for OSAP comparison */
} TCM_COUNTER_VALUE; 

/* 5.14 TCM_SIGN_INFO Structure rev 102

   This is an addition in 1.2 and is the structure signed for certain commands (e.g.,
   TCM_ReleaseTransportSigned).  Some commands have a structure specific to that command (e.g.,
   TCM_Quote uses TCM_QUOTE_INFO) and do not use TCM_SIGN_INFO.

   TCM_Sign uses this structure when the signature scheme is TCM_SS_RSASSAPKCS1v15_INFO.
*/

#define TCM_SIGN_INFO_FIXED_SIZE 4

typedef struct tdTCM_SIGN_INFO { 
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* TCM_TAG_SIGNINFO */
#endif
    BYTE fixed[TCM_SIGN_INFO_FIXED_SIZE];       /* The ASCII text that identifies what function was
                                                   performing the signing operation*/
    TCM_NONCE replay;           /* Nonce provided by caller to prevent replay attacks */
#if 0
    uint32_t dataLen;		/* The length of the data area */
    BYTE* data;                 /* The data that is being signed */
#endif
    TCM_SIZED_BUFFER data;      /* The data that is being signed */
} TCM_SIGN_INFO; 

/* 5.15 TCM_MSA_COMPOSITE Structure rev 87

   TCM_MSA_COMPOSITE contains an arbitrary number of digests of public keys belonging to Migration
   Authorities. An instance of TCM_MSA_COMPOSITE is incorporated into the migrationAuth value of a
   certified-migration-key (CMK), and any of the Migration Authorities specified in that instance is
   able to approve the migration of that certified-migration-key.
   
   TCMs MUST support TCM_MSA_COMPOSITE structures with MSAlist of four (4) or less, and MAY support
   larger values of MSAlist.
*/

typedef struct tdTCM_MSA_COMPOSITE {
    uint32_t MSAlist;			/* The number of migAuthDigests. MSAlist MUST be one (1) or
                                           greater. */
    TCM_DIGEST *migAuthDigest;          /* An arbitrary number of digests of public keys belonging
                                           to Migration Authorities. */
} TCM_MSA_COMPOSITE;

/* 5.16 TCM_CMK_AUTH 

   The signed digest of TCM_CMK_AUTH is a ticket to prove that the entity with public key
   "migrationAuthority" has approved the public key "destination Key" as a migration destination for
   the key with public key "sourceKey".

   Normally the digest of TCM_CMK_AUTH is signed by the private key corresponding to
   "migrationAuthority".

   To reduce data size, TCM_CMK_AUTH contains just the digests of "migrationAuthority",
   "destinationKey" and "sourceKey".
*/

typedef struct tdTCM_CMK_AUTH { 
    TCM_DIGEST migrationAuthorityDigest;        /* The digest of the public key of a Migration
                                                   Authority */
    TCM_DIGEST destinationKeyDigest;            /* The digest of a TCM_PUBKEY structure that is an
                                                   approved destination key for the private key
                                                   associated with "sourceKey"*/
    TCM_DIGEST sourceKeyDigest;                 /* The digest of a TCM_PUBKEY structure whose
                                                   corresponding private key is approved by the
                                                   Migration Authority to be migrated as a child to
                                                   the destinationKey.  */
} TCM_CMK_AUTH;

/* 5.18 TCM_SELECT_SIZE rev 87

  This structure provides the indication for the version and sizeOfSelect structure in GetCapability
*/

typedef struct tdTCM_SELECT_SIZE {
    BYTE major;         /* This SHALL indicate the major version of the TCM. This MUST be 0x01 */
    BYTE minor;         /* This SHALL indicate the minor version of the TCM. This MAY be 0x01 or
                           0x02 */
    uint16_t reqSize;	/* This SHALL indicate the value for a sizeOfSelect field in the
                           TCM_SELECTION structure */
} TCM_SELECT_SIZE;

/* 5.19 TCM_CMK_MIGAUTH rev 89

   Structure to keep track of the CMK migration authorization
*/

typedef struct tdTCM_CMK_MIGAUTH {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* Set to TCM_TAG_CMK_MIGAUTH */
#endif
    TCM_DIGEST msaDigest;       /* The digest of a TCM_MSA_COMPOSITE structure containing the
                                   migration authority public key and parameters. */
    TCM_DIGEST pubKeyDigest;    /* The hash of the associated public key */
} TCM_CMK_MIGAUTH;

/* 5.20 TCM_CMK_SIGTICKET rev 87

   Structure to keep track of the CMK migration authorization
*/

typedef struct tdTCM_CMK_SIGTICKET {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* Set to TCM_TAG_CMK_SIGTICKET */
#endif
    TCM_DIGEST verKeyDigest;    /* The hash of a TCM_PUBKEY structure containing the public key and
                                   parameters of the key that can verify the ticket */
    TCM_DIGEST signedData;      /* The ticket data */
} TCM_CMK_SIGTICKET;

/* 5.21 TCM_CMK_MA_APPROVAL rev 87
    
   Structure to keep track of the CMK migration authorization
*/

typedef struct tdTCM_CMK_MA_APPROVAL {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;                      /* Set to TCM_TAG_CMK_MA_APPROVAL */
#endif
    TCM_DIGEST migrationAuthorityDigest;        /* The hash of a TCM_MSA_COMPOSITE structure
                                                   containing the hash of one or more migration
                                                   authority public keys and parameters. */
} TCM_CMK_MA_APPROVAL;

/* 20.2 Delegate Definitions rev 101

   The delegations are in a 64-bit field. Each bit describes a capability that the TCM Owner can
   delegate to a trusted process by setting that bit. Each delegation bit setting is independent of
   any other delegation bit setting in a row.

   If a TCM command is not listed in the following table, then the TCM Owner cannot delegate that
   capability to a trusted process. For the TCM commands that are listed in the following table, if
   the bit associated with a TCM command is set to zero in the row of the table that identifies a
   trusted process, then that process has not been delegated to use that TCM command.

   The minimum granularity for delegation is at the ordinal level. It is not possible to delegate an
   option of an ordinal. This implies that if the options present a difficulty and there is a need
   to separate the delegations then there needs to be a split into two separate ordinals.
*/

#define TCM_DEL_OWNER_BITS 0x00000001 
#define TCM_DEL_KEY_BITS   0x00000002 

typedef struct tdTCM_DELEGATIONS { 
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* This SHALL be TCM_TAG_DELEGATIONS */
#endif
    uint32_t delegateType;        /* Owner or key */
    uint32_t per1;                /* The first block of permissions */
    uint32_t per2;                /* The second block of permissions */
} TCM_DELEGATIONS; 

/* 20.4 TCM_FAMILY_LABEL rev 85

   Used in the family table to hold a one-byte numeric value (sequence number) that software can map
   to a string of bytes that can be displayed or used by applications.

   This is not sensitive data. 
*/

#if 0
typedef struct tdTCM_FAMILY_LABEL { 
    BYTE label;         /* A sequence number that software can map to a string of bytes that can be
                           displayed or used by the applications. This MUST not contain sensitive
                           information. */
} TCM_FAMILY_LABEL; 
#endif

typedef BYTE TCM_FAMILY_LABEL;  /* NOTE: No need for a structure here */

/* 20.5 TCM_FAMILY_TABLE_ENTRY rev 101

   The family table entry is an individual row in the family table. There are no sensitive values in
   a family table entry.

   Each family table entry contains values to facilitate table management: the familyID sequence
   number value that associates a family table row with one or more delegate table rows, a
   verification sequence number value that identifies when rows in the delegate table were last
   verified, and BYTE family label value that software can map to an ASCII text description of the
   entity using the family table entry
*/

typedef struct tdTCM_FAMILY_TABLE_ENTRY { 
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;              /* This SHALL be TCM_TAG_FAMILY_TABLE_ENTRY */
#endif
    TCM_FAMILY_LABEL familyLabel;       /* A sequence number that software can map to a string of
                                           bytes that can be displayed of used by the applications.
                                           This MUST not contain sensitive informations. */
    TCM_FAMILY_ID familyID;             /* The family ID in use to tie values together. This is not
                                           a sensitive value. */
    TCM_FAMILY_VERIFICATION verificationCount;  /* The value inserted into delegation rows to
                                                   indicate that they are the current generation of
                                                   rows. Used to identify when a row in the delegate
                                                   table was last verified. This is not a sensitive
                                                   value. */
    TCM_FAMILY_FLAGS flags;             /* See section on TCM_FAMILY_FLAGS. */
    /* NOTE Added */
    TCM_BOOL valid;
} TCM_FAMILY_TABLE_ENTRY;

/* 20.6 TCM_FAMILY_TABLE rev 87

   The family table is stored in a TCM shielded location. There are no confidential values in the
   family table.  The family table contains a minimum of 8 rows.
*/

#ifdef TCM_NUM_FAMILY_TABLE_ENTRY_MIN 
#if (TCM_NUM_FAMILY_TABLE_ENTRY_MIN < 8)
#error "TCM_NUM_FAMILY_TABLE_ENTRY_MIN minimum is 8"
#endif
#endif 

#ifndef TCM_NUM_FAMILY_TABLE_ENTRY_MIN 
#define TCM_NUM_FAMILY_TABLE_ENTRY_MIN 8
#endif

typedef struct tdTCM_FAMILY_TABLE { 
    TCM_FAMILY_TABLE_ENTRY famTableRow[TCM_NUM_FAMILY_TABLE_ENTRY_MIN]; 
} TCM_FAMILY_TABLE;

/* 20.7 TCM_DELEGATE_LABEL rev 87

   Used in both the delegate table and the family table to hold a string of bytes that can be
   displayed or used by applications. This is not sensitive data.
*/

#if 0
typedef struct tdTCM_DELEGATE_LABEL { 
    BYTE label;         /* A byte that can be displayed or used by the applications. This MUST not
                           contain sensitive information.  */
} TCM_DELEGATE_LABEL; 
#endif

typedef BYTE TCM_DELEGATE_LABEL;        /* NOTE: No need for structure */

/* 20.8 TCM_DELEGATE_PUBLIC rev 101

   The information of a delegate row that is public and does not have any sensitive information.

   PCR_INFO_SHORT is appropriate here as the command to create this is done using owner
   authorization, hence the owner authorized the command and the delegation. There is no need to
   validate what configuration was controlling the platform during the blob creation.
*/

typedef struct tdTCM_DELEGATE_PUBLIC { 
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;              /* This SHALL be TCM_TAG_DELEGATE_PUBLIC  */
#endif
    TCM_DELEGATE_LABEL rowLabel;        /* This SHALL be the label for the row. It
                                           MUST not contain any sensitive information. */
    TCM_PCR_INFO_SHORT pcrInfo;         /* This SHALL be the designation of the process that can use
                                           the permission. This is a not sensitive
                                           value. PCR_SELECTION may be NULL.

                                           If selected the pcrInfo MUST be checked on each use of
                                           the delegation. Use of the delegation is where the
                                           delegation is passed as an authorization handle. */
    TCM_DELEGATIONS permissions;        /* This SHALL be the permissions that are allowed to the
                                           indicated process. This is not a sensitive value. */
    TCM_FAMILY_ID familyID;             /* This SHALL be the family ID that identifies which family
                                           the row belongs to. This is not a sensitive value. */
    TCM_FAMILY_VERIFICATION verificationCount;  /* A copy of verificationCount from the associated
                                                   family table. This is not a sensitive value. */
} TCM_DELEGATE_PUBLIC; 


/* 20.9 TCM_DELEGATE_TABLE_ROW rev 101

   A row of the delegate table. 
*/

typedef struct tdTCM_DELEGATE_TABLE_ROW { 
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* This SHALL be TCM_TAG_DELEGATE_TABLE_ROW */
#endif
    TCM_DELEGATE_PUBLIC pub;    /* This SHALL be the public information for a table row. */
    TCM_SECRET authValue;       /* This SHALL be the authorization value that can use the
                                   permissions. This is a sensitive value. */
    /* NOTE Added */
    TCM_BOOL valid;
} TCM_DELEGATE_TABLE_ROW; 

/* 20.10 TCM_DELEGATE_TABLE rev 87

   This is the delegate table. The table contains a minimum of 2 rows.

   This will be an entry in the TCM_PERMANENT_DATA structure.
*/

#ifdef TCM_NUM_DELEGATE_TABLE_ENTRY_MIN 
#if (TCM_NUM_DELEGATE_TABLE_ENTRY_MIN < 2)
#error "TCM_NUM_DELEGATE_TABLE_ENTRY_MIN minimum is 2"
#endif
#endif 

#ifndef TCM_NUM_DELEGATE_TABLE_ENTRY_MIN 
#define TCM_NUM_DELEGATE_TABLE_ENTRY_MIN 2
#endif


typedef struct tdTCM_DELEGATE_TABLE { 
    TCM_DELEGATE_TABLE_ROW delRow[TCM_NUM_DELEGATE_TABLE_ENTRY_MIN]; /* The array of delegations */
} TCM_DELEGATE_TABLE; 

/* 20.11 TCM_DELEGATE_SENSITIVE rev 115

   The TCM_DELEGATE_SENSITIVE structure is the area of a delegate blob that contains sensitive
   information.

   This structure is normative for loading unencrypted blobs before there is an owner.  It is
   informative for TCM_CreateOwnerDelegation and TCM_LoadOwnerDelegation after there is an owner and
   encrypted blobs are used, since the structure is under complete control of the TCM.
*/

typedef struct tdTCM_DELEGATE_SENSITIVE {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* This MUST be TCM_TAG_DELEGATE_SENSITIVE */
#endif
    TCM_SECRET authValue;       /* AuthData value */
} TCM_DELEGATE_SENSITIVE;

/* 20.12 TCM_DELEGATE_OWNER_BLOB rev 87

   This data structure contains all the information necessary to externally store a set of owner
   delegation rights that can subsequently be loaded or used by this TCM.
   
   The encryption mechanism for the sensitive area is a TCM choice. The TCM may use asymmetric
   encryption and the SRK for the key. The TCM may use symmetric encryption and a secret key known
   only to the TCM.
*/

typedef struct tdTCM_DELEGATE_OWNER_BLOB {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* This MUST be TCM_TAG_DELG_OWNER_BLOB */
#endif
    TCM_DELEGATE_PUBLIC pub;    /* The public information for this blob */
    TCM_DIGEST integrityDigest; /* The HMAC to guarantee the integrity of the entire structure */
    TCM_SIZED_BUFFER additionalArea;    /* An area that the TCM can add to the blob which MUST NOT
                                           contain any sensitive information. This would include any
                                           IV material for symmetric encryption */
    TCM_SIZED_BUFFER sensitiveArea;     /* The area that contains the encrypted
                                           TCM_DELEGATE_SENSITIVE */
} TCM_DELEGATE_OWNER_BLOB;

/* 20.13 TCM_DELEGATE_KEY_BLOB rev 87
    
   A structure identical to TCM_DELEGATE_OWNER_BLOB but which stores delegation information for user
   keys.  As compared to TCM_DELEGATE_OWNER_BLOB, it adds a hash of the corresponding public key
   value to the public information.
*/

typedef struct tdTCM_DELEGATE_KEY_BLOB {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;              /* This MUST be TCM_TAG_DELG_KEY_BLOB */
#endif
    TCM_DELEGATE_PUBLIC pub;            /* The public information for this blob */
    TCM_DIGEST integrityDigest;         /* The HMAC to guarantee the integrity of the entire
                                           structure */
    TCM_DIGEST pubKeyDigest;            /* The digest, that uniquely identifies the key for which
                                           this usage delegation applies.  */
    TCM_SIZED_BUFFER additionalArea;    /* An area that the TCM can add to the blob which MUST NOT
                                           contain any sensitive information. This would include any
                                           IV material for symmetric encryption */
    TCM_SIZED_BUFFER sensitiveArea;     /* The area that contains the encrypted
                                           TCM_DELEGATE_SENSITIVE */
} TCM_DELEGATE_KEY_BLOB;

/* 15.1 TCM_CURRENT_TICKS rev 110

   This structure holds the current number of time ticks in the TCM. The value is the number of time
   ticks from the start of the current session. Session start is a variable function that is
   platform dependent. Some platforms may have batteries or other power sources and keep the TCM
   clock session across TCM initialization sessions.
   
   The <tickRate> element of the TCM_CURRENT_TICKS structure provides the number of microseconds per
   tick.  The platform manufacturer must satisfy input clock requirements set by the TCM vendor to
   ensure the accuracy of the tickRate.
   
   No external entity may ever set the current number of time ticks held in TCM_CURRENT_TICKS. This
   value is always reset to 0 when a new clock session starts and increments under control of the
   TCM.
   
   Maintaining the relationship between the number of ticks counted by the TCM and some real world
   clock is a task for external software.
*/

/* This is not a true UINT64, but a special structure to hold currentTicks */

typedef struct tdTCM_UINT64 {
    uint32_t sec;
    uint32_t usec;
} TCM_UINT64;

typedef struct tdTCM_CURRENT_TICKS {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* TCM_TAG_CURRENT_TICKS */
#endif
    TCM_UINT64 currentTicks;    /* The number of ticks since the start of this tick session */
    /* upper is seconds, lower is useconds */
    uint16_t tickRate;		/* The number of microseconds per tick. The maximum resolution of
                                   the TCM tick counter is thus 1 microsecond. The minimum
                                   resolution SHOULD be 1 millisecond. */
    TCM_NONCE tickNonce;        /* TCM_NONCE tickNonce The nonce created by the TCM when resetting
                                   the currentTicks to 0.  This indicates the beginning of a time
                                   session.  This value MUST be valid before the first use of
                                   TCM_CURRENT_TICKS. The value can be set at TCM_Startup or just
                                   prior to first use. */
    /* NOTE Added */
    TCM_UINT64 initialTime;     /* Time from TCM_GetTimeOfDay() */
} TCM_CURRENT_TICKS;

/*
  13. Transport Structures
*/

/* 13.1 TCM _TRANSPORT_PUBLIC rev 87

   The public information relative to a transport session
*/

typedef struct tdTCM_TRANSPORT_PUBLIC {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG   tag;                    /* TCM_TAG_TRANSPORT_PUBLIC */
#endif
    TCM_TRANSPORT_ATTRIBUTES transAttributes;   /* The attributes of this session */
    TCM_ALGORITHM_ID algId;                     /* This SHALL be the algorithm identifier of the
                                                   symmetric key. */
    TCM_ENC_SCHEME encScheme;                   /* This SHALL fully identify the manner in which the
                                                   key will be used for encryption operations. */
} TCM_TRANSPORT_PUBLIC;

/* 13.2 TCM_TRANSPORT_INTERNAL rev 88

   The internal information regarding transport session
*/

/* 7.6 TCM_STANY_DATA */

#ifdef TCM_MIN_TRANS_SESSIONS
#if (TCM_MIN_TRANS_SESSIONS < 3)
#error "TCM_MIN_TRANS_SESSIONS minimum is 3"
#endif
#endif 

#ifndef TCM_MIN_TRANS_SESSIONS
#define TCM_MIN_TRANS_SESSIONS 3
#endif

typedef struct tdTCM_TRANSPORT_INTERNAL {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;              /* TCM_TAG_TRANSPORT_INTERNAL */
#endif
    TCM_AUTHDATA authData;              /* The shared secret for this session */
    TCM_TRANSPORT_PUBLIC transPublic;   /* The public information of this session */
    TCM_TRANSHANDLE transHandle;        /* The handle for this session */
    TCM_NONCE transNonceEven;           /* The even nonce for the rolling protocol */
    TCM_DIGEST transDigest;             /* The log of transport events */
    /* added kgold */
    TCM_BOOL valid;                     /* entry is valid */
} TCM_TRANSPORT_INTERNAL;

/* 13.3 TCM_TRANSPORT_LOG_IN rev 87

   The logging of transport commands occurs in two steps, before execution with the input 
   parameters and after execution with the output parameters.
   
   This structure is in use for input log calculations.
*/

typedef struct tdTCM_TRANSPORT_LOG_IN {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG   tag;    /* TCM_TAG_TRANSPORT_LOG_IN */
#endif
    TCM_DIGEST parameters;      /* The actual parameters contained in the digest are subject to the
                                   rules of the command using this structure. To find the exact
                                   calculation refer to the actions in the command using this
                                   structure. */
    TCM_DIGEST pubKeyHash;      /* The hash of any keys in the transport command */
} TCM_TRANSPORT_LOG_IN;

/* 13.4 TCM_TRANSPORT_LOG_OUT rev 88

   The logging of transport commands occurs in two steps, before execution with the input parameters
   and after execution with the output parameters.
   
   This structure is in use for output log calculations. 
   
   This structure is in use for the INPUT logging during releaseTransport.
*/

typedef struct tdTCM_TRANSPORT_LOG_OUT {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;              /* TCM_TAG_TRANSPORT_LOG_OUT */
#endif
    TCM_CURRENT_TICKS currentTicks;     /* The current tick count. This SHALL be the value of the
                                           current TCM tick counter.  */
    TCM_DIGEST parameters;              /* The actual parameters contained in the digest are subject
                                           to the rules of the command using this structure. To find
                                           the exact calculation refer to the actions in the command
                                           using this structure. */
    TCM_MODIFIER_INDICATOR locality;    /* The locality that called TCM_ExecuteTransport */
} TCM_TRANSPORT_LOG_OUT;

/* 13.5 TCM_TRANSPORT_AUTH structure rev 87

   This structure provides the validation for the encrypted AuthData value.
*/

typedef struct tdTCM_TRANSPORT_AUTH {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG   tag;    /* TCM_TAG_TRANSPORT_AUTH */
#endif
    TCM_AUTHDATA authData;      /* The AuthData value */
} TCM_TRANSPORT_AUTH;

/* 22.3 TCM_DAA_ISSUER rev 91

   This structure is the abstract representation of non-secret settings controlling a DAA
   context. The structure is required when loading public DAA data into a TCM.  TCM_DAA_ISSUER
   parameters are normally held outside the TCM as plain text data, and loaded into a TCM when a DAA
   session is required. A TCM_DAA_ISSUER structure contains no integrity check: the TCM_DAA_ISSUER
   structure at time of JOIN is indirectly verified by the issuer during the JOIN process, and a
   digest of the verified TCM_DAA_ISSUER structure is held inside the TCM_DAA_TCM structure created
   by the JOIN process.  Parameters DAA_digest_X are digests of public DAA_generic_X parameters, and
   used to verify that the correct value of DAA_generic_X has been loaded. DAA_generic_q is stored
   in its native form to reduce command complexity.
*/

typedef struct tdTCM_DAA_ISSUER {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG   tag;    /* MUST be TCM_TAG_DAA_ISSUER */
#endif
    TCM_DIGEST  DAA_digest_R0;  /* A digest of the parameter "R0", which is not secret and may be
                                   common to many TCMs.  */
    TCM_DIGEST  DAA_digest_R1;  /* A digest of the parameter "R1", which is not secret and may be
                                   common to many TCMs.  */
    TCM_DIGEST  DAA_digest_S0;  /* A digest of the parameter "S0", which is not secret and may be
                                   common to many TCMs.  */
    TCM_DIGEST  DAA_digest_S1;  /* A digest of the parameter "S1", which is not secret and may be
                                   common to many TCMs. */
    TCM_DIGEST  DAA_digest_n;   /* A digest of the parameter "n", which is not secret and may be
                                   common to many TCMs.  */
    TCM_DIGEST  DAA_digest_gamma;       /* A digest of the parameter "gamma", which is not secret
                                           and may be common to many TCMs.  */
    BYTE        DAA_generic_q[26];      /* The parameter q, which is not secret and may be common to
                                           many TCMs. Note that q is slightly larger than a digest,
                                           but is stored in its native form to simplify the
                                           TCM_DAA_join command. Otherwise, JOIN requires 3 input
                                           parameters. */
} TCM_DAA_ISSUER;

/* 22.4 TCM_DAA_TCM rev 91

   This structure is the abstract representation of TCM specific parameters used during a DAA 
   context. TCM-specific DAA parameters may be stored outside the TCM, and hence this 
   structure is needed to save private DAA data from a TCM, or load private DAA data into a 
   TCM.
   
   If a TCM_DAA_TCM structure is stored outside the TCM, it is stored in a confidential format that
   can be interpreted only by the TCM created it. This is to ensure that secret parameters are
   rendered confidential, and that both secret and non-secret data in TCM_DAA_TCM form a
   self-consistent set.
  
   TCM_DAA_TCM includes a digest of the public DAA parameters that were used during creation of the
   TCM_DAA_TCM structure. This is needed to verify that a TCM_DAA_TCM is being used with the public
   DAA parameters used to create the TCM_DAA_TCM structure.  Parameters DAA_digest_v0 and
   DAA_digest_v1 are digests of public DAA_private_v0 and DAA_private_v1 parameters, and used to
   verify that the correct private parameters have been loaded.
   
   Parameter DAA_count is stored in its native form, because it is smaller than a digest, and is
   required to enforce consistency.
*/

typedef struct tdTCM_DAA_TCM {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* MUST be TCM_TAG_DAA_TCM */
#endif
    TCM_DIGEST  DAA_digestIssuer;       /* A digest of a TCM_DAA_ISSUER structure that contains the
                                           parameters used to generate this TCM_DAA_TCM
                                           structure. */
    TCM_DIGEST  DAA_digest_v0;  /* A digest of the parameter "v0", which is secret and specific to
                                   this TCM. "v0" is generated during a JOIN phase.  */
    TCM_DIGEST  DAA_digest_v1;  /* A digest of the parameter "v1", which is secret and specific to
                                   this TCM. "v1" is generated during a JOIN phase.  */
    TCM_DIGEST  DAA_rekey;      /* A digest related to the rekeying process, which is not secret but
                                   is specific to this TCM, and must be consistent across JOIN/SIGN
                                   sessions. "rekey" is generated during a JOIN phase. */
    uint32_t      DAA_count;	/* The parameter "count", which is not secret but must be consistent
                                   across JOIN/SIGN sessions. "count" is an input to the TCM from
                                   the host system. */
} TCM_DAA_TCM;

/* 22.5 TCM_DAA_CONTEXT rev 91

   TCM_DAA_CONTEXT structure is created and used inside a TCM, and never leaves the TCM.  This
   entire section is informative as the TCM does not expose this structure.  TCM_DAA_CONTEXT
   includes a digest of the public and private DAA parameters that were used during creation of the
   TCM_DAA_CONTEXT structure. This is needed to verify that a TCM_DAA_CONTEXT is being used with the
   public and private DAA parameters used to create the TCM_DAA_CONTEXT structure.
*/

typedef struct tdTCM_DAA_CONTEXT {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG   tag;    /* MUST be TCM_TAG_DAA_CONTEXT */
#endif
    TCM_DIGEST  DAA_digestContext;      /* A digest of parameters used to generate this
                                           structure. The parameters vary, depending on whether the
                                           session is a JOIN session or a SIGN session. */
    TCM_DIGEST  DAA_digest;     /* A running digest of certain parameters generated during DAA
                                   computation; operationally the same as a PCR (which holds a
                                   running digest of integrity metrics). */
    TCM_DAA_CONTEXT_SEED        DAA_contextSeed;        /* The seed used to generate other DAA
                                                           session parameters */
    BYTE        DAA_scratch[256];       /* Memory used to hold different parameters at different
                                           times of DAA computation, but only one parameter at a
                                           time.  The maximum size of this field is 256 bytes */
    BYTE        DAA_stage;      /* A counter, indicating the stage of DAA computation that was most
                                   recently completed. The value of the counter is zero if the TCM
                                   currently contains no DAA context.

                                   When set to zero (0) the TCM MUST clear all other fields in this
                                   structure.

                                   The TCM MUST set DAA_stage to 0 on TCM_Startup(ANY) */
    TCM_BOOL    DAA_scratch_null;       
} TCM_DAA_CONTEXT;

/* 22.6 TCM_DAA_JOINDATA rev 91

   This structure is the abstract representation of data that exists only during a specific JOIN
   session.
*/

typedef struct tdTCM_DAA_JOINDATA {
    BYTE        DAA_join_u0[128];       /* A TCM-specific secret "u0", used during the JOIN phase,
                                           and discarded afterwards.  */
    BYTE        DAA_join_u1[138];       /* A TCM-specific secret "u1", used during the JOIN phase,
                                           and discarded afterwards.  */
    TCM_DIGEST  DAA_digest_n0;  /* A digest of the parameter "n0", which is an RSA public key with
                                   exponent 2^16 +1 */
} TCM_DAA_JOINDATA;

/* DAA Session structure

*/

#ifdef TCM_MIN_DAA_SESSIONS 
#if (TCM_MIN_DAA_SESSIONS < 1)
#error "TCM_MIN_DAA_SESSIONS minimum is 1"
#endif
#endif 

#ifndef TCM_MIN_DAA_SESSIONS 
#define TCM_MIN_DAA_SESSIONS 1
#endif

typedef struct tdTCM_DAA_SESSION_DATA {
    TCM_DAA_ISSUER      DAA_issuerSettings;     /* A set of DAA issuer parameters controlling a DAA
                                                   session. (non-secret) */
    TCM_DAA_TCM         DAA_tcmSpecific;        /* A set of DAA parameters associated with a
                                                   specific TCM. (secret) */
    TCM_DAA_CONTEXT     DAA_session;            /* A set of DAA parameters associated with a DAA
                                                   session. (secret) */
    TCM_DAA_JOINDATA    DAA_joinSession;        /* A set of DAA parameters used only during the JOIN
                                                   phase of a DAA session, and generated by the
                                                   TCM. (secret) */
    /* added kgold */
    TCM_HANDLE          daaHandle;              /* DAA session handle */
    TCM_BOOL            valid;                  /* array entry is valid */
    /* FIXME should have handle type Join or Sign */
} TCM_DAA_SESSION_DATA;

/* 22.8 TCM_DAA_BLOB rev 98

   The structure passed during the join process
*/

typedef struct tdTCM_DAA_BLOB {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;              /* MUST be TCM_TAG_DAA_BLOB */
#endif
    TCM_RESOURCE_TYPE resourceType;     /* The resource type: enc(DAA_tcmSpecific) or enc(v0) or
                                           enc(v1) */
    BYTE label[16];                     /* Label for identification of the blob. Free format
                                           area. */
    TCM_DIGEST blobIntegrity;           /* The integrity of the entire blob including the sensitive
                                           area. This is a HMAC calculation with the entire
                                           structure (including sensitiveData) being the hash and
                                           daaProof is the secret */
    TCM_SIZED_BUFFER additionalData;    /* Additional information set by the TCM that helps define
                                           and reload the context. The information held in this area
                                           MUST NOT expose any information held in shielded
                                           locations. This should include any IV for symmetric
                                           encryption */
    TCM_SIZED_BUFFER sensitiveData;     /* A TCM_DAA_SENSITIVE structure */
#if 0
    uint32_t additionalSize;              
    [size_is(additionalSize)] BYTE* additionalData;
    uint32_t sensitiveSize;
    [size_is(sensitiveSize)] BYTE* sensitiveData;
#endif
} TCM_DAA_BLOB;

/* 22.9 TCM_DAA_SENSITIVE rev 91
   
   The encrypted area for the DAA parameters
*/

typedef struct tdTCM_DAA_SENSITIVE {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;              /* MUST be TCM_TAG_DAA_SENSITIVE */
#endif
    TCM_SIZED_BUFFER internalData;      /* DAA_tcmSpecific or DAA_private_v0 or DAA_private_v1 */
#if 0
    uint32_t internalSize;
    [size_is(internalSize)] BYTE* internalData;
#endif
} TCM_DAA_SENSITIVE;

/* 7.1 TCM_PERMANENT_FLAGS rev 110

   These flags maintain state information for the TCM. The values are not affected by any
   TCM_Startup command.

   The flag history includes:

   Rev 62 specLevel 1 errataRev 0:  15 BOOLs
   Rev 85 specLevel 2 errataRev 0:  19 BOOLs
        Added: nvLocked, readSRKPub, tcmEstablished, maintenanceDone
   Rev 94 specLevel 2 errataRev 1:  19 BOOLs
   Rev 103 specLevel 2 errataRev 2:  20 BOOLs
        Added: disableFullDALogicInfo
*/

typedef struct tdTCM_PERMANENT_FLAGS { 
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* TCM_TAG_PERMANENT_FLAGS */
#endif
    TCM_BOOL disable;           /* disable The state of the disable flag. The default state is TRUE
                                   */
    TCM_BOOL ownership;         /* The ability to install an owner. The default state is TRUE. */
    TCM_BOOL deactivated;       /* The state of the inactive flag. The default state is TRUE. */
    TCM_BOOL readPubek;         /* The ability to read the PUBEK without owner authorization. The
                                   default state is TRUE.

                                   set TRUE on owner clear
                                   set FALSE on take owner, disablePubekRead
                                */
    TCM_BOOL disableOwnerClear; /* Whether the owner authorized clear commands are active. The
                                   default state is FALSE. */
    TCM_BOOL allowMaintenance;  /* Whether the TCM Owner may create a maintenance archive. The
                                   default state is TRUE. */
    TCM_BOOL physicalPresenceLifetimeLock; /* This bit can only be set to TRUE; it cannot be set to
                                           FALSE except during the manufacturing process.

                                           FALSE: The state of either physicalPresenceHWEnable or
                                           physicalPresenceCMDEnable MAY be changed. (DEFAULT)

                                           TRUE: The state of either physicalPresenceHWEnable or
                                           physicalPresenceCMDEnable MUST NOT be changed for the
                                           life of the TCM. */
    TCM_BOOL physicalPresenceHWEnable;  /* FALSE: Disable the hardware signal indicating physical
                                           presence. (DEFAULT)

                                           TRUE: Enables the hardware signal indicating physical
                                           presence. */
    TCM_BOOL physicalPresenceCMDEnable;         /* FALSE: Disable the command indicating physical
                                           presence. (DEFAULT)

                                           TRUE: Enables the command indicating physical
                                           presence. */
    TCM_BOOL CEKPUsed;          /* TRUE: The PRIVEK and PUBEK were created using
                                   TCM_CreateEndorsementKeyPair.

                                   FALSE: The PRIVEK and PUBEK were created using a manufacturer's
                                   process.  NOTE: This flag has no default value as the key pair
                                   MUST be created by one or the other mechanism. */
    TCM_BOOL TCMpost;           /* TRUE: After TCM_Startup, if there is a call to
                                   TCM_ContinueSelfTest the TCM MUST execute the actions of
                                   TCM_SelfTestFull

                                   FALSE: After TCM_Startup, if there is a call to
                                   TCM_ContinueSelfTest the TCM MUST execute TCM_ContinueSelfTest

                                   If the TCM supports the implicit invocation of
                                   TCM_ContinueSelftTest upon the use of an untested resource, the
                                   TCM MUST use the TCMPost flag to call either TCM_ContinueSelfTest
                                   or TCM_SelfTestFull

                                   The TCM manufacturer sets this bit during TCM manufacturing and
                                   the bit is unchangeable after shipping the TCM

                                   The default state is FALSE */
    TCM_BOOL TCMpostLock;       /* With the clarification of TCMPost TCMpostLock is now 
                                   unnecessary. 
                                   This flag is now deprecated */
//    TCM_BOOL FIPS;              // TRUE: This TCM operates in FIPS mode 
                                  // FALSE: This TCM does NOT operate in FIPS mode 
    TCM_BOOL tcmOperator;       /* TRUE: The operator authorization value is valid 
                                   FALSE: the operator authorization value is not set */
    TCM_BOOL enableRevokeEK;    /* TRUE: The TCM_RevokeTrust command is active 
                                   FALSE: the TCM RevokeTrust command is disabled */
    TCM_BOOL nvLocked;          /* TRUE: All NV area authorization checks are active
                                   FALSE: No NV area checks are performed, except for maxNVWrites.
                                   FALSE is the default value */
//  TCM_BOOL readSRKPub;        // TRUE: GetPubKey will return the SRK pub key
                                // FALSE: GetPubKey will not return the SRK pub key
                                // Default SHOULD be FALSE 
    TCM_BOOL tcmEstablished;    /* TRUE: TCM_HASH_START has been executed at some time
                                   FALSE: TCM_HASH_START has not been executed at any time
                                   Default is FALSE - resets using TCM_ResetEstablishmentBit */
//   TCM_BOOL maintenanceDone;   // TRUE: A maintenance archive has been created for the current
                                 //  SRK 
} __attribute__((packed)) TCM_PERMANENT_FLAGS; 

/* 7.2 TCM_STCLEAR_FLAGS rev 109

   These flags maintain state that is reset on each TCM_Startup(ST_Clear) command. The values are
   not affected by TCM_Startup(ST_State) commands.
*/

typedef struct tdTCM_STCLEAR_FLAGS { 
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;              /* TCM_TAG_STCLEAR_FLAGS */
#endif
    TCM_BOOL deactivated;               /* Prevents the operation of most capabilities. There is no
                                           default state. It is initialized by TCM_Startup to the
                                           same value as TCM_PERMANENT_FLAGS ->
                                           deactivated. TCM_SetTempDeactivated sets it to TRUE. */
    TCM_BOOL disableForceClear;         /* Prevents the operation of TCM_ForceClear when TRUE. The
                                           default state is FALSE.  TCM_DisableForceClear sets it to
                                           TRUE. */
    TCM_BOOL physicalPresence;          /* Command assertion of physical presence. The default state
                                           is FALSE.  This flag is affected by the
                                           TSC_PhysicalPresence command but not by the hardware
                                           signal.  */
    TCM_BOOL physicalPresenceLock;      /* Indicates whether changes to the TCM_STCLEAR_FLAGS ->
                                           physicalPresence flag are permitted.
                                           TCM_Startup(ST_CLEAR) sets PhysicalPresenceLock to its
                                           default state of FALSE (allow changes to the
                                           physicalPresence flag). When TRUE, the physicalPresence
                                           flag is FALSE. TSC_PhysicalPresence can change the state
                                           of physicalPresenceLock.  */
    TCM_BOOL bGlobalLock;               /* Set to FALSE on each TCM_Startup(ST_CLEAR). Set to TRUE
                                           when a write to NV_Index =0 is successful */
    /* NOTE: Cannot add vendor specific flags here, since TCM_GetCapability() returns the serialized
       structure */
}__attribute__((packed))  TCM_STCLEAR_FLAGS; 


/* 7.3 TCM_STANY_FLAGS rev 87

   These flags reset on any TCM_Startup command. 
*/

typedef struct tdTCM_STANY_FLAGS {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* TCM_TAG_STANY_FLAGS   */
#endif
    TCM_BOOL postInitialise;    /* Prevents the operation of most capabilities. There is no default
                                   state. It is initialized by TCM_Init to TRUE. TCM_Startup sets it
                                   to FALSE.  */
    TCM_MODIFIER_INDICATOR localityModifier; /*This SHALL indicate for each command the presence of
                                               a locality modifier for the command. It MUST be set
                                               to NULL after the TCM executes each command.  */
#if 0
    TCM_BOOL transportExclusive; /* Defaults to FALSE. TRUE when there is an exclusive transport
                                    session active. Execution of ANY command other than
                                    TCM_ExecuteTransport or TCM_ReleaseTransportSigned MUST
                                    invalidate the exclusive transport session. */    
#endif
    TCM_TRANSHANDLE transportExclusive; /* Defaults to 0x00000000, Set to the handle when an
                                           exclusive transport session is active */
    TCM_BOOL TOSPresent;        /* Defaults to FALSE
                                   Set to TRUE on TCM_HASH_START
                                   set to FALSE using setCapability */
    /* NOTE: Added kgold */
//   TCM_BOOL stateSaved;        // Defaults to FALSE
                                 //  Set to TRUE on TCM_SaveState
                                 //  Set to FALSE on any other ordinal

                                 //  This is an optimization flag, so the file need not be deleted if
                                 //  it does not exist.
}__attribute__((packed))  TCM_STANY_FLAGS;

/* 7.4 TCM_PERMANENT_DATA rev 105

   This structure contains the data fields that are permanently held in the TCM and not affected by
   TCM_Startup(any).

   Many of these fields contain highly confidential and privacy sensitive material. The TCM must
   maintain the protections around these fields.
*/

#ifdef TCM_MIN_COUNTERS
#if (TCM_MIN_COUNTERS < 4)
#error "TCM_MIN_COUNTERS minumum is 4"
#endif
#endif

#ifndef TCM_MIN_COUNTERS
#define TCM_MIN_COUNTERS 4 /* the minimum number of counters is 4 */
#endif

#define TCM_DELEGATE_KEY TCM_KEY 
#define TCM_MAX_NV_WRITE_NOOWNER 64 

/* Although the ordinal is 32 bits, only the lower 8 bits seem to be used.  So for now, define an
   array of 256/8 bytes for ordinalAuditStatus - kgold */

#define TCM_ORDINALS_MAX        256     /* assumes a multiple of CHAR_BIT */
#define TCM_AUTHDIR_SIZE        1       /* Number of DIR registers */




typedef struct tdTCM_PERMANENT_DATA {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* TCM_TAG_PERMANENT_DATA */
#endif
    BYTE revMajor;              /* This is the TCM major revision indicator. This SHALL be set by
                                   the TCME, only. The default value is manufacturer-specific. */
    BYTE revMinor;              /* This is the TCM minor revision indicator. This SHALL be set by
                                   the TCME, only. The default value is manufacturer-specific. */
    TCM_SECRET tcmProof;        /* This is a random number that each TCM maintains to validate blobs
                                   in the SEAL and other processes. The default value is
                                   manufacturer-specific. */
    TCM_NONCE EKReset;          /* Nonce held by TCM to validate TCM_RevokeTrust. This value is set
                                   as the next 20 bytes from the TCM RNG when the EK is set
                                   (was fipsReset - kgold) */
    TCM_SECRET ownerAuth;       /* This is the TCM-Owner's authorization data. The default value is
                                   manufacturer-specific. */
    TCM_SECRET operatorAuth;    /* The value that allows the execution of the SetTempDeactivated
                                   command */
//    TCM_DIRVALUE authDIR;       /* The array of TCM Owner authorized DIR. Points to the same
//                                   location as the NV index value. (kgold - was array of 1) */
//#ifndef TCM_NOMAINTENANCE
//    TCM_PUBKEY manuMaintPub;    /* This is the manufacturer's public key to use in the maintenance
//                                   operations. The default value is manufacturer-specific. */
//#endif
    TCM_KEY endorsementKey;     // This is the TCM's endorsement key pair. 
    TCM_KEY smk;                // This is the TCM's StorageRootKey. 
    TCM_KEY contextKey;                // This is the TCM's Runtime protect key. 
/*
    TCM_SYMMETRIC_KEY_TOKEN contextKey;  // This is the key in use to perform context saves. The key
					 //   may be symmetric or asymmetric. The key size is
					//    predicated by the algorithm in use. 
    TCM_SYMMETRIC_KEY_TOKEN delegateKey;	// This key encrypts delegate rows that are stored
						//   outside the TCM. 
    TCM_COUNTER_VALUE auditMonotonicCounter;    // This SHALL be the audit monotonic counter for the
                                                //   TCM. This value starts at 0 and increments
*/                                                //   according to the rules of auditing 
    TCM_COUNTER_VALUE auditMonitinicCounter;       // This SHALL be the monotonic
    TCM_COUNTER_VALUE monotonicCounter[TCM_MIN_COUNTERS];       // This SHALL be the monotonic
                                                                //   counters for the TCM. The
                                                                //   individual counters start and
                                                                //   increment according to the rules
                                                                //   of monotonic counters. 

    TCM_PCR_ATTRIBUTES pcrAttrib[TCM_NUM_PCR];  /* The attributes for all of the PCR registers
                                                   supported by the TCM. */
    BYTE ordinalAuditStatus[TCM_ORDINALS_MAX/CHAR_BIT]; // Table indicating which ordinals are being
    BYTE* rngState;                     /* State information describing the random number
                                           generator. */
    UINT32   maxNVBufSize;
    uint32_t noOwnerNVWrite;    //  The count of NV writes that have occurred when there is no TCM
    
} __attribute__((packed)) TCM_PERMANENT_DATA; 

/* 7.6 TCM_STANY_DATA */

#ifdef TCM_MIN_AUTH_SESSIONS
#if (TCM_MIN_AUTH_SESSIONS < 3)
#error "TCM_MIN_AUTH_SESSIONS minimum is 3"
#endif
#endif

#ifndef TCM_MIN_AUTH_SESSIONS 
#define TCM_MIN_AUTH_SESSIONS 3
#endif

/* NOTE: Vendor specific */

typedef struct tdTCM_SESSION_DATA {
    /* vendor specific */
    TCM_AUTHHANDLE SERIAL;
    TCM_AUTHHANDLE handle;      /* Handle for a session */
    TCM_PROTOCOL_ID protocolID; /* TCM_PID_OIAP, TCM_PID_OSAP, TCM_PID_DSAP */
    TCM_ENT_TYPE entityTypeByte;        /* The type of entity in use (TCM_ET_SRK, TCM_ET_OWNER,
                                           TCM_ET_KEYHANDLE ... */
    TCM_ADIP_ENC_SCHEME adipEncScheme;  /* ADIP encryption scheme */
    TCM_NONCE nonceEven;        /* OIAP, OSAP, DSAP */
    TCM_SECRET sharedSecret;    /* OSAP */
    TCM_DIGEST entityDigest;    /* OSAP tracks which entity established the OSAP session */
    TCM_BOOL valid;             /* added kgold: array entry is valid */
}__attribute__((packed)) TCM_SESSION_DATA ;


/* 3.   contextList MUST support a minimum of 16 entries, it MAY support more. */

#ifdef TCM_MIN_SESSION_LIST 
#if (TCM_MIN_SESSION_LIST < 16)
#error "TCM_MIN_SESSION_LIST minimum is 16"
#endif
#endif 

#ifndef TCM_MIN_SESSION_LIST 
#define TCM_MIN_SESSION_LIST 16
#endif

/* 7.5 TCM_STCLEAR_DATA rev 101

   This is an informative structure and not normative. It is purely for convenience of writing the
   spec.

   Most of the data in this structure resets on TCM_Startup(ST_Clear). A TCM may implement rules
   that provide longer-term persistence for the data. The TCM reflects how it handles the data in
   various TCM_GetCapability fields including startup effects.
*/

typedef struct tdTCM_STCLEAR_DATA {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* TCM_TAG_STCLEAR_DATA */
#endif
    TCM_NONCE contextNonceKey;  /* This is the nonce in use to properly identify saved key context
                                   blobs This SHALL be set to all zeros on each TCM_Startup
                                   (ST_Clear).
                                */

    TCM_COUNT_ID countID;       // This is the handle for the current monotonic counter.  This SHALL
                                //   be set to zero on each TCM_Startup(ST_Clear). 
    uint32_t ownerReference;	// Points to where to obtain the owner secret in OIAP and OSAP
                                //   commands. This allows a TSS to manage 1.1 applications on a 1.2
                                //   TCM where delegation is in operation. 

    TCM_BOOL disableResetLock;  /* Disables TCM_ResetLockValue upon authorization failure.
                                   The value remains TRUE for the timeout period.

                                   Default is FALSE.

                                   The value is in the STCLEAR_DATA structure as the
                                   implementation of this flag is TCM vendor specific. */
    TCM_PCRVALUE PCRS[TCM_NUM_PCR];     /* Platform configuration registers */
    /* NOTE Storage for the ordinal response */
}__attribute__((packed)) TCM_STCLEAR_DATA ; 


/* 7.6 TCM_STANY_DATA rev 87

   This is an informative structure and not normative. It is purely for convenience of writing the
   spec.
    
   Most of the data in this structure resets on TCM_Startup(ST_State). A TCM may implement rules
   that provide longer-term persistence for the data. The TCM reflects how it handles the data in
   various getcapability fields including startup effects.
*/

typedef struct tdTCM_STANY_DATA {
    TCM_STRUCTURE_TAG tag;              // TCM_TAG_STANY_DATA 
    TCM_NONCE contextNonceSession;      // This is the nonce in use to properly identify saved
                                        // session context blobs.  This MUST be set to all zeros on
                                        // each TCM_Startup (ST_Clear).  The nonce MAY be set to
                                        // null on TCM_Startup( any). */
    TCM_DIGEST auditDigest;             // This is the extended value that is the audit log. This
                                        // SHALL be set to all zeros at the start of each audit
                                        // session. 
    TCM_CURRENT_TICKS currentTicks;     //   This is the current tick counter.  This is reset to 0
                                        //   according to the rules when the TCM can tick. See the
                                        //   section on the tick counter for details. 
    uint32_t contextCount;		// This is the counter to avoid session context blob replay
                                        // attacks.  This MUST be set to 0 on each TCM_Startup
                                        // (ST_Clear).  The value MAY be set to 0 on TCM_Startup
                                        // (any). 
    uint32_t contextList[TCM_MIN_SESSION_LIST];	// This is the list of outstanding session blobs.
                                                //  All elements of this array MUST be set to 0 on
                                                //  each TCM_Startup (ST_Clear).  The values MAY be
                                                //  set to 0 on TCM_Startup (any). */
    TCM_SESSION_DATA sessions[TCM_MIN_AUTH_SESSIONS];  // List of current sessions.
} __attribute__((packed)) TCM_STANY_DATA;

/* 11. Signed Structures  */

/* 11.1 TCM_CERTIFY_INFO rev 101

   When the TCM certifies a key, it must provide a signature with a TCM identity key on information
   that describes that key. This structure provides the mechanism to do so.

   Key usage and keyFlags must have their upper byte set to zero to avoid collisions with the other
   signature headers.
*/

typedef struct tdTCM_CERTIFY_INFO { 
    TCM_STRUCT_VER version;             /* This MUST be 1.1.0.0  */
    TCM_KEY_USAGE keyUsage;             /* This SHALL be the same value that would be set in a
                                           TCM_KEY representation of the key to be certified. The
                                           upper byte MUST be zero */
    TCM_KEY_FLAGS keyFlags;             /* This SHALL be set to the same value as the corresponding
                                           parameter in the TCM_KEY structure that describes the
                                           public key that is being certified. The upper byte MUST
                                           be zero */
    TCM_AUTH_DATA_USAGE authDataUsage;  /* This SHALL be the same value that would be set in a
                                           TCM_KEY representation of the key to be certified */
    TCM_KEY_PARMS algorithmParms;       /* This SHALL be the same value that would be set in a
                                           TCM_KEY representation of the key to be certified */
    TCM_DIGEST pubkeyDigest;            /* This SHALL be a digest of the value TCM_KEY -> pubKey ->
                                           key in a TCM_KEY representation of the key to be
                                           certified */
    TCM_NONCE data;                     /* This SHALL be externally provided data.  */
    TCM_BOOL parentPCRStatus;           /* This SHALL indicate if any parent key was wrapped to a
                                           PCR */
    TCM_SIZED_BUFFER pcrInfo;           /*  */
#if 0
    uint32_t PCRInfoSize;		/* This SHALL be the size of the pcrInfo parameter. A value
                                           of zero indicates that the key is not wrapped to a PCR */
    BYTE* PCRInfo;                      /* This SHALL be the TCM_PCR_INFO structure.  */
#endif
    /* NOTE: kgold - Added this structure, a cache of PCRInfo when not NULL */
    //TCM_PCR_INFO *tcm_pcr_info;
}__attribute__((packed)) TCM_CERTIFY_INFO;

/* 11.2 TCM_CERTIFY_INFO2 rev 101

   When the TCM certifies a key, it must provide a signature with a TCM identity key on information
   that describes that key. This structure provides the mechanism to do so.

   Key usage and keyFlags must have their upper byte set to zero to avoid collisions with the other
   signature headers.
*/

typedef struct tdTCM_CERTIFY_INFO2 { 
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;              /* MUST be TCM_TAG_CERTIFY_INFO2  */
#endif
    BYTE fill;                          /* MUST be 0x00  */
    TCM_PAYLOAD_TYPE payloadType;       /* This SHALL be the same value that would be set in a
                                           TCM_KEY representation of the key to be certified */
    TCM_KEY_USAGE keyUsage;             /* This SHALL be the same value that would be set in a
                                           TCM_KEY representation of the key to be certified. The
                                           upper byte MUST be zero */
    TCM_KEY_FLAGS keyFlags;             /* This SHALL be set to the same value as the corresponding
                                           parameter in the TCM_KEY structure that describes the
                                           public key that is being certified. The upper byte MUST
                                           be zero.  */
    TCM_AUTH_DATA_USAGE authDataUsage;  /* This SHALL be the same value that would be set in a
                                           TCM_KEY representation of the key to be certified */
    TCM_KEY_PARMS algorithmParms;       /* This SHALL be the same value that would be set in a
                                           TCM_KEY representation of the key to be certified */
    TCM_DIGEST pubkeyDigest;            /* This SHALL be a digest of the value TCM_KEY -> pubKey ->
                                           key in a TCM_KEY representation of the key to be
                                           certified */
    TCM_NONCE data;                     /* This SHALL be externally provided data.  */
    TCM_BOOL parentPCRStatus;           /* This SHALL indicate if any parent key was wrapped to a
                                           PCR */
#if 0
    uint32_t PCRInfoSize;		/* This SHALL be the size of the pcrInfo parameter. A value
                                           of zero indicates that the key is not wrapped to a PCR */
    BYTE* PCRInfo;                      /* This SHALL be the TCM_PCR_INFO_SHORT structure.  */
#endif
    TCM_SIZED_BUFFER pcrInfo;
#if 0
    uint32_t migrationAuthoritySize;	/* This SHALL be the size of migrationAuthority */
    BYTE *migrationAuthority;           /* If the key to be certified has [payload ==
                                           TCM_PT_MIGRATE_RESTRICTED or payload
                                           ==TCM_PT_MIGRATE_EXTERNAL], migrationAuthority is the
                                           digest of the TCM_MSA_COMPOSITE and has TYPE ==
                                           TCM_DIGEST. Otherwise it is NULL. */
#endif
    TCM_SIZED_BUFFER migrationAuthority;
    /* NOTE: kgold - Added this structure, a cache of PCRInfo when not NULL */
    TCM_PCR_INFO_SHORT *tcm_pcr_info_short;
}__attribute__((packed)) TCM_CERTIFY_INFO2;

/* 11.3 TCM_QUOTE_INFO rev 87

   This structure provides the mechanism for the TCM to quote the current values of a list of PCRs.
*/
/*
typedef struct tdTCM_QUOTE_INFO { 
    TCM_STRUCT_VER version;             // This MUST be 1.1.0.0 
    BYTE fixed[4];                      // This SHALL always be the string 'QUOT' 
    TCM_COMPOSITE_HASH digestValue;     // This SHALL be the result of the composite hash algorithm
                                           using the current values of the requested PCR indices. 
    TCM_NONCE externalData;             // 160 bits of externally supplied data 
} TCM_QUOTE_INFO;
*/
/* 11.4 TCM_QUOTE_INFO2 rev 87

   This structure provides the mechanism for the TCM to quote the current values of a list of PCRs.
*/

typedef struct tdTCM_QUOTE_INFO {
    TCM_STRUCTURE_TAG tag;              /* This SHALL be TCM_TAG_QUOTE_INFO2 */
    BYTE fixed[4];                      /* This SHALL always be the string 'QUT2' */
    TCM_NONCE externalData;             /* 160 bits of externally supplied data  */
    TCM_PCR_INFO_LONG info;       /*  */
}__attribute__((packed)) TCM_QUOTE_INFO;

/* 12.1 TCM_EK_BLOB rev 87
  
  This structure provides a wrapper to each type of structure that will be in use when the
  endorsement key is in use.
*/

typedef struct tdTCM_EK_BLOB {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* TCM_TAG_EK_BLOB */
#endif
    TCM_EK_TYPE ekType;         /* This SHALL be set to reflect the type of blob in use */
    TCM_SIZED_BUFFER    blob;   /* The blob of information depending on the type */
#if 0
    uint32_t blobSize;    /* */
    [size_is(blobSize)] byte* blob;     /* */
#endif
}__attribute__((packed)) TCM_EK_BLOB;

/* 12.2 TCM_EK_BLOB_ACTIVATE rev 87

   This structure contains the symmetric key to encrypt the identity credential.  This structure
   always is contained in a TCM_EK_BLOB.
*/

typedef struct tdTCM_EK_BLOB_ACTIVATE {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;              /* TCM_TAG_EK_BLOB_ACTIVATE */
#endif
    TCM_SYMMETRIC_KEY sessionKey;       /* This SHALL be the session key used by the CA to encrypt
                                           the TCM_IDENTITY_CREDENTIAL */
    TCM_DIGEST idDigest;                /* This SHALL be the digest of the TCM identity public key
                                           that is being certified by the CA */
    TCM_PCR_INFO_SHORT pcrInfo;         /* This SHALL indicate the PCR's and localities */
}__attribute__((packed)) TCM_EK_BLOB_ACTIVATE;

/* 12.3 TCM_EK_BLOB_AUTH rev 87

   This structure contains the symmetric key to encrypt the identity credential.  This structure
   always is contained in a TCM_EK_BLOB.
*/

typedef struct tdTCM_EK_BLOB_AUTH {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* TCM_TAG_EK_BLOB_AUTH */
#endif
    TCM_SECRET authValue;       /* This SHALL be the authorization value */
}__attribute__((packed)) TCM_EK_BLOB_AUTH;

/* 12.5 TCM_IDENTITY_CONTENTS rev 87

   TCM_MakeIdentity uses this structure and the signature of this structure goes to a privacy CA
   during the certification process.
*/

typedef struct tdTCM_IDENTITY_CONTENTS {
    TCM_STRUCT_VER ver;                 /* This MUST be 1.1.0.0 */
    uint32_t ordinal;			/* This SHALL be the ordinal of the TCM_MakeIdentity
                                           command. */
    TCM_CHOSENID_HASH labelPrivCADigest;        /* This SHALL be the result of hashing the chosen
                                                   identityLabel and privacyCA for the new TCM
                                                   identity */
    TCM_PUBKEY identityPubKey;          /* This SHALL be the public key structure of the identity
                                           key */
}__attribute__((packed)) TCM_IDENTITY_CONTENTS; 

/* 12.8 TCM_ASYM_CA_CONTENTS rev 87

   This structure contains the symmetric key to encrypt the identity credential.
*/

typedef struct tdTCM_ASYM_CA_CONTENTS {
    TCM_SYMMETRIC_KEY sessionKey;       /* This SHALL be the session key used by the CA to encrypt
                                           the TCM_IDENTITY_CREDENTIAL */
    TCM_DIGEST idDigest;                /* This SHALL be the digest of the TCM_PUBKEY of the key
                                           that is being certified by the CA */
}__attribute__((packed))  TCM_ASYM_CA_CONTENTS;

/*
  14. Audit Structures
*/

/* 14.1 TCM_AUDIT_EVENT_IN rev 87

   This structure provides the auditing of the command upon receipt of the command. It provides the
   information regarding the input parameters.
*/

typedef struct tdTCM_AUDIT_EVENT_IN {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG   tag;            /* TCM_TAG_AUDIT_EVENT_IN */
#endif
    TCM_DIGEST inputParms;              /* Digest value according to the HMAC digest rules of the
                                           "above the line" parameters (i.e. the first HMAC digest
                                           calculation). When there are no HMAC rules, the input
                                           digest includes all parameters including and after the
                                           ordinal. */
    TCM_COUNTER_VALUE auditCount;       /* The current value of the audit monotonic counter */
} TCM_AUDIT_EVENT_IN;

/* 14.2 TCM_AUDIT_EVENT_OUT rev 87

  This structure reports the results of the command execution. It includes the return code and the
  output parameters.
*/

typedef struct tdTCM_AUDIT_EVENT_OUT {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;              /* TCM_TAG_AUDIT_EVENT_OUT */
#endif
    TCM_DIGEST outputParms;             /* Digest value according to the HMAC digest rules of the
                                           "above the line" parameters (i.e. the first HMAC digest
                                           calculation). When there are no HMAC rules, the output
                                           digest includes the return code, the ordinal, and all
                                           parameters after the return code. */
    TCM_COUNTER_VALUE auditCount;       /* The current value of the audit monotonic counter */
} TCM_AUDIT_EVENT_OUT;

/*
  18. Context structures
*/

/* 18.1 TCM_CONTEXT_BLOB rev 102

   This is the header for the wrapped context. The blob contains all information necessary to reload
   the context back into the TCM.
   
   The additional data is used by the TCM manufacturer to save information that will assist in the
   reloading of the context. This area must not contain any shielded data. For instance, the field
   could contain some size information that allows the TCM more efficient loads of the context. The
   additional area could not contain one of the primes for a RSA key.
   
   To ensure integrity of the blob when using symmetric encryption the TCM vendor could use some
   valid cipher chaining mechanism. To ensure the integrity without depending on correct
   implementation, the TCM_CONTEXT_BLOB structure uses a HMAC of the entire structure using tcmProof
   as the secret value.

   Since both additionalData and sensitiveData are informative, any or all of additionalData 
   could be moved to sensitiveData.
*/

#define TCM_CONTEXT_LABEL_SIZE 16

typedef struct tdTCM_CONTEXT_BLOB {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;              /* MUST be TCM_TAG_CONTEXTBLOB */
#endif
    TCM_RESOURCE_TYPE resourceType;     /* The resource type */
    TCM_HANDLE handle;                  /* Previous handle of the resource */
    BYTE label[TCM_CONTEXT_LABEL_SIZE]; /* Label for identification of the blob. Free format
                                           area. */
    uint32_t contextCount;		/* MUST be TCM_STANY_DATA -> contextCount when creating the
                                           structure.  This value is ignored for context blobs that
                                           reference a key. */
    TCM_DIGEST integrityDigest;         /* The integrity of the entire blob including the sensitive
                                           area. This is a HMAC calculation with the entire
                                           structure (including sensitiveData) being the hash and
                                           tcmProof is the secret */
#if 0
    uint32_t additionalSize;
    [size_is(additionalSize)] BYTE* additionalData;
    uint32_t sensitiveSize;
    [size_is(sensitiveSize)] BYTE* sensitiveData;
#endif
    TCM_SIZED_BUFFER additionalData;    /* Additional information set by the TCM that helps define
                                           and reload the context. The information held in this area
                                           MUST NOT expose any information held in shielded
                                           locations. This should include any IV for symmetric
                                           encryption */
    TCM_SIZED_BUFFER sensitiveData;     /* The normal information for the resource that can be
                                           exported */
} TCM_CONTEXT_BLOB;

/* 18.2 TCM_CONTEXT_SENSITIVE rev 87

   The internal areas that the TCM needs to encrypt and store off the TCM.

   This is an informative structure and the TCM can implement in any manner they wish.
*/

typedef struct tdTCM_CONTEXT_SENSITIVE {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;              /* MUST be TCM_TAG_CONTEXT_SENSITIVE */
#endif
    TCM_NONCE contextNonce;             /* On context blobs other than keys this MUST be
                                           TCM_STANY_DATA - > contextNonceSession For keys the value
                                           is TCM_STCLEAR_DATA -> contextNonceKey */
#if 0
    uint32_t internalSize;
    [size_is(internalSize)] BYTE* internalData;
#endif
    TCM_SIZED_BUFFER internalData;      /* The internal data area */
} TCM_CONTEXT_SENSITIVE;

/* 19.2 TCM_NV_ATTRIBUTES rev 99

   This structure allows the TCM to keep track of the data and permissions to manipulate the area. 
*/

typedef struct tdTCM_NV_ATTRIBUTES { 
//#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* TCM_TAG_NV_ATTRIBUTES */
//#endif
    uint32_t attributes;	/* The attribute area */
}__attribute__((packed)) TCM_NV_ATTRIBUTES; 

/* 19.3 TCM_NV_DATA_PUBLIC rev 110

   This structure represents the public description and controls on the NV area.

   bReadSTClear and bWriteSTClear are volatile, in that they are set FALSE at TCM_Startup(ST_Clear).
   bWriteDefine is persistent, in that it remains TRUE through startup.

   A pcrSelect of 0 indicates that the digestAsRelease is not checked.  In this case, the TCM is not
   required to consume NVRAM space to store the digest, although it may do so.  When
   TCM_GetCapability (TCM_CAP_NV_INDEX) returns the structure, a TCM that does not store the digest
   can return zero.  A TCM that does store the digest may return either the digest or zero.
*/

typedef struct tdTCM_NV_DATA_PUBLIC { 
//#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;              /* This SHALL be TCM_TAG_NV_DATA_PUBLIC */
//#endif
    TCM_NV_INDEX nvIndex;               /* The index of the data area */
    TCM_PCR_INFO_LONG pcrInfoRead;     /* The PCR selection that allows reading of the area */
    TCM_PCR_INFO_LONG pcrInfoWrite;    /* The PCR selection that allows writing of the area */
    TCM_NV_ATTRIBUTES permission;       /* The permissions for manipulating the area */
    TCM_BOOL bReadSTClear;              /* Set to FALSE on each TCM_Startup(ST_Clear) and set to
                                           TRUE after a ReadValuexxx with datasize of 0 */
    TCM_BOOL bWriteSTClear;             /* Set to FALSE on each TCM_Startup(ST_CLEAR) and set to
                                           TRUE after a WriteValuexxx with a datasize of 0. */
    TCM_BOOL bWriteDefine;              /* Set to FALSE after TCM_NV_DefineSpace and set to TRUE
                                           after a successful WriteValuexxx with a datasize of 0 */
    uint32_t dataSize;			/* The size of the data area in bytes */
}__attribute__((packed)) TCM_NV_DATA_PUBLIC; 

/*  19.4 TCM_NV_DATA_SENSITIVE rev 101
  
    This is an internal structure that the TCM uses to keep the actual NV data and the controls
    regarding the area.
*/

typedef struct tdTCM_NV_DATA_SENSITIVE { 
//#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* This SHALL be TCM_TAG_NV_DATA_SENSITIVE */
//#endif
    TCM_NV_DATA_PUBLIC pubInfo; /* The public information regarding this area */
    TCM_AUTHDATA authValue;     /* The authorization value to manipulate the value */
    BYTE *data;                 /* The data area. This MUST not contain any sensitive information as
                                   the TCM does not provide any confidentiality on the data. */
}__attribute__((packed)) TCM_NV_DATA_SENSITIVE;

typedef struct tdTCM_NV_INDEX_ENTRIES {
    uint32_t nvIndexCount;			/* number of entries */
    TCM_NV_DATA_SENSITIVE *tcm_nvindex_entry;	/* array of TCM_NV_DATA_SENSITIVE */
}__attribute__((packed)) TCM_NV_INDEX_ENTRIES;

/* TCM_NV_DATA_ST

   This is a cache of the the NV defined space volatile flags, used during error rollback
*/

typedef struct tdTCM_NV_DATA_ST {
    TCM_NV_INDEX nvIndex;               /* The index of the data area */
    TCM_BOOL bReadSTClear;
    TCM_BOOL bWriteSTClear;
} TCM_NV_DATA_ST;

/*
  21. Capability areas
*/

/* 21.6 TCM_CAP_VERSION_INFO rev 99

   This structure is an output from a TCM_GetCapability -> TCM_CAP_VERSION_VAL request.  TCM returns
   the current version and revision of the TCM.

   The specLevel and errataRev are defined in the document "Specification and File Naming
   Conventions"

   The tcmVendorID is a value unique to each vendor. It is defined in the document "TCG Vendor
   Naming".

   The vendor specific area allows the TCM vendor to provide support for vendor options. The TCM
   vendor may define the area to the TCM vendor's needs.
*/

typedef struct tdTCM_CAP_VERSION_INFO {
//#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* MUST be TCM_TAG_CAP_VERSION_INFO */
//#endif
    TCM_VERSION version;        /* The version and revision */
    uint16_t specLevel;		/* A number indicating the level of ordinals supported */
    BYTE errataRev;             /* A number indicating the errata version of the specification */
    BYTE tcmVendorID[4];        /* The vendor ID unique to each TCM manufacturer. */
    uint16_t vendorSpecificSize;  /* The size of the vendor specific area */
    BYTE* vendorSpecific;       /* Vendor specific information */
    /* NOTE Cannot be TCM_SIZED_BUFFER, because of uint16_t */
} TCM_CAP_VERSION_INFO;


/* 21.10 TCM_DA_ACTION_TYPE rev 100

   This structure indicates the action taken when the dictionary attack mitigation logic is active,
   when TCM_DA_STATE is TCM_DA_STATE_ACTIVE.
*/   

typedef struct tdTCM_DA_ACTION_TYPE {
    TCM_STRUCTURE_TAG tag;      /* MUST be TCM_TAG_DA_ACTION_TYPE */
    uint32_t actions;		/* The action taken when TCM_DA_STATE is TCM_DA_STATE_ACTIVE. */
} TCM_DA_ACTION_TYPE;

/* 21.7  TCM_DA_INFO rev 100
   
   This structure is an output from a TCM_GetCapability -> TCM_CAP_DA_LOGIC request if
   TCM_PERMANENT_FLAGS -> disableFullDALogicInfo is FALSE.
   
   It returns static information describing the TCM response to authorization failures that might
   indicate a dictionary attack and dynamic information regarding the current state of the
   dictionary attack mitigation logic.
*/

typedef struct tdTCM_DA_INFO {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* MUST be TCM_TAG_DA_INFO */
#endif
    TCM_DA_STATE state;         /* Dynamic.  The actual state of the dictionary attack mitigation
                                   logic.  See 21.9. */
    uint16_t currentCount;	/* Dynamic.  The actual count of the authorization failure counter
                                   for the selected entity type */
    uint16_t thresholdCount;	/* Static.  Dictionary attack mitigation threshold count for the
                                   selected entity type */
    TCM_DA_ACTION_TYPE actionAtThreshold;       /* Static Action of the TCM when currentCount passes
                                                   thresholdCount. See 21.10. */
    uint32_t actionDependValue;	/* Dynamic.  Action being taken when the dictionary attack
                                   mitigation logic is active.  E.g., when actionAtThreshold is
                                   TCM_DA_ACTION_TIMEOUT, this is the lockout time remaining in
                                   seconds. */
    TCM_SIZED_BUFFER vendorData;        /* Vendor specific data field */
} TCM_DA_INFO;

/* 21.8 TCM_DA_INFO_LIMITED rev 100

   This structure is an output from a TCM_GetCapability -> TCM_CAP_DA_LOGIC request if
   TCM_PERMANENT_FLAGS -> disableFullDALogicInfo is TRUE.
   
   It returns static information describing the TCM response to authorization failures that might
   indicate a dictionary attack and dynamic information regarding the current state of the
   dictionary attack mitigation logic. This structure omits information that might aid an attacker.
*/

typedef struct tdTCM_DA_INFO_LIMITED {
#ifdef TCM_USE_TAG_IN_STRUCTURE
    TCM_STRUCTURE_TAG tag;      /* MUST be TCM_TAG_DA_INFO_LIMITED */
#endif
    TCM_DA_STATE state;         /* Dynamic.  The actual state of the dictionary attack mitigation
                                   logic.  See 21.9. */
    TCM_DA_ACTION_TYPE actionAtThreshold;       /* Static Action of the TCM when currentCount passes
                                                   thresholdCount. See 21.10. */
    TCM_SIZED_BUFFER vendorData;        /* Vendor specific data field */
} TCM_DA_INFO_LIMITED;

#endif

/* Sanity check the size of the NV file vs. the maximum allocation size

   The multipliers are very conservative
*/
//!!
#if (TCM_ALLOC_MAX < (4000 + (TCM_OWNER_EVICT_KEY_HANDLES * 2000) +	 TCM_MAX_NV_DEFINED_SPACE))
#error "TCM_ALLOC_MAX too small for NV file size"
#endif

/* Sanity check the size of the volatile file vs. the maximum allocation size
 
   The multipliers are very conservative
*/

#if (TCM_ALLOC_MAX < (4000 + TCM_KEY_HANDLES * 2000 + TCM_MIN_TRANS_SESSIONS * 500 + TCM_MIN_DAA_SESSIONS * 2000 + TCM_MIN_AUTH_SESSIONS * 500))
#error "TCM_ALLOC_MAX too small for volatile file size"
#endif
