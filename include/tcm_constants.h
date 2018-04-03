/********************************************************************************/
/*                                                                              */
/*                              TCM Constants                                   */
/*                           Written by Ken Goldman                             */
/*                     IBM Thomas J. Watson Research Center                     */
/*            $Id: tcm_constants.h 4603 2011-08-16 20:40:26Z kgoldman $         */
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

#ifndef TCM_CONSTANTS_H
#define TCM_CONSTANTS_H

#include <stdint.h>

/*
  NOTE implementation Specific
*/

/*
  version, revision, specLevel, errataRev
*/

/* current for released specification revision 103 */

#define TCM_HASH_SIZE 32
#define TCM_REVISION_MAX 9999
#ifndef TCM_REVISION
#define TCM_REVISION TCM_REVISION_MAX
#endif

#if  (TCM_REVISION >= 116) 

#define TCM_SPEC_LEVEL  0x0002          /* uint16_t The level of ordinals supported */
#define TCM_ERRATA_REV  0x03            /* specification errata level */

#elif  (TCM_REVISION >= 103) 

#define TCM_SPEC_LEVEL  0x0002          /* uint16_t The level of ordinals supported */
#define TCM_ERRATA_REV  0x02            /* specification errata level */

#elif (TCM_REVISION >= 94)

#define TCM_SPEC_LEVEL  0x0002          /* uint16_t The level of ordinals supported */
#define TCM_ERRATA_REV  0x01            /* specification errata level */

#elif (TCM_REVISION >= 85)

#define TCM_SPEC_LEVEL  0x0002          /* uint16_t The level of ordinals supported */
#define TCM_ERRATA_REV  0x00            /* specification errata level */

#else

#define TCM_SPEC_LEVEL  0x0001          /* uint16_t The level of ordinals supported */
#define TCM_ERRATA_REV  0x00            /* specification errata level */

#endif

/* IBM specific */

#if 0   /* at one time vendorID was the PCI vendor ID, this is the IBM code */
#define TCM_VENDOR_ID   "\x00\x00\x10\x14"      /* BYTE[4], the vendor ID, obtained from the TCG,
                                                   typically PCI vendor ID */
#endif



#define TCM_VENDOR_ID    "IBM"  /* 4 bytes, as of rev 99 vendorID and TCM_CAP_PROP_MANUFACTURER
                                   return the same value */
#define TCM_MANUFACTURER "IBM"  /* 4 characters, assigned by TCG, typically stock ticker symbol */


/* Timeouts in microseconds.  These are for the platform specific interface (e.g. the LPC bus
   registers in the PC Client TCM).  They are most likely not applicable to a software TCM.  */
#define TCM_TIMEOUT_A   1000000
#define TCM_TIMEOUT_B   1000000
#define TCM_TIMEOUT_C   1000000
#define TCM_TIMEOUT_D   1000000

/* dictionary attack mitigation */

#define TCM_LOCKOUT_THRESHOLD 5         /* successive failures to trigger lockout, must be greater
                                           than 0 */

/* Denotes the duration value in microseconds of the duration of the three classes of commands:
   Small, Medium and Long.  The command types are in the Part 2 Ordinal Table.  Essentially:

   Long - creating an RSA key pair
   Medium - using an RSA key
   Short  - anything else
*/

#ifndef TCM_SMALL_DURATION
#define TCM_SMALL_DURATION      2000000
#endif

#ifndef TCM_MEDIUM_DURATION     
#define TCM_MEDIUM_DURATION     5000000
#endif

#ifndef TCM_LONG_DURATION
#define TCM_LONG_DURATION      60000000
#endif

/* startup effects */
   
#define    TCM_STARTUP_EFFECTS_VALUE   \
(TCM_STARTUP_EFFECTS_ST_ANY_RT_KEY |    /* key resources init by TCM_Startup(ST_ANY) */ \
 TCM_STARTUP_EFFECTS_ST_STATE_RT_HASH | /* hash resources are init by TCM_Startup(ST_STATE) */ \
 TCM_STARTUP_EFFECTS_ST_CLEAR_AUDITDIGEST) /* auditDigest nulled on TCM_Startup(ST_CLEAR) */

/*
  TCM buffer limits
*/

/* This value is used to limit memory allocation to prevent resource overload. */

#ifndef TCM_ALLOC_MAX
#define TCM_ALLOC_MAX  0x10000  /* 64k bytes */
#endif

/* This is the increment by which the TCM_STORE_BUFFER grows.  A larger number saves realloc's.  A
   smaller number saves memory.

   TCM_ALLOC_MAX must be a multiple of this value.
*/

#define TCM_STORE_BUFFER_INCREMENT (TCM_ALLOC_MAX / 64)

/* This is the maximum value of the TCM input and output packet buffer.  It should be large enough
   to accommodate the largest TCM command or response, currently about 1200 bytes.  It should be
   small enough to accommodate whatever software is driving the TCM.

   NOTE: Some commands are somewhat open ended, and related to this parmater.  E.g., The input size
   for the TCM_SHA1Init.  The output size for TCM_GetRandom.
  
   It is returned by TCM_GetCapability -> TCM_CAP_PROP_INPUT_BUFFER
*/

#ifndef TCM_BUFFER_MAX
#define TCM_BUFFER_MAX  0x1000  /* 4k bytes */
#endif

/* Random number generator */

/* maximum bytes in one TCM_GetRandom() call

   Use maximum input buffer size minus tag, paramSize, returnCode, randomBytesSize.
*/

#define TCM_RANDOM_MAX  (TCM_BUFFER_MAX \
                         - sizeof(TCM_TAG) - sizeof(uint32_t) \
			 - sizeof(TCM_RESULT) - sizeof(uint32_t))

/* Maximum number of bytes that can be sent to TCM_SHA1Update. Must be a multiple of 64 bytes.

   Use maximum input buffer size minus tag, paramSize, ordinal, numBytes.
*/

#define TCM_SHA1_MAXNUMBYTES    (TCM_BUFFER_MAX - 64)

/* extra audit status bits for TSC commands outside the normal ordinal range */
#define TSC_PHYS_PRES_AUDIT     0x01
#define TSC_RESET_ESTAB_AUDIT   0x02


/* TCM_CAP_MFR capabilities */
#define TCM_CAP_PROCESS_ID              0x00000020


/* define a value for an illegal instance handle */

#define TCM_ILLEGAL_INSTANCE_HANDLE     0xffffffff

/*
  NOTE End Implementation Specific
*/

/* 3. Structure Tags rev 105

   There have been some indications that knowing what structure is in use would be valuable
   information in each structure. This new tag will be in each new structure that the TCM defines.
   
   The upper nibble of the value designates the purview of the structure tag.  0 is used for TCM
   structures, 1 for platforms, and 2-F are reserved.
*/

/* 3.1 TCM_STRUCTURE_TAG */

/*                                              Structure   */
#define TCM_TAG_CONTEXTBLOB             0x0001 /*  TCM_CONTEXT_BLOB */
#define TCM_TAG_CONTEXT_SENSITIVE       0x0002 /*  TCM_CONTEXT_SENSITIVE */
#define TCM_TAG_CONTEXTPOINTER          0x0003 /*  TCM_CONTEXT_POINTER */
#define TCM_TAG_CONTEXTLIST             0x0004 /*  TCM_CONTEXT_LIST */
#define TCM_TAG_SIGNINFO                0x0005 /*  TCM_SIGN_INFO */
#define TCM_TAG_PCR_INFO           	0x0006 /*  TCM_PCR_INFO_LONG */
#define TCM_TAG_PERSISTENT_FLAGS        0x0007 /*  TCM_PERSISTENT_FLAGS (deprecated 1.1 struct) */
#define TCM_TAG_VOLATILE_FLAGS          0x0008 /*  TCM_VOLATILE_FLAGS (deprecated 1.1 struct) */
#define TCM_TAG_PERSISTENT_DATA         0x0009 /*  TCM_PERSISTENT_DATA (deprecated 1.1 struct) */
#define TCM_TAG_VOLATILE_DATA           0x000A /*  TCM_VOLATILE_DATA (deprecated 1.1 struct) */
#define TCM_TAG_SV_DATA                 0x000B /*  TCM_SV_DATA */
#define TCM_TAG_EK_BLOB                 0x000C /*  TCM_EK_BLOB */
#define TCM_TAG_EK_BLOB_AUTH            0x000D /*  TCM_EK_BLOB_AUTH */
#define TCM_TAG_COUNTER_VALUE           0x000E /*  TCM_COUNTER_VALUE */
#define TCM_TAG_TRANSPORT_INTERNAL      0x000F /*  TCM_TRANSPORT_INTERNAL */
#define TCM_TAG_TRANSPORT_LOG_IN        0x0010 /*  TCM_TRANSPORT_LOG_IN */
#define TCM_TAG_TRANSPORT_LOG_OUT       0x0011 /*  TCM_TRANSPORT_LOG_OUT */
#define TCM_TAG_AUDIT_EVENT_IN          0x0012 /*  TCM_AUDIT_EVENT_IN */
#define TCM_TAG_AUDIT_EVENT_OUT         0X0013 /*  TCM_AUDIT_EVENT_OUT */
#define TCM_TAG_CURRENT_TICKS           0x0014 /*  TCM_CURRENT_TICKS */
#define TCM_TAG_KEY                     0x0015 /*  TCM_KEY */
#define TCM_TAG_STORED_DATA12           0x0016 /*  TCM_STORED_DATA12 */
#define TCM_TAG_NV_ATTRIBUTES           0x0017 /*  TCM_NV_ATTRIBUTES */
#define TCM_TAG_NV_DATA_PUBLIC          0x0018 /*  TCM_NV_DATA_PUBLIC */
#define TCM_TAG_NV_DATA_SENSITIVE       0x0019 /*  TCM_NV_DATA_SENSITIVE */
#define TCM_TAG_DELEGATIONS             0x001A /*  TCM DELEGATIONS */
#define TCM_TAG_DELEGATE_PUBLIC         0x001B /*  TCM_DELEGATE_PUBLIC */
#define TCM_TAG_DELEGATE_TABLE_ROW      0x001C /*  TCM_DELEGATE_TABLE_ROW */
#define TCM_TAG_TRANSPORT_AUTH          0x001D /*  TCM_TRANSPORT_AUTH */
#define TCM_TAG_TRANSPORT_PUBLIC        0X001E /*  TCM_TRANSPORT_PUBLIC */
#define TCM_TAG_PERMANENT_FLAGS         0X001F /*  TCM_PERMANENT_FLAGS */
#define TCM_TAG_STCLEAR_FLAGS           0X0020 /*  TCM_STCLEAR_FLAGS */
#define TCM_TAG_STANY_FLAGS             0X0021 /*  TCM_STANY_FLAGS */
#define TCM_TAG_PERMANENT_DATA          0X0022 /*  TCM_PERMANENT_DATA */
#define TCM_TAG_STCLEAR_DATA            0X0023 /*  TCM_STCLEAR_DATA */
#define TCM_TAG_STANY_DATA              0X0024 /*  TCM_STANY_DATA */
#define TCM_TAG_FAMILY_TABLE_ENTRY      0X0025 /*  TCM_FAMILY_TABLE_ENTRY */
#define TCM_TAG_DELEGATE_SENSITIVE      0X0026 /*  TCM_DELEGATE_SENSITIVE */
#define TCM_TAG_DELG_KEY_BLOB           0X0027 /*  TCM_DELG_KEY_BLOB */
#define TCM_TAG_KEY12                   0x0028 /*  TCM_KEY12 */
#define TCM_TAG_CERTIFY_INFO2           0X0029 /*  TCM_CERTIFY_INFO2 */
#define TCM_TAG_DELEGATE_OWNER_BLOB     0X002A /*  TCM_DELEGATE_OWNER_BLOB */
#define TCM_TAG_EK_BLOB_ACTIVATE        0X002B /*  TCM_EK_BLOB_ACTIVATE */
#define TCM_TAG_DAA_BLOB                0X002C /*  TCM_DAA_BLOB */
#define TCM_TAG_DAA_CONTEXT             0X002D /*  TCM_DAA_CONTEXT */
#define TCM_TAG_DAA_ENFORCE             0X002E /*  TCM_DAA_ENFORCE */
#define TCM_TAG_DAA_ISSUER              0X002F /*  TCM_DAA_ISSUER */
#define TCM_TAG_CAP_VERSION_INFO        0X0030 /*  TCM_CAP_VERSION_INFO */
#define TCM_TAG_DAA_SENSITIVE           0X0031 /*  TCM_DAA_SENSITIVE */
#define TCM_TAG_DAA_TCM                 0X0032 /*  TCM_DAA_TCM */
#define TCM_TAG_CMK_MIGAUTH             0X0033 /*  TCM_CMK_MIGAUTH */
#define TCM_TAG_CMK_SIGTICKET           0X0034 /*  TCM_CMK_SIGTICKET */
#define TCM_TAG_CMK_MA_APPROVAL         0X0035 /*  TCM_CMK_MA_APPROVAL */
#define TCM_TAG_QUOTE_INFO             0X0036 /*  TCM_QUOTE_INFO2 */
#define TCM_TAG_DA_INFO                 0x0037 /*  TCM_DA_INFO */
#define TCM_TAG_DA_INFO_LIMITED         0x0038 /*  TCM_DA_INFO_LIMITED */
#define TCM_TAG_DA_ACTION_TYPE          0x0039 /*  TCM_DA_ACTION_TYPE */

/*
  SW TCM Tags
*/

/*
  These tags are used to describe the format of serialized TCM non-volatile state
*/

/* These describe the overall format */

/* V1 state is the sequence permanent data, permanent flags, owner evict keys, NV defined space */

#define TCM_TAG_NVSTATE_V1		0x0001		/* svn revision 4078 */

/* These tags describe the TCM_PERMANENT_DATA format */

/* For the first release, use the standard TCM_TAG_PERMANENT_DATA tag.  Since this tag is never
   visible outside the TCM, the tag value can be changed if the format changes.
*/

/* These tags describe the TCM_PERMANENT_FLAGS format */

/* The TCM_PERMANENT_FLAGS structure changed from rev 94 to 103.  Unfortunately, the standard TCM
   tag did not change.  Define distinguishing values here.
*/

#define TCM_TAG_NVSTATE_PF94		0x0001
#define TCM_TAG_NVSTATE_PF103		0x0002

/* This tag describes the owner evict key format */

#define TCM_TAG_NVSTATE_OE_V1		0x0001

/* This tag describes the NV defined space format */

#define TCM_TAG_NVSTATE_NV_V1		0x0001

/* V2 added the NV public optimization */

#define TCM_TAG_NVSTATE_NV_V2		0x0002

/*
  These tags are used to describe the format of serialized TCM volatile state
*/

/* These describe the overall format */

/* V1 state is the sequence TCM Parameters, TCM_STCLEAR_FLAGS, TCM_STANY_FLAGS, TCM_STCLEAR_DATA,
   TCM_STANY_DATA, TCM_KEY_HANDLE_ENTRY, SHA1 context(s), TCM_TRANSHANDLE, testState, NV volatile
   flags */

#define TCM_TAG_VSTATE_V1		0x0001

/* This tag defines the TCM Parameters format */

#define TCM_TAG_TCM_PARAMETERS_V1	0x0001

/* This tag defines the TCM_STCLEAR_FLAGS format */

/* V1 is the TCG standard returned by the getcap.  It's unlikely that this will change */

#define TCM_TAG_STCLEAR_FLAGS_V1	0x0001

/* These tags describe the TCM_STANY_FLAGS format */

/* For the first release, use the standard TCM_TAG_STANY_FLAGS tag.  Since this tag is never visible
   outside the TCM, the tag value can be changed if the format changes.
*/

/* This tag defines the TCM_STCLEAR_DATA format */

/* V2 deleted the ordinalResponse, responseCount */ 

#define TCM_TAG_STCLEAR_DATA_V2         0X0024

/* These tags describe the TCM_STANY_DATA format */

/* For the first release, use the standard TCM_TAG_STANY_DATA tag.  Since this tag is never visible
   outside the TCM, the tag value can be changed if the format changes.
*/

/* This tag defines the key handle entries format */

#define TCM_TAG_KEY_HANDLE_ENTRIES_V1	0x0001

/* This tag defines the SHA-1 context format */

#define TCM_TAG_SHA1CONTEXT_OSSL_V1	0x0001		/* for openssl */

#define TCM_TAG_SHA1CONTEXT_FREEBL_V1	0x0101		/* for freebl */

/* This tag defines the NV index entries volatile format */

#define TCM_TAG_NV_INDEX_ENTRIES_VOLATILE_V1	0x0001

/* 4. Types
 */

/* 4.1 TCM_RESOURCE_TYPE rev 87 */

#define TCM_RT_KEY      0x00000001  /* The handle is a key handle and is the result of a LoadKey
                                       type operation */
   
#define TCM_RT_AUTH     0x00000002  /* The handle is an authorization handle. Auth handles come from
                                       TCM_APCreate, TCM_OSAP and TCM_DSAP */
   
#define TCM_RT_HASH     0X00000003  /* Reserved for hashes */

#define TCM_RT_TRANS    0x00000004  /* The handle is for a transport session. Transport handles come
                                       from TCM_EstablishTransport */
   
#define TCM_RT_CONTEXT  0x00000005  /* Resource wrapped and held outside the TCM using the context
                                       save/restore commands */

#define TCM_RT_COUNTER  0x00000006  /* Reserved for counters */

#define TCM_RT_DELEGATE 0x00000007  /* The handle is for a delegate row. These are the internal rows
                                       held in NV storage by the TCM */
   
#define TCM_RT_DAA_TCM  0x00000008  /* The value is a DAA TCM specific blob */
                                      
#define TCM_RT_DAA_V0   0x00000009  /* The value is a DAA V0 parameter */
                                     
#define TCM_RT_DAA_V1   0x0000000A  /* The value is a DAA V1 parameter */
                                     
/* 4.2 TCM_PAYLOAD_TYPE rev 87

   This structure specifies the type of payload in various messages. 
*/

#define TCM_PT_SYM              0x00    /* The entity is an asymmetric key */
#define TCM_PT_ASYM             0x01    /* The entity is an asymmetric key */
#define TCM_PT_BIND             0x02    /* The entity is bound data */
#define TCM_PT_MIGRATE          0x03    /* The entity is a migration blob */
#define TCM_PT_MAINT            0x04    /* The entity is a maintenance blob */
#define TCM_PT_SEAL             0x05    /* The entity is sealed data */
#define TCM_PT_MIGRATE_RESTRICTED 0x06  /* The entity is a restricted-migration asymmetric key */
#define TCM_PT_MIGRATE_EXTERNAL 0x07    /* The entity is a external migratable key */
#define TCM_PT_SYM_MIGRATE      0x08    /* The entity is a CMK migratable blob */
#define TCM_PT_ASYM_MIGRATE      0x09    /* The entity is a CMK migratable blob */
/* 0x09 - 0x7F Reserved for future use by TCM */
/* 0x80 - 0xFF Vendor specific payloads */

/* 4.3 TCM_ENTITY_TYPE rev 100

   This specifies the types of entity that are supported by the TCM. 

   The LSB is used to indicate the entity type.  The MSB is used to indicate the ADIP 
   encryption scheme when applicable.

   For compatibility with TCM 1.1, this mapping is maintained:

   0x0001 specifies a keyHandle entity with XOR encryption
   0x0002 specifies an owner entity with XOR encryption
   0x0003 specifies some data entity with XOR encryption
   0x0004 specifies the SRK entity with XOR encryption
   0x0005 specifies a key entity with XOR encryption

   When the entity is not being used for ADIP encryption, the MSB MUST be 0x00.
*/

/* TCM_ENTITY_TYPE LSB Values (entity type) */

#define TCM_ET_KEYHANDLE        0x01    /* The entity is a keyHandle or key */
#define TCM_ET_OWNER            0x02    /*0x40000001 The entity is the TCM Owner */
#define TCM_ET_DATA             0x03    /* The entity is some data */
#define TCM_ET_SMK              0x04    /*0x40000000 The entity is the SRK */
#define TCM_ET_KEY              0x05    /* The entity is a key or keyHandle */
#define TCM_ET_REVOKE           0x06    /*0x40000002 The entity is the RevokeTrust value */
#define TCM_ET_DEL_OWNER_BLOB   0x07    /* The entity is a delegate owner blob */
#define TCM_ET_DEL_ROW          0x08    /* The entity is a delegate row */
#define TCM_ET_DEL_KEY_BLOB     0x09    /* The entity is a delegate key blob */
#define TCM_ET_COUNTER          0x0A    /* The entity is a counter */
#define TCM_ET_NV               0x0B    /* The entity is a NV index */
#define TCM_ET_OPERATOR         0x0C    /* The entity is the operator */
#define TCM_ET_RESERVED_HANDLE  0x40    /* Reserved. This value avoids collisions with the handle
                                           MSB setting.*/
#define TCM_ET_NONE 0x12

/* TCM_ENTITY_TYPE MSB Values (ADIP encryption scheme) */

#define TCM_ET_XOR              0x00    /* XOR  */
#define TCM_ET_AES128_CTR       0x06    /* AES 128 bits in CTR mode */

/* 4.4 Handles rev 88

   Handles provides pointers to TCM internal resources. Handles should provide the ability to locate
   a value without collision.

   1. The TCM MAY order and set a handle to any value the TCM determines is appropriate

   2. The handle value SHALL provide assurance that collisions SHOULD not occur in 2^24 handles

   4.4.1 Reserved Key Handles 

   The reserved key handles. These values specify specific keys or specific actions for the TCM. 
*/

/* 4.4.1 Reserved Key Handles rev 87

   The reserved key handles. These values specify specific keys or specific actions for the TCM.

   TCM_KH_TRANSPORT indicates to TCM_EstablishTransport that there is no encryption key, and that
   the "secret" wrapped parameters are actually passed unencrypted.
*/

#define TCM_KH_SRK              0x40000000 /* The handle points to the SRK */
#define TCM_KH_OWNER            0x40000001 /* The handle points to the TCM Owner */
#define TCM_KH_REVOKE           0x40000002 /* The handle points to the RevokeTrust value */
#define TCM_KH_TRANSPORT        0x40000003 /* The handle points to the TCM_EstablishTransport static
                                              authorization */
#define TCM_KH_OPERATOR         0x40000004 /* The handle points to the Operator auth */
#define TCM_KH_ADMIN            0x40000005 /* The handle points to the delegation administration
                                              auth */
#define TCM_KH_EK               0x40000006 /* The handle points to the PUBEK, only usable with
                                              TCM_OwnerReadInternalPub */

/* 4.5 TCM_STARTUP_TYPE rev 87

   To specify what type of startup is occurring.  
*/

#define TCM_ST_CLEAR            0x0001 /* The TCM is starting up from a clean state */
#define TCM_ST_STATE            0x0002 /* The TCM is starting up from a saved state */
#define TCM_ST_DEACTIVATED      0x0003 /* The TCM is to startup and set the deactivated flag to
                                          TRUE */

/* 4.6 TCM_STARTUP_EFFECTS rev 101

   This structure lists for the various resources and sessions on a TCM the affect that TCM_Startup
   has on the values.

   There are three ST_STATE options for keys (restore all, restore non-volatile, or restore none)
   and two ST_CLEAR options (restore non-volatile or restore none).  As bit 4 was insufficient to
   describe the possibilities, it is deprecated.  Software should use TCM_CAP_KEY_HANDLE to
   determine which keys are loaded after TCM_Startup.

   31-9 No information and MUST be FALSE
   
   8 TCM_RT_DAA_TCM resources are initialized by TCM_Startup(ST_STATE)
   7 TCM_Startup has no effect on auditDigest 
   6 auditDigest is set to all zeros on TCM_Startup(ST_CLEAR) but not on other types of TCM_Startup 
   5 auditDigest is set to all zeros on TCM_Startup(any)
   4 TCM_RT_KEY Deprecated, as the meaning was subject to interpretation.  (Was:TCM_RT_KEY resources
     are initialized by TCM_Startup(ST_ANY))
   3 TCM_RT_AUTH resources are initialized by TCM_Startup(ST_STATE) 
   2 TCM_RT_HASH resources are initialized by TCM_Startup(ST_STATE) 
   1 TCM_RT_TRANS resources are initialized by TCM_Startup(ST_STATE) 
   0 TCM_RT_CONTEXT session (but not key) resources are initialized by TCM_Startup(ST_STATE) 
*/


#define TCM_STARTUP_EFFECTS_ST_STATE_RT_DAA             0x00000100      /* bit 8 */
#define TCM_STARTUP_EFFECTS_STARTUP_NO_AUDITDIGEST      0x00000080      /* bit 7 */
#define TCM_STARTUP_EFFECTS_ST_CLEAR_AUDITDIGEST        0x00000040      /* bit 6 */
#define TCM_STARTUP_EFFECTS_STARTUP_AUDITDIGEST         0x00000020      /* bit 5 */
#define TCM_STARTUP_EFFECTS_ST_ANY_RT_KEY               0x00000010      /* bit 4 */
#define TCM_STARTUP_EFFECTS_ST_STATE_RT_AUTH            0x00000008      /* bit 3 */
#define TCM_STARTUP_EFFECTS_ST_STATE_RT_HASH            0x00000004      /* bit 2 */
#define TCM_STARTUP_EFFECTS_ST_STATE_RT_TRANS           0x00000002      /* bit 1 */
#define TCM_STARTUP_EFFECTS_ST_STATE_RT_CONTEXT         0x00000001      /* bit 0 */

/* 4.7 TCM_PROTOCOL_ID rev 87 

   This value identifies the protocol in use. 
*/

#define TCM_PID_NONE            0x0000  /* kgold - added */
#define TCM_PID_APCREATE        0x0001  /* The APCreate protocol. */
#define TCM_PID_OSAP            0x0002  /* The OSAP protocol. */
#define TCM_PID_ADIP            0x0003  /* The ADIP protocol. */
#define TCM_PID_ADCP            0X0004  /* The ADCP protocol. */
#define TCM_PID_OWNER           0X0005  /* The protocol for taking ownership of a TCM. */
#define TCM_PID_DSAP            0x0006  /* The DSAP protocol */
#define TCM_PID_TRANSPORT       0x0007  /*The transport protocol */

/* 4.8 TCM_ALGORITHM_ID rev 99

   This table defines the types of algorithms that may be supported by the TCM. 

   The TCM MUST support the algorithms TCM_ALG_RSA, TCM_ALG_SHA, TCM_ALG_HMAC, and TCM_ALG_MGF1
*/

#define TCM_ALG_KDF  	0x00000007      /* AES, key size 192 */
#define TCM_ALG_AES192  0x00000008      /* AES, key size 192 */
#define TCM_ALG_AES256  0x00000009      /* AES, key size 256 */
#define TCM_ALG_XOR     0x0000000A      /* XOR using the rolling nonces */
#define TCM_ALG_SM2     0x0000000B      /* XOR using the rolling nonces */
#define TCM_ALG_SM4     0x0000000C      /* XOR using the rolling nonces */
#define TCM_ALG_SM3     0x0000000D      /* XOR using the rolling nonces */
#define TCM_ALG_HMAC    0x0000000E      /* XOR using the rolling nonces */

/* 4.9 TCM_PHYSICAL_PRESENCE rev 87

*/

#define TCM_PHYSICAL_PRESENCE_HW_DISABLE        0x0200 /* Sets the physicalPresenceHWEnable to FALSE
                                                        */
#define TCM_PHYSICAL_PRESENCE_CMD_DISABLE       0x0100 /* Sets the physicalPresenceCMDEnable to
                                                          FALSE */
#define TCM_PHYSICAL_PRESENCE_LIFETIME_LOCK     0x0080 /* Sets the physicalPresenceLifetimeLock to
                                                          TRUE */
#define TCM_PHYSICAL_PRESENCE_HW_ENABLE         0x0040 /* Sets the physicalPresenceHWEnable to TRUE
                                                        */
#define TCM_PHYSICAL_PRESENCE_CMD_ENABLE        0x0020 /* Sets the physicalPresenceCMDEnable to TRUE
                                                        */
#define TCM_PHYSICAL_PRESENCE_NOTPRESENT        0x0010 /* Sets PhysicalPresence = FALSE */
#define TCM_PHYSICAL_PRESENCE_PRESENT           0x0008 /* Sets PhysicalPresence = TRUE */
#define TCM_PHYSICAL_PRESENCE_LOCK              0x0004 /* Sets PhysicalPresenceLock = TRUE */

#define TCM_PHYSICAL_PRESENCE_MASK              0xfc03  /* ~ OR of all above bits */

/* 4.10 TCM_MIGRATE_SCHEME rev 103

   The scheme indicates how the StartMigrate command should handle the migration of the encrypted
   blob.
*/

#define TCM_MS_MIGRATE                  0x0001 /* A public key that can be used with all TCM
                                                  migration commands other than 'ReWrap' mode. */
#define TCM_MS_REWRAP                   0x0002 /* A public key that can be used for the ReWrap mode
                                                  of TCM_CreateMigrationBlob. */
#define TCM_MS_MAINT                    0x0003 /* A public key that can be used for the Maintenance
                                                  commands */
#define TCM_MS_RESTRICT_MIGRATE         0x0004 /* The key is to be migrated to a Migration
                                                  Authority. */
#define TCM_MS_RESTRICT_APPROVE         0x0005 /* The key is to be migrated to an entity approved by
                                                  a Migration Authority using double wrapping */

/* 4.11 TCM_EK_TYPE rev 87 

   This structure indicates what type of information that the EK is dealing with.
*/

#define TCM_EK_TYPE_ACTIVATE    0x0001  /* The blob MUST be TCM_EK_BLOB_ACTIVATE */
#define TCM_EK_TYPE_AUTH        0x0002  /* The blob MUST be TCM_EK_BLOB_AUTH */

/* 4.12 TCM_PLATFORM_SPECIFIC rev 87

   This enumerated type indicates the platform specific spec that the information relates to.
*/

#define TCM_PS_PC_11            0x0001  /* PC Specific version 1.1 */
#define TCM_PS_PC_12            0x0002  /* PC Specific version 1.2 */
#define TCM_PS_PDA_12           0x0003  /* PDA Specific version 1.2 */
#define TCM_PS_Server_12        0x0004  /* Server Specific version 1.2 */
#define TCM_PS_Mobile_12        0x0005  /* Mobil Specific version 1.2 */

/* 5.8 TCM_KEY_USAGE rev 101

   This table defines the types of keys that are possible.  Each value defines for what operation
   the key can be used.  Most key usages can be CMKs.  See 4.2, TCM_PAYLOAD_TYPE.

   Each key has a setting defining the encryption and signature scheme to use. The selection of a
   key usage value limits the choices of encryption and signature schemes.
*/

#define TCM_KEY_UNINITIALIZED   0x0000  /* NOTE: Added.  This seems like a good place to indicate
                                           that a TCM_KEY structure has not been initialized */

#define TCM_KEY_SIGNING         0x0010  /* This SHALL indicate a signing key. The [private] key
                                           SHALL be used for signing operations, only. This means
                                           that it MUST be a leaf of the Protected Storage key
                                           hierarchy. */

#define TCM_KEY_STORAGE         0x0011  /* This SHALL indicate a storage key. The key SHALL be used
                                           to wrap and unwrap other keys in the Protected Storage
                                           hierarchy */

#define TCM_KEY_IDENTITY        0x0012  /* This SHALL indicate an identity key. The key SHALL be
                                           used for operations that require a TCM identity, only. */

#define TCM_KEY_AUTHCHANGE      0X0013  /* This SHALL indicate an ephemeral key that is in use
                                           during the ChangeAuthAsym process, only. */

#define TCM_KEY_BIND            0x0014  /* This SHALL indicate a key that can be used for TCM_Bind
                                           and TCM_Unbind operations only. */

#define TCM_KEY_LEGACY          0x0015  /* This SHALL indicate a key that can perform signing and
                                           binding operations. The key MAY be used for both signing
                                           and binding operations. The TCM_KEY_LEGACY key type is to
                                           allow for use by applications where both signing and
                                           encryption operations occur with the same key. */

#define TCM_KEY_MIGRATE         0x0016  /* This SHALL indicate a key in use for TCM_MigrateKey */

#define TCM_SM2KEY_SIGNING      0x0010  

#define TCM_SM2KEY_STORAGE      0x0011
#define TCM_SM2KEY_IDENTITY     0x0012
#define TCM_SM2KEY_BIND		0x0014  
#define TCM_SM2KEY_MIGRATE	0x0016  
#define TCM_SM2KEY_PEK		0x0017 
#define TCM_SM4KEY_STORAGE	0x0018  
#define TCM_SM4KEY_BIND		0x0019  
#define TCM_SM4KEY_MIGRATE	0x001a  

/* 5.8.1 TCM_ENC_SCHEME Mandatory Key Usage Schemes rev 99

   The TCM MUST check that the encryption scheme defined for use with the key is a valid scheme for
   the key type, as follows:
*/

#define TCM_ES_SM2                      0x0002 
#define TCM_ES_NONE             	0x0004 
#define TCM_ES_SM4_CBC		        0x0006 
#define TCM_ES_SM4_ECB                  0x0008 


/* 5.8.1 TCM_SIG_SCHEME Mandatory Key Usage Schemes rev 99

   The TCM MUST check that the signature scheme defined for use with the key is a valid scheme for
   the key type, as follows:
*/

#define TCM_SS_NONE                  0x0001 
#define TCM_SS_SM2                      0x0005 

/* 5.9 TCM_AUTH_DATA_USAGE rev 110

   The indication to the TCM when authorization sessions for an entity are required.  Future
   versions may allow for more complex decisions regarding AuthData checking.
*/

#define TCM_AUTH_NEVER         0x00 /* This SHALL indicate that usage of the key without
                                       authorization is permitted. */

#define TCM_AUTH_ALWAYS        0x01 /* This SHALL indicate that on each usage of the key the
                                       authorization MUST be performed. */

#define TCM_NO_READ_PUBKEY_AUTH 0x03 /* This SHALL indicate that on commands that require the TCM to
                                       use the the key, the authorization MUST be performed. For
                                       commands that cause the TCM to read the public portion of the
                                       key, but not to use the key (e.g. TCM_GetPubKey), the
                                       authorization may be omitted. */

/* 5.10 TCM_KEY_FLAGS rev 110

   This table defines the meanings of the bits in a TCM_KEY_FLAGS structure, used in
   TCM_STORE_ASYMKEY and TCM_CERTIFY_INFO.
   
   The value of TCM_KEY_FLAGS MUST be decomposed into individual mask values. The presence of a mask
   value SHALL have the effect described in the above table
   
   On input, all undefined bits MUST be zero. The TCM MUST return an error if any undefined bit is
   set. On output, the TCM MUST set all undefined bits to zero.
*/

#ifdef TCM_V12
#define TCM_KEY_FLAGS_MASK      0x0000001f
#else
#define TCM_KEY_FLAGS_MASK      0x00000007
#endif

#define TCM_REDIRECTION         0x00000001 /* This mask value SHALL indicate the use of redirected
                                              output. */

#define TCM_MIGRATABLE          0x00000002 /* This mask value SHALL indicate that the key is
                                              migratable. */

#define TCM_ISVOLATILE          0x00000004 /* This mask value SHALL indicate that the key MUST be
                                              unloaded upon execution of the
                                              TCM_Startup(ST_Clear). This does not indicate that a
                                              non-volatile key will remain loaded across
                                              TCM_Startup(ST_Clear) events. */

#define TCM_PCRIGNOREDONREAD    0x00000008 /* When TRUE the TCM MUST NOT check digestAtRelease or
                                              localityAtRelease for commands that read the public
                                              portion of the key (e.g., TCM_GetPubKey) and MAY NOT
                                              check digestAtRelease or localityAtRelease for
                                              commands that use the public portion of the key
                                              (e.g. TCM_Seal)

                                              When FALSE the TCM MUST check digestAtRelease and
                                              localityAtRelease for commands that read or use the
                                              public portion of the key */

#define TCM_MIGRATEAUTHORITY    0x00000010 /* When set indicates that the key is under control of a
                                              migration authority. The TCM MUST only allow the
                                              creation of a key with this flag in
                                              TCM_MA_CreateKey */

/* 5.17 TCM_CMK_DELEGATE values rev 89

   The bits of TCM_CMK_DELEGATE are flags that determine how the TCM responds to delegated requests
   to manipulate a certified-migration-key, a loaded key with payload type TCM_PT_MIGRATE_RESTRICTED
   or TCM_PT_MIGRATE_EXTERNAL..

   26:0 reserved MUST be 0

   The default value of TCM_CMK_Delegate is zero (0)
*/

#define TCM_CMK_DELEGATE_SIGNING        0x80000000 /* When set to 1, this bit SHALL indicate that a
                                                      delegated command may manipulate a CMK of
                                                      TCM_KEY_USAGE == TCM_KEY_SIGNING */
#define TCM_CMK_DELEGATE_STORAGE        0x40000000 /* When set to 1, this bit SHALL indicate that a
                                                      delegated command may manipulate a CMK of
                                                      TCM_KEY_USAGE == TCM_KEY_STORAGE */
#define TCM_CMK_DELEGATE_BIND           0x20000000 /* When set to 1, this bit SHALL indicate that a
                                                      delegated command may manipulate a CMK of
                                                      TCM_KEY_USAGE == TCM_KEY_BIND */
#define TCM_CMK_DELEGATE_LEGACY         0x10000000 /* When set to 1, this bit SHALL indicate that a
                                                      delegated command may manipulate a CMK of
                                                      TCM_KEY_USAGE == TCM_KEY_LEGACY */
#define TCM_CMK_DELEGATE_MIGRATE        0x08000000 /* When set to 1, this bit SHALL indicate that a
                                                      delegated command may manipulate a CMK of
                                                      TCM_KEY_USAGE == TCM_KEY_MIGRATE */

/* 6. TCM_TAG (Command and Response Tags) rev 100

   These tags indicate to the TCM the construction of the command either as input or as output. The
   AUTH indicates that there are one or more AuthData values that follow the command
   parameters.
*/

#define TCM_TAG_RQU_COMMAND             0x00C1 /* A command with no authentication.  */
#define TCM_TAG_RQU_AUTH1_COMMAND       0x00C2 /* An authenticated command with one authentication
                                                  handle */
#define TCM_TAG_RQU_AUTH2_COMMAND       0x00C3 /* An authenticated command with two authentication
                                                  handles */
#define TCM_TAG_RSP_COMMAND             0x00C4 /* A response from a command with no authentication
                                                */
#define TCM_TAG_RSP_AUTH1_COMMAND       0x00C5 /* An authenticated response with one authentication
                                                  handle */
#define TCM_TAG_RSP_AUTH2_COMMAND       0x00C6 /* An authenticated response with two authentication
                                                  handles */
/* TIS 7.2 PCR Attributes

*/

#define TCM_DEBUG_PCR 		16
#define TCM_LOCALITY_4_PCR	17
#define TCM_LOCALITY_3_PCR	18
#define TCM_LOCALITY_2_PCR	19
#define TCM_LOCALITY_1_PCR	20

/* 10.9 TCM_KEY_CONTROL rev 87

   Attributes that can control various aspects of key usage and manipulation.

   Allows for controlling of the key when loaded and how to handle TCM_Startup issues.
*/

#define TCM_KEY_CONTROL_OWNER_EVICT     0x00000001      /* Owner controls when the key is evicted
                                                           from the TCM. When set the TCM MUST
                                                           preserve key the key across all TCM_Init
                                                           invocations. */

/* 13.1.1 TCM_TRANSPORT_ATTRIBUTES Definitions */

#define TCM_TRANSPORT_ENCRYPT           0x00000001      /* The session will provide encryption using
                                                           the internal encryption algorithm */
#define TCM_TRANSPORT_LOG               0x00000002      /* The session will provide a log of all
                                                           operations that occur in the session */
#define TCM_TRANSPORT_EXCLUSIVE         0X00000004      /* The transport session is exclusive and
                                                           any command executed outside the
                                                           transport session causes the invalidation
                                                           of the session */

/* 21.1 TCM_CAPABILITY_AREA rev 115

   To identify a capability to be queried. 
*/

#define TCM_CAP_ORD             0x00000001 /* Boolean value. TRUE indicates that the TCM supports
                                              the ordinal. FALSE indicates that the TCM does not
                                              support the ordinal.  Unimplemented optional ordinals
                                              and unused (unassigned) ordinals return FALSE. */
#define TCM_CAP_ALG             0x00000002 /* Boolean value. TRUE means that the TCM supports the
                                              asymmetric algorithm for TCM_Sign, TCM_Seal,
                                              TCM_UnSeal and TCM_UnBind and related commands. FALSE
                                              indicates that the asymmetric algorithm is not
                                              supported for these types of commands. The TCM MAY
                                              return TRUE or FALSE for other than asymmetric
                                              algoroithms that it supports. Unassigned and
                                              unsupported algorithm IDs return FALSE.*/

#define TCM_CAP_PID             0x00000003 /* Boolean value. TRUE indicates that the TCM supports
                                              the protocol, FALSE indicates that the TCM does not
                                              support the protocol.  */
#define TCM_CAP_FLAG            0x00000004 /* Return the TCM_PERMANENT_FLAGS structure or Return the
                                              TCM_STCLEAR_FLAGS structure */
#define TCM_CAP_PROPERTY        0x00000005 /* See following table for the subcaps */
#define TCM_CAP_VERSION         0x00000006 /* TCM_STRUCT_VER structure. The Major and Minor must
                                              indicate 1.1. The firmware revision MUST indicate
                                              0.0 */
#define TCM_CAP_KEY_HANDLE      0x00000007 /* A TCM_KEY_HANDLE_LIST structure that enumerates all
                                              key handles loaded on the TCM.  */
#define TCM_CAP_CHECK_LOADED    0x00000008 /* A Boolean value. TRUE indicates that the TCM has
                                              enough memory available to load a key of the type
                                              specified by TCM_KEY_PARMS. FALSE indicates that the
                                              TCM does not have enough memory.  */
#define TCM_CAP_SYM_MODE        0x00000009 /* Subcap TCM_SYM_MODE
                                              A Boolean value. TRUE indicates that the TCM supports
                                              the TCM_SYM_MODE, FALSE indicates the TCM does not
                                              support the mode. */
#define TCM_CAP_KEY_STATUS      0x0000000C /* Boolean value of ownerEvict. The handle MUST point to
                                              a valid key handle.*/
#define TCM_CAP_NV_LIST         0x0000000D /* A list of TCM_NV_INDEX values that are currently
                                              allocated NV storage through TCM_NV_DefineSpace. */
#define TCM_CAP_MFR             0x00000010 /* Manufacturer specific. The manufacturer may provide
                                              any additional information regarding the TCM and the
                                              TCM state but MUST not expose any sensitive
                                              information.  */
#define TCM_CAP_NV_INDEX        0x00000011 /* A TCM_NV_DATA_PUBLIC structure that indicates the
                                              values for the TCM_NV_INDEX.  Returns TCM_BADINDEX if
                                              the index is not in the TCM_CAP_NV_LIST list. */
#define TCM_CAP_TRANS_ALG       0x00000012 /* Boolean value. TRUE means that the TCM supports the
                                              algorithm for TCM_EstablishTransport,
                                              TCM_ExecuteTransport and
                                              TCM_ReleaseTransportSigned. FALSE indicates that for
                                              these three commands the algorithm is not supported."
                                              */
#define TCM_CAP_HANDLE          0x00000014 /* A TCM_KEY_HANDLE_LIST structure that enumerates all
                                              handles currently loaded in the TCM for the given
                                              resource type.  */
#define TCM_CAP_TRANS_ES        0x00000015 /* Boolean value. TRUE means the TCM supports the
                                              encryption scheme in a transport session for at least
                                              one algorithm..  */
#define TCM_CAP_AUTH_ENCRYPT    0x00000017 /* Boolean value. TRUE indicates that the TCM supports
                                              the encryption algorithm in OSAP encryption of
                                              AuthData values */
#define TCM_CAP_SELECT_SIZE     0x00000018 /* Boolean value. TRUE indicates that the TCM supports
                                              the size for the given version. For instance a request
                                              could ask for version 1.1 size 2 and the TCM would
                                              indicate TRUE. For 1.1 size 3 the TCM would indicate
                                              FALSE. For 1.2 size 3 the TCM would indicate TRUE. */
#define TCM_CAP_DA_LOGIC        0x00000019 /* (OPTIONAL)
                                              A TCM_DA_INFO or TCM_DA_INFO_LIMITED structure that
                                              returns data according to the selected entity type
                                              (e.g., TCM_ET_KEYHANDLE, TCM_ET_OWNER, TCM_ET_SRK,
                                              TCM_ET_COUNTER, TCM_ET_OPERATOR, etc.). If the
                                              implemented dictionary attack logic does not support
                                              different secret types, the entity type can be
                                              ignored. */
#define TCM_CAP_VERSION_VAL     0x0000001A /* TCM_CAP_VERSION_INFO structure. The TCM fills in the
                                              structure and returns the information indicating what
                                              the TCM currently supports. */

#define TCM_CAP_FLAG_PERMANENT  0x00000108 /* Return the TCM_PERMANENT_FLAGS structure */
#define TCM_CAP_FLAG_VOLATILE   0x00000109 /* Return the TCM_STCLEAR_FLAGS structure */

/* 21.2 CAP_PROPERTY Subcap values for CAP_PROPERTY rev 105

   The TCM_CAP_PROPERTY capability has numerous subcap values.  The definition for all subcap values
   occurs in this table.

   TCM_CAP_PROP_MANUFACTURER returns a vendor ID unique to each manufacturer. The same value is
   returned as the TCM_CAP_VERSION_INFO -> tcmVendorID.  A company abbreviation such as a null
   terminated stock ticker is a typical choice. However, there is no requirement that the value
   contain printable characters.  The document "TCG Vendor Naming" lists the vendor ID values.

   TCM_CAP_PROP_MAX_xxxSESS is a constant.  At TCM_Startup(ST_CLEAR) TCM_CAP_PROP_xxxSESS ==
   TCM_CAP_PROP_MAX_xxxSESS.  As sessions are created on the TCM, TCM_CAP_PROP_xxxSESS decreases
   toward zero.  As sessions are terminated, TCM_CAP_PROP_xxxSESS increases toward
   TCM_CAP_PROP_MAX_xxxSESS.

   There is a similar relationship between the constants TCM_CAP_PROP_MAX_COUNTERS and
   TCM_CAP_PROP_MAX_CONTEXT and the varying TCM_CAP_PROP_COUNTERS and TCM_CAP_PROP_CONTEXT.
   
   In one typical implementation where authorization and transport sessions reside in separate
   pools, TCM_CAP_PROP_SESSIONS will be the sum of TCM_CAP_PROP_AUTHSESS and TCM_CAP_PROP_TRANSESS.
   In another typical implementation where authorization and transport sessions share the same pool,
   TCM_CAP_PROP_SESSIONS, TCM_CAP_PROP_AUTHSESS, and TCM_CAP_PROP_TRANSESS will all be equal.
*/

#define TCM_CAP_PROP_PCR                0x00000101    /* uint32_t value. Returns the number of PCR
                                                         registers supported by the TCM */
#define TCM_CAP_PROP_DIR                0x00000102    /* uint32_t. Deprecated. Returns the number of
                                                         DIR, which is now fixed at 1 */
#define TCM_CAP_PROP_MANUFACTURER       0x00000103    /* uint32_t value.  Returns the vendor ID
                                                         unique to each TCM manufacturer. */
#define TCM_CAP_PROP_KEYS               0x00000104    /* uint32_t value. Returns the number of 2048-
                                                         bit RSA keys that can be loaded. This may
                                                         vary with time and circumstances. */
#define TCM_CAP_PROP_MIN_COUNTER        0x00000107    /* uint32_t. The minimum amount of time in
                                                         10ths of a second that must pass between
                                                         invocations of incrementing the monotonic
                                                         counter. */
#define TCM_CAP_PROP_AUTHSESS           0x0000010A    /* uint32_t. The number of available
                                                         authorization sessions. This may vary with
                                                         time and circumstances. */
#define TCM_CAP_PROP_TRANSESS           0x0000010B    /* uint32_t. The number of available transport
                                                         sessions. This may vary with time and
                                                         circumstances.  */
#define TCM_CAP_PROP_COUNTERS           0x0000010C    /* uint32_t. The number of available monotonic
                                                         counters. This may vary with time and
                                                         circumstances. */
#define TCM_CAP_PROP_MAX_AUTHSESS       0x0000010D    /* uint32_t. The maximum number of loaded
                                                         authorization sessions the TCM supports */
#define TCM_CAP_PROP_MAX_TRANSESS       0x0000010E    /* uint32_t. The maximum number of loaded
                                                         transport sessions the TCM supports. */
#define TCM_CAP_PROP_MAX_COUNTERS       0x0000010F    /* uint32_t. The maximum number of monotonic
                                                         counters under control of TCM_CreateCounter
                                                         */
#define TCM_CAP_PROP_MAX_KEYS           0x00000110    /* uint32_t. The maximum number of 2048 RSA
                                                         keys that the TCM can support. The number
                                                         does not include the EK or SRK. */
#define TCM_CAP_PROP_OWNER              0x00000111    /* BOOL. A value of TRUE indicates that the
                                                         TCM has successfully installed an owner. */
#define TCM_CAP_PROP_CONTEXT            0x00000112    /* uint32_t. The number of available saved
                                                         session slots. This may vary with time and
                                                         circumstances. */
#define TCM_CAP_PROP_MAX_CONTEXT        0x00000113    /* uint32_t. The maximum number of saved
                                                         session slots. */
#define TCM_CAP_PROP_FAMILYROWS         0x00000114    /* uint32_t. The maximum number of rows in the
                                                         family table */
#define TCM_CAP_PROP_TIS_TIMEOUT        0x00000115    /* A 4 element array of uint32_t values each
                                                         denoting the timeout value in microseconds
                                                         for the following in this order:
                                                         
                                                         TIMEOUT_A, TIMEOUT_B, TIMEOUT_C, TIMEOUT_D 

                                                         Where these timeouts are to be used is
                                                         determined by the platform specific TCM
                                                         Interface Specification. */
#define TCM_CAP_PROP_STARTUP_EFFECT     0x00000116    /* The TCM_STARTUP_EFFECTS structure */
#define TCM_CAP_PROP_DELEGATE_ROW       0x00000117    /* uint32_t. The maximum size of the delegate
                                                         table in rows. */
#define TCM_CAP_PROP_MAX_DAASESS        0x00000119    /* uint32_t. The maximum number of loaded DAA
                                                         sessions (join or sign) that the TCM
                                                         supports */
#define TCM_CAP_PROP_DAASESS            0x0000011A    /* uint32_t. The number of available DAA
                                                         sessions. This may vary with time and
                                                         circumstances */
#define TCM_CAP_PROP_CONTEXT_DIST       0x0000011B    /* uint32_t. The maximum distance between
                                                         context count values. This MUST be at least
                                                         2^16-1. */
#define TCM_CAP_PROP_DAA_INTERRUPT      0x0000011C    /* BOOL. A value of TRUE indicates that the
                                                         TCM will accept ANY command while executing
                                                         a DAA Join or Sign.

                                                         A value of FALSE indicates that the TCM
                                                         will invalidate the DAA Join or Sign upon
                                                         the receipt of any command other than the
                                                         next join/sign in the session or a
                                                         TCM_SaveContext */
#define TCM_CAP_PROP_SESSIONS           0X0000011D    /* uint32_t. The number of available sessions
                                                         from the pool. This MAY vary with time and
                                                         circumstances. Pool sessions include
                                                         authorization and transport sessions. */
#define TCM_CAP_PROP_MAX_SESSIONS       0x0000011E    /* uint32_t. The maximum number of sessions
                                                         the TCM supports. */
#define TCM_CAP_PROP_CMK_RESTRICTION    0x0000011F    /* uint32_t TCM_Permanent_Data ->
                                                         restrictDelegate
                                                       */
#define TCM_CAP_PROP_DURATION           0x00000120    /* A 3 element array of uint32_t values each
                                                         denoting the duration value in microseconds
                                                         of the duration of the three classes of
                                                         commands: Small, Medium and Long in the
                                                         following in this order: SMALL_DURATION,
                                                         MEDIUM_DURATION, LONG_DURATION */
#define TCM_CAP_PROP_ACTIVE_COUNTER     0x00000122      /* TCM_COUNT_ID. The id of the current
                                                           counter. 0xff..ff if no counter is active
                                                        */
#define TCM_CAP_PROP_MAX_NV_AVAILABLE   0x00000123      /*uint32_t. Deprecated.  The maximum number
                                                          of NV space that can be allocated, MAY
                                                          vary with time and circumstances.  This
                                                          capability was not implemented
                                                          consistently, and is replaced by
                                                          TCM_NV_INDEX_TRIAL. */
#define TCM_CAP_PROP_INPUT_BUFFER       0x00000124      /* uint32_t. The maximum size of the TCM
                                                           input buffer or output buffer in
                                                           bytes. */

/* 21.4 Set_Capability Values rev 107
 */
   
#define TCM_SET_PERM_FLAGS      0x00000001      /* The ability to set a value is field specific and
                                                   a review of the structure will disclose the
                                                   ability and requirements to set a value */
#define TCM_SET_PERM_DATA       0x00000002      /* The ability to set a value is field specific and
                                                   a review of the structure will disclose the
                                                   ability and requirements to set a value */
#define TCM_SET_STCLEAR_FLAGS   0x00000003      /* The ability to set a value is field specific and
                                                   a review of the structure will disclose the
                                                   ability and requirements to set a value */
#define TCM_SET_STCLEAR_DATA    0x00000004      /* The ability to set a value is field specific and
                                                   a review of the structure will disclose the
                                                   ability and requirements to set a value */
#define TCM_SET_STANY_FLAGS     0x00000005      /* The ability to set a value is field specific and
                                                   a review of the structure will disclose the
                                                   ability and requirements to set a value */
#define TCM_SET_STANY_DATA      0x00000006      /* The ability to set a value is field specific and
                                                   a review of the structure will disclose the
                                                   ability and requirements to set a value */
#define TCM_SET_VENDOR          0x00000007      /* This area allows the vendor to set specific areas
                                                   in the TCM according to the normal shielded
                                                   location requirements */

/* Set Capability sub caps */

/* TCM_PERMANENT_FLAGS */

#define  TCM_PF_DISABLE                         1
#define  TCM_PF_OWNERSHIP                       2
#define  TCM_PF_DEACTIVATED                     3
#define  TCM_PF_READPUBEK                       4
#define  TCM_PF_DISABLEOWNERCLEAR               5
#define  TCM_PF_ALLOWMAINTENANCE                6
#define  TCM_PF_PHYSICALPRESENCELIFETIMELOCK    7
#define  TCM_PF_PHYSICALPRESENCEHWENABLE        8
#define  TCM_PF_PHYSICALPRESENCECMDENABLE       9
#define  TCM_PF_CEKPUSED                        10
#define  TCM_PF_TCMPOST                         11
#define  TCM_PF_TCMPOSTLOCK                     12
#define  TCM_PF_FIPS                            13
#define  TCM_PF_OPERATOR                        14
#define  TCM_PF_ENABLEREVOKEEK                  15
#define  TCM_PF_NV_LOCKED                       16
#define  TCM_PF_READSRKPUB                      17
#define  TCM_PF_TCMESTABLISHED                  18
#define  TCM_PF_MAINTENANCEDONE                 19
#define  TCM_PF_DISABLEFULLDALOGICINFO          20

/* TCM_STCLEAR_FLAGS */

#define  TCM_SF_DEACTIVATED                     1
#define  TCM_SF_DISABLEFORCECLEAR               2
#define  TCM_SF_PHYSICALPRESENCE                3
#define  TCM_SF_PHYSICALPRESENCELOCK            4
#define  TCM_SF_BGLOBALLOCK                     5
                                                
/* TCM_STANY_FLAGS */                           
                                                
#define  TCM_AF_POSTINITIALISE                  1
#define  TCM_AF_LOCALITYMODIFIER                2
#define  TCM_AF_TRANSPORTEXCLUSIVE              3
#define  TCM_AF_TOSPRESENT                      4
                                                
/* TCM_PERMANENT_DATA */                        
                                                
#define  TCM_PD_REVMAJOR                        1
#define  TCM_PD_REVMINOR                        2
#define  TCM_PD_TCMPROOF                        3
#define  TCM_PD_OWNERAUTH                       4
#define  TCM_PD_OPERATORAUTH                    5
#define  TCM_PD_MANUMAINTPUB                    6
#define  TCM_PD_ENDORSEMENTKEY                  7
#define  TCM_PD_SRK                             8
#define  TCM_PD_DELEGATEKEY                     9
#define  TCM_PD_CONTEXTKEY                      10
#define  TCM_PD_AUDITMONOTONICCOUNTER           11
#define  TCM_PD_MONOTONICCOUNTER                12
#define  TCM_PD_PCRATTRIB                       13
#define  TCM_PD_ORDINALAUDITSTATUS              14
#define  TCM_PD_AUTHDIR                         15
#define  TCM_PD_RNGSTATE                        16
#define  TCM_PD_FAMILYTABLE                     17
#define  TCM_DELEGATETABLE                      18
#define  TCM_PD_EKRESET                         19
#define  TCM_PD_LASTFAMILYID                    21
#define  TCM_PD_NOOWNERNVWRITE                  22
#define  TCM_PD_RESTRICTDELEGATE                23
#define  TCM_PD_TCMDAASEED                      24
#define  TCM_PD_DAAPROOF                        25
                                                
/* TCM_STCLEAR_DATA */                          
                                                
#define  TCM_SD_CONTEXTNONCEKEY                 1
#define  TCM_SD_COUNTID                         2
#define  TCM_SD_OWNERREFERENCE                  3
#define  TCM_SD_DISABLERESETLOCK                4
#define  TCM_SD_PCR                             5
#define  TCM_SD_DEFERREDPHYSICALPRESENCE        6

/* TCM_STCLEAR_DATA -> deferredPhysicalPresence bits */

#define  TCM_DPP_UNOWNED_FIELD_UPGRADE  0x00000001      /* bit 0 TCM_FieldUpgrade */
                                
/* TCM_STANY_DATA */                            
                                                
#define  TCM_AD_CONTEXTNONCESESSION             1
#define  TCM_AD_AUDITDIGEST                     2
#define  TCM_AD_CURRENTTICKS                    3
#define  TCM_AD_CONTEXTCOUNT                    4
#define  TCM_AD_CONTEXTLIST                     5
#define  TCM_AD_SESSIONS                        6

/*  17. Ordinals rev 110

    Ordinals are 32 bit values of type TCM_COMMAND_CODE. The upper byte contains values that serve
    as flag indicators, the next byte contains values indicating what committee designated the
    ordinal, and the final two bytes contain the Command Ordinal Index.

       3                   2                   1 
     1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |P|C|V| Reserved|    Purview    |     Command Ordinal Index     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 

    Where: 

    P is Protected/Unprotected command. When 0 the command is a Protected command, when 1 the
    command is an Unprotected command.

    C is Non-Connection/Connection related command. When 0 this command passes through to either the
    protected (TCM) or unprotected (TSS) components.

    V is TCM/Vendor command. When 0 the command is TCM defined, when 1 the command is vendor
    defined.

    All reserved area bits are set to 0. 
*/

/* The following masks are created to allow for the quick definition of the commands */

#define TCM_PROTECTED_COMMAND   0x00000000 /* TCM protected command, specified in main specification
                                            */
#define TCM_UNPROTECTED_COMMAND 0x80000000 /* TSS command, specified in the TSS specification */
#define TCM_CONNECTION_COMMAND  0x40000000 /* TSC command, protected connection commands are
                                              specified in the main specification Unprotected
                                              connection commands are specified in the TSS */
#define TCM_VENDOR_COMMAND      0x20000000 /* Command that is vendor specific for a given TCM or
                                              TSS.  */


/* The following Purviews have been defined: */

#define TCM_MAIN        0x00 /* Command is from the main specification  */
#define TCM_PC          0x01 /* Command is specific to the PC  */
#define TCM_PDA         0x02 /* Command is specific to a PDA  */
#define TCM_CELL_PHONE  0x03 /* Command is specific to a cell phone  */
#define TCM_SERVER      0x04 /* Command is specific to servers  */
#define TCM_PERIPHERAL  0x05 /* Command is specific to peripherals */
#define TCM_TSS         0x06 /* Command is specific to TSS */

/* Combinations for the main specification would be:   */

#define TCM_PROTECTED_ORDINAL   (TCM_PROTECTED_COMMAND   | TCM_MAIN)
#define TCM_UNPROTECTED_ORDINAL (TCM_UNPROTECTED_COMMAND | TCM_MAIN)
#define TCM_CONNECTION_ORDINAL  (TCM_CONNECTION_COMMAND  | TCM_MAIN)

/* Command ordinals */

#define TCM_ORD_ActivateIdentity                0x0000007A
#define TCM_ORD_AuthorizeMigrationKey           0x0000002B
#define TCM_ORD_CertifyKey                      0x00000032
#define TCM_ORD_CertifyKey2                     0x00000033
#define TCM_ORD_CertifySelfTest                 0x00000052
#define TCM_ORD_ChangeAuth                      0x0000000C
#define TCM_ORD_ChangeAuthAsymFinish            0x0000000F
#define TCM_ORD_ChangeAuthAsymStart             0x0000000E
#define TCM_ORD_ChangeAuthOwner                 0x00000010
#define TCM_ORD_CMK_ApproveMA                   0x0000001D
#define TCM_ORD_CMK_ConvertMigration            0x00000024
#define TCM_ORD_CMK_CreateBlob                  0x0000001B
#define TCM_ORD_CMK_CreateKey                   0x00000013
#define TCM_ORD_CMK_CreateTicket                0x00000012
#define TCM_ORD_CMK_SetRestrictions             0x0000001C
#define TCM_ORD_ContinueSelfTest                0x00000053
#define TCM_ORD_ConvertMigrationBlob            0x0000002A
#define TCM_ORD_CreateCounter                   0x000000DC
#define TCM_ORD_CreateEndorsementKeyPair        0x00000078
#define TCM_ORD_CreateMaintenanceArchive        0x0000002C
#define TCM_ORD_CreateMigrationBlob             0x00000028
#define TCM_ORD_CreateRevocableEK               0x0000007F
#define TCM_ORD_CreateWrapKey                   0x0000001F
#define TCM_ORD_DAA_Join                        0x00000029
#define TCM_ORD_DAA_Sign                        0x00000031
#define TCM_ORD_Delegate_CreateKeyDelegation    0x000000D4
#define TCM_ORD_Delegate_CreateOwnerDelegation  0x000000D5
#define TCM_ORD_Delegate_LoadOwnerDelegation    0x000000D8
#define TCM_ORD_Delegate_Manage                 0x000000D2
#define TCM_ORD_Delegate_ReadTable              0x000000DB
#define TCM_ORD_Delegate_UpdateVerification     0x000000D1
#define TCM_ORD_Delegate_VerifyDelegation       0x000000D6
#define TCM_ORD_DirRead                         0x0000001A
#define TCM_ORD_DirWriteAuth                    0x00000019
#define TCM_ORD_DisableForceClear               0x0000005E
#define TCM_ORD_DisableOwnerClear               0x0000005C
#define TCM_ORD_DisablePubekRead                0x0000007E
#define TCM_ORD_DSAP                            0x00000011
#define TCM_ORD_EstablishTransport              0x000000E6
#define TCM_ORD_EvictKey                        0x00000022
#define TCM_ORD_ExecuteTransport                0x000000E7
#define TCM_ORD_Extend                          0x00000014
#define TCM_ORD_FieldUpgrade                    0x000000AA
#define TCM_ORD_FlushSpecific                   0x000000BA
#define TCM_ORD_ForceClear                      0x0000005D
#define TCM_ORD_GetAuditDigest                  0x00000085
#define TCM_ORD_GetAuditDigestSigned            0x00000086
#define TCM_ORD_GetAuditEvent                   0x00000082
#define TCM_ORD_GetAuditEventSigned             0x00000083
#define TCM_ORD_GetCapability                   0x00000065
#define TCM_ORD_GetCapabilityOwner              0x00000066
#define TCM_ORD_GetCapabilitySigned             0x00000064
#define TCM_ORD_GetOrdinalAuditStatus           0x0000008C
#define TCM_ORD_GetPubKey                       0x00000021
#define TCM_ORD_GetRandom                       0x00000046
#define TCM_ORD_GetTestResult                   0x00000054
#define TCM_ORD_GetTicks                        0x000000F1
#define TCM_ORD_IncrementCounter                0x000000DD
#define TCM_ORD_Init                            0x00000097
#define TCM_ORD_KeyControlOwner                 0x00000023
#define TCM_ORD_KillMaintenanceFeature          0x0000002E
#define TCM_ORD_LoadAuthContext                 0x000000B7
#define TCM_ORD_LoadContext                     0x000000B9
#define TCM_ORD_LoadKey                         0x00000020
#define TCM_ORD_LoadKey2                        0x00000041
#define TCM_ORD_LoadKeyContext                  0x000000B5
#define TCM_ORD_LoadMaintenanceArchive          0x0000002D
#define TCM_ORD_LoadManuMaintPub                0x0000002F
#define TCM_ORD_MakeIdentity                    0x00000079
#define TCM_ORD_MigrateKey                      0x00000025
#define TCM_ORD_NV_DefineSpace                  0x000000CC
#define TCM_ORD_NV_ReadValue                    0x000000CF
#define TCM_ORD_NV_ReadValueAuth                0x000000D0
#define TCM_ORD_NV_WriteValue                   0x000000CD
#define TCM_ORD_NV_WriteValueAuth               0x000000CE
#define TCM_ORD_APCreate                        0x0000000A
#define TCM_ORD_OSAP                            0x0000000B
#define TCM_ORD_OwnerClear                      0x0000005B
#define TCM_ORD_OwnerReadInternalPub            0x00000081
#define TCM_ORD_OwnerReadPubek                  0x0000007D
#define TCM_ORD_OwnerSetDisable                 0x0000006E
#define TCM_ORD_PCR_Reset                       0x000000C8
#define TCM_ORD_PcrRead                         0x00000015
#define TCM_ORD_PhysicalDisable                 0x00000070
#define TCM_ORD_PhysicalEnable                  0x0000006F
#define TCM_ORD_PhysicalSetDeactivated          0x00000072
#define TCM_ORD_Quote                           0x00000016
#define TCM_ORD_Quote2                          0x0000003E
#define TCM_ORD_ReadCounter                     0x000000DE
#define TCM_ORD_ReadManuMaintPub                0x00000030
#define TCM_ORD_ReadPubek                       0x0000007C
#define TCM_ORD_ReleaseCounter                  0x000000DF
#define TCM_ORD_ReleaseCounterOwner             0x000000E0
#define TCM_ORD_ReleaseTransportSigned          0x000000E8
#define TCM_ORD_Reset                           0x0000005A
#define TCM_ORD_ResetLockValue                  0x00000040
#define TCM_ORD_RevokeTrust                     0x00000080
#define TCM_ORD_SaveAuthContext                 0x000000B6
#define TCM_ORD_SaveContext                     0x000000B8
#define TCM_ORD_SaveKeyContext                  0x000000B4
#define TCM_ORD_SaveState                       0x00000098
#define TCM_ORD_Seal                            0x00000017
#define TCM_ORD_Sealx                           0x0000003D
#define TCM_ORD_SelfTestFull                    0x00000050
#define TCM_ORD_SetCapability                   0x0000003F
#define TCM_ORD_SetOperatorAuth                 0x00000074
#define TCM_ORD_SetOrdinalAuditStatus           0x0000008D
#define TCM_ORD_SetOwnerInstall                 0x00000071
#define TCM_ORD_SetOwnerPointer                 0x00000075
#define TCM_ORD_SetRedirection                  0x0000009A
#define TCM_ORD_SetTempDeactivated              0x00000073
#define TCM_ORD_SHA1Complete                    0x000000A2
#define TCM_ORD_SHA1CompleteExtend              0x000000A3
#define TCM_ORD_SHA1Start                       0x000000A0
#define TCM_ORD_SHA1Update                      0x000000A1
#define TCM_ORD_Sign                            0x0000003C
#define TCM_ORD_Startup                         0x00000099
#define TCM_ORD_StirRandom                      0x00000047
#define TCM_ORD_TakeOwnership                   0x0000000D
#define TCM_ORD_Terminate_Handle                0x00000096
#define TCM_ORD_TickStampBlob                   0x000000F2
#define TCM_ORD_UnBind                          0x0000001E
#define TCM_ORD_Unseal                          0x00000018

#define TSC_ORD_PhysicalPresence                0x4000000A
#define TSC_ORD_ResetEstablishmentBit           0x4000000B

/* 19. NV storage structures */

/* 19.1 TCM_NV_INDEX rev 110

     The index provides the handle to identify the area of storage. The reserved bits allow for a
     segregation of the index name space to avoid name collisions.

     The TCM may check the resvd bits for zero.  Thus, applications should set the bits to zero.

     The TCG defines the space where the high order bits (T, P, U) are 0. The other spaces are
     controlled by the indicated entity.

     T is the TCM manufacturer reserved bit. 0 indicates a TCG defined value. 1 indicates a TCM
     manufacturer specific value.

     P is the platform manufacturer reserved bit. 0 indicates a TCG defined value. 1 indicates that
     the index is controlled by the platform manufacturer.

     U is for the platform user. 0 indicates a TCG defined value. 1 indicates that the index is
     controlled by the platform user.

     The TCM_NV_INDEX is a 32-bit value.
     3                   2                   1
     1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |T|P|U|D| resvd |   Purview      |         Index                |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

     Where:

     1. The TCM MAY return an error if the reserved area bits are not set to 0.

     2. The TCM MUST accept all values for T, P, and U

     3. D indicates defined. 1 indicates that the index is permanently defined and that any
        TCM_NV_DefineSpace operation will fail after nvLocked is set TRUE.

     a. TCG reserved areas MAY have D set to 0 or 1
        
     4. Purview is the value used to indicate the platform specific area. This value is the
     same as used for command ordinals.

     a. The TCM MUST reject purview values that the TCM cannot support. This means that an
     index value for a PDA MUST be rejected by a TCM designed to work only on the PC Client.
*/

#define TCM_NV_INDEX_T_BIT              0x80000000
#define TCM_NV_INDEX_P_BIT              0x40000000
#define TCM_NV_INDEX_U_BIT              0x20000000
#define TCM_NV_INDEX_D_BIT              0x10000000
/* added kgold */
#define TCM_NV_INDEX_RESVD              0x0f000000
#define TCM_NV_INDEX_PURVIEW_BIT        16
#define TCM_NV_INDEX_PURVIEW_MASK       0x00ff0000

/* 19.1.1 Required TCM_NV_INDEX values rev 97

   The required index values must be found on each TCM regardless of platform. These areas are
   always present and do not require a TCM_DefineSpace command to allocate.

   A platform specific specification may add additional required index values for the platform.

   The TCM MUST reserve the space as indicated for the required index values
*/

#define TCM_NV_INDEX_LOCK  0xFFFFFFFF   /* This value turns on the NV authorization
                                           protections. Once executed all NV areas use the
                                           protections as defined. This value never resets.

                                           Attempting to execute TCM_NV_DefineSpace on this value
                                           with non-zero size MAY result in a TCM_BADINDEX
                                           response.
                                        */

#define TCM_NV_INDEX0      0x00000000   /* This value allows for the setting of the bGlobalLock
                                           flag, which is only reset on TCM_Startup(ST_Clear)

                                           Attempting to execute TCM_NV_WriteValue with a size other
                                           than zero MAY result in the TCM_BADINDEX error code.
                                        */

#define TCM_NV_INDEX_DIR   0x10000001   /* Size MUST be 20. This index points to the deprecated DIR
                                           command area from 1.1.  The TCM MUST map this reserved
                                           space to be the area operated on by the 1.1 DIR commands.
                                           */

/* 19.1.2 Reserved Index values rev 116

  The reserved values are defined to avoid index collisions. These values are not in each and every
  TCM.

  1. The reserved index values are to avoid index value collisions. 
  2. These index values require a TCM_DefineSpace to have the area for the index allocated 
  3. A platform specific specification MAY indicate that reserved values are required. 
  4. The reserved index values MAY have their D bit set by the TCM vendor to permanently
*/

#define TCM_NV_INDEX_TCM                0x0000Fxxx      /* Reserved for TCM use */
#define TCM_NV_INDEX_EKCert             0x0000F000      /* The Endorsement credential */

#define TCM_NV_INDEX_TCM_CC             0x0000F001      /* The TCM Conformance credential */
#define TCM_NV_INDEX_PlatformCert       0x0000F002      /* The platform credential */
#define TCM_NV_INDEX_Platform_CC        0x0000F003      /* The Platform conformance credential */
#define TCM_NV_INDEX_TRIAL              0x0000F004      /* To try TCM_NV_DefineSpace without
                                                           actually allocating NV space */

#if 0
#define TCM_NV_INDEX_PC                 0x0001xxxx      /* Reserved for PC Client use */
#define TCM_NV_INDEX_GPIO_xx            0x000116xx      /* Reserved for GPIO pins */
#define TCM_NV_INDEX_PDA                0x0002xxxx      /* Reserved for PDA use */
#define TCM_NV_INDEX_MOBILE             0x0003xxxx      /* Reserved for mobile use */
#define TCM_NV_INDEX_SERVER             0x0004xxxx      /* Reserved for Server use */
#define TCM_NV_INDEX_PERIPHERAL         0x0005xxxx      /* Reserved for peripheral use */
#define TCM_NV_INDEX_TSS                0x0006xxxx      /* Reserved for TSS use */
#define TCM_NV_INDEX_GROUP_RESV         0x00xxxxxx      /* Reserved for TCG WG use */
#endif                                 

#define TCM_NV_INDEX_GPIO_00            0x00011600      /* GPIO-Express-00 */

#define TCM_NV_INDEX_GPIO_START         0x00011600      /* Reserved for GPIO pins */
#define TCM_NV_INDEX_GPIO_END           0x000116ff      /* Reserved for GPIO pins */

/* 19.2 TCM_NV_ATTRIBUTES rev 99

   The attributes TCM_NV_PER_AUTHREAD and TCM_NV_PER_OWNERREAD cannot both be set to TRUE.
   Similarly, the attributes TCM_NV_PER_AUTHWRITE and TCM_NV_PER_OWNERWRITE cannot both be set to
   TRUE.
*/

#define TCM_NV_PER_READ_STCLEAR         0x80000000 /* 31: The value can be read until locked by a
                                                      read with a data size of 0.  It can only be
                                                      unlocked by TCM_Startup(ST_Clear) or a
                                                      successful write. Lock held for each area in
                                                      bReadSTClear. */
/* #define 30:19 Reserved */
#define TCM_NV_PER_AUTHREAD             0x00040000 /* 18: The value requires authorization to read
                                                      */
#define TCM_NV_PER_OWNERREAD            0x00020000 /* 17: The value requires TCM Owner authorization
                                                      to read. */
#define TCM_NV_PER_PPREAD               0x00010000 /* 16: The value requires physical presence to
                                                      read */
#define TCM_NV_PER_GLOBALLOCK           0x00008000 /* 15: The value is writable until a write to
                                                      index 0 is successful. The lock of this
                                                      attribute is reset by
                                                      TCM_Startup(ST_CLEAR). Lock held by SF ->
                                                      bGlobalLock */
#define TCM_NV_PER_WRITE_STCLEAR        0x00004000 /* 14: The value is writable until a write to
                                                      the specified index with a datasize of 0 is
                                                      successful. The lock of this attribute is
                                                      reset by TCM_Startup(ST_CLEAR). Lock held for
                                                      each area in bWriteSTClear. */
#define TCM_NV_PER_WRITEDEFINE          0x00002000 /* 13: Lock set by writing to the index with a
                                                      datasize of 0. Lock held for each area in
                                                      bWriteDefine.  This is a persistent lock. */
#define TCM_NV_PER_WRITEALL             0x00001000 /* 12: The value must be written in a single
                                                      operation */
/* #define 11:3 Reserved for write additions */
#define TCM_NV_PER_AUTHWRITE            0x00000004 /* 2: The value requires authorization to write
                                                      */
#define TCM_NV_PER_OWNERWRITE           0x00000002 /* 1: The value requires TCM Owner authorization
                                                      to write */
#define TCM_NV_PER_PPWRITE              0x00000001 /* 0: The value requires physical presence to
                                                      write */

/* 20.2.1 Owner Permission Settings rev 87 */

/* Per1 bits */

#define TCM_DELEGATE_PER1_MASK                          0xffffffff      /* mask of legal bits */
#define TCM_DELEGATE_KeyControlOwner                    31
#define TCM_DELEGATE_SetOrdinalAuditStatus              30
#define TCM_DELEGATE_DirWriteAuth                       29
#define TCM_DELEGATE_CMK_ApproveMA                      28
#define TCM_DELEGATE_NV_WriteValue                      27
#define TCM_DELEGATE_CMK_CreateTicket                   26
#define TCM_DELEGATE_NV_ReadValue                       25
#define TCM_DELEGATE_Delegate_LoadOwnerDelegation       24
#define TCM_DELEGATE_DAA_Join                           23
#define TCM_DELEGATE_AuthorizeMigrationKey              22
#define TCM_DELEGATE_CreateMaintenanceArchive           21
#define TCM_DELEGATE_LoadMaintenanceArchive             20
#define TCM_DELEGATE_KillMaintenanceFeature             19
#define TCM_DELEGATE_OwnerReadInternalPub               18
#define TCM_DELEGATE_ResetLockValue                     17
#define TCM_DELEGATE_OwnerClear                         16
#define TCM_DELEGATE_DisableOwnerClear                  15
#define TCM_DELEGATE_NV_DefineSpace                     14
#define TCM_DELEGATE_OwnerSetDisable                    13
#define TCM_DELEGATE_SetCapability                      12
#define TCM_DELEGATE_MakeIdentity                       11
#define TCM_DELEGATE_ActivateIdentity                   10
#define TCM_DELEGATE_OwnerReadPubek                     9 
#define TCM_DELEGATE_DisablePubekRead                   8 
#define TCM_DELEGATE_SetRedirection                     7 
#define TCM_DELEGATE_FieldUpgrade                       6 
#define TCM_DELEGATE_Delegate_UpdateVerification        5 
#define TCM_DELEGATE_CreateCounter                      4 
#define TCM_DELEGATE_ReleaseCounterOwner                3 
#define TCM_DELEGATE_Delegate_Manage                    2 
#define TCM_DELEGATE_Delegate_CreateOwnerDelegation     1 
#define TCM_DELEGATE_DAA_Sign                           0 

/* Per2 bits */
#define TCM_DELEGATE_PER2_MASK                          0x00000000      /* mask of legal bits */
/* All reserved */

/* 20.2.3 Key Permission settings rev 85 */

/* Per1 bits */

#define TCM_KEY_DELEGATE_PER1_MASK                      0x1fffffff      /* mask of legal bits */
#define TCM_KEY_DELEGATE_CMK_ConvertMigration           28
#define TCM_KEY_DELEGATE_TickStampBlob                  27
#define TCM_KEY_DELEGATE_ChangeAuthAsymStart            26
#define TCM_KEY_DELEGATE_ChangeAuthAsymFinish           25
#define TCM_KEY_DELEGATE_CMK_CreateKey                  24
#define TCM_KEY_DELEGATE_MigrateKey                     23
#define TCM_KEY_DELEGATE_LoadKey2                       22
#define TCM_KEY_DELEGATE_EstablishTransport             21
#define TCM_KEY_DELEGATE_ReleaseTransportSigned         20
#define TCM_KEY_DELEGATE_Quote2                         19
#define TCM_KEY_DELEGATE_Sealx                          18
#define TCM_KEY_DELEGATE_MakeIdentity                   17
#define TCM_KEY_DELEGATE_ActivateIdentity               16
#define TCM_KEY_DELEGATE_GetAuditDigestSigned           15
#define TCM_KEY_DELEGATE_Sign                           14
#define TCM_KEY_DELEGATE_CertifyKey2                    13
#define TCM_KEY_DELEGATE_CertifyKey                     12
#define TCM_KEY_DELEGATE_CreateWrapKey                  11
#define TCM_KEY_DELEGATE_CMK_CreateBlob                 10
#define TCM_KEY_DELEGATE_CreateMigrationBlob            9 
#define TCM_KEY_DELEGATE_ConvertMigrationBlob           8 
#define TCM_KEY_DELEGATE_Delegate_CreateKeyDelegation   7 
#define TCM_KEY_DELEGATE_ChangeAuth                     6 
#define TCM_KEY_DELEGATE_GetPubKey                      5 
#define TCM_KEY_DELEGATE_UnBind                         4 
#define TCM_KEY_DELEGATE_Quote                          3 
#define TCM_KEY_DELEGATE_Unseal                         2 
#define TCM_KEY_DELEGATE_Seal                           1 
#define TCM_KEY_DELEGATE_LoadKey                        0 

/* Per2 bits */
#define TCM_KEY_DELEGATE_PER2_MASK                      0x00000000      /* mask of legal bits */
/* All reserved */

/* 20.3 TCM_FAMILY_FLAGS rev 87

   These flags indicate the operational state of the delegation and family table. These flags
   are additions to TCM_PERMANENT_FLAGS and are not stand alone values.
*/

#define TCM_DELEGATE_ADMIN_LOCK 0x00000002 /* TRUE: Some TCM_Delegate_XXX commands are locked and
                                              return TCM_DELEGATE_LOCK
                                             
                                              FALSE: TCM_Delegate_XXX commands are available

                                              Default is FALSE */
#define TCM_FAMFLAG_ENABLED     0x00000001 /* When TRUE the table is enabled. The default value is
                                              FALSE.  */

/* 20.14 TCM_FAMILY_OPERATION Values rev 87

   These are the opFlag values used by TCM_Delegate_Manage.
*/

#define TCM_FAMILY_CREATE       0x00000001      /* Create a new family */
#define TCM_FAMILY_ENABLE       0x00000002      /* Set or reset the enable flag for this family. */
#define TCM_FAMILY_ADMIN        0x00000003      /* Prevent administration of this family. */
#define TCM_FAMILY_INVALIDATE   0x00000004      /* Invalidate a specific family row. */

/* 21.9 TCM_DA_STATE rev 100
   
   TCM_DA_STATE enumerates the possible states of the dictionary attack mitigation logic.
*/

#define TCM_DA_STATE_INACTIVE   0x00    /* The dictionary attack mitigation logic is currently
                                           inactive */
#define TCM_DA_STATE_ACTIVE     0x01    /* The dictionary attack mitigation logic is
                                           active. TCM_DA_ACTION_TYPE (21.10) is in progress. */

/* 21.10 TCM_DA_ACTION_TYPE rev 100
 */

/* 31-4 Reserved  No information and MUST be FALSE */

#define TCM_DA_ACTION_FAILURE_MODE      0x00000008 /* bit 3: The TCM is in failure mode. */
#define TCM_DA_ACTION_DEACTIVATE        0x00000004 /* bit 2: The TCM is in the deactivated state. */
#define TCM_DA_ACTION_DISABLE           0x00000002 /* bit 1: The TCM is in the disabled state. */
#define TCM_DA_ACTION_TIMEOUT           0x00000001 /* bit 0: The TCM will be in a locked state for
                                                      TCM_DA_INFO -> actionDependValue seconds. This
                                                      value is dynamic, depending on the time the
                                                      lock has been active.  */

/* 22. DAA Structures rev 91
   
   All byte and bit areas are byte arrays treated as large integers
*/

#define DAA_SIZE_r0             43
#define DAA_SIZE_r1             43
#define DAA_SIZE_r2             128
#define DAA_SIZE_r3             168
#define DAA_SIZE_r4             219
#define DAA_SIZE_NT             20
#define DAA_SIZE_v0             128
#define DAA_SIZE_v1             192
#define DAA_SIZE_NE             256
#define DAA_SIZE_w              256
#define DAA_SIZE_issuerModulus  256

/* check that DAA_SIZE_issuerModulus will fit in DAA_scratch */
#if (DAA_SIZE_issuerModulus != 256)
#error "DAA_SIZE_issuerModulus must be 256"
#endif

/* 22.2 Constant definitions rev 91 */

#define DAA_power0      104  
#define DAA_power1      1024  

#endif
