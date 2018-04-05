#include "tcm_structures.h" 

#ifndef VTCM_APPSTRUCT_H
#define VTCM_APPSTRUCT_H

//#define TCM_REVISION_MAX 9999    // for TCM_Process_GetCapability  vtcm_GetCapability_CapVersionVal
//#ifndef TCM_REVISION
//#define TCM_REVISION TCM_REVISION_MAX
//#endif

enum  vtcm_record_type
{
    DTYPE_VTCM_IN=0x2010,
    DTYPE_VTCM_IN_AUTH1=0x2011,
    DTYPE_VTCM_IN_AUTH2=0x2012,
    DTYPE_VTCM_OUT=0x2020,
    DTYPE_VTCM_OUT_AUTH1=0x2021,
    DTYPE_VTCM_OUT_AUTH2=0x2022,
    DTYPE_VTCM_HEAD=0x2030,
    DTYPE_VTCM_UTILS=0x2040
};
enum tcm_utils_subtype
{
	SUBTYPE_TCM_UTILS_INPUT=0x01,
	SUBTYPE_TCM_UTILS_OUTPUT,
	SUBTYPE_TCM_PIK_CERT
};

enum tcm_in_subtype
{
    	SUBTYPE_PHYSICALPRESENCE_IN=0x0A000040,
        SUBTYPE_CHANGEAUTH_IN=0x0C800000,
    	SUBTYPE_TAKEOWNERSHIP_IN=0x0D800000,
        SUBTYPE_CHANGEAUTHOWNER_IN=0x10800000,
        SUBTYPE_QUOTE_IN=0x16800000,
    	SUBTYPE_EXTEND_IN=0x14800000,
    	SUBTYPE_PCRREAD_IN=0x15800000,
    	SUBTYPE_SEAL_IN=0x17800000,
    	SUBTYPE_UNSEAL_IN=0x18800000,
        SUBTYPE_CREATEWRAPKEY_IN=0x1F800000,
        SUNTYPE_CERTIFYKEY_IN=0x32800000,
        SUBTYPE_SIGN_IN=0x3C800000,
        SUBTYPE_SETCAPABILITY_IN=0x3F800000,
        SUBTYPE_GETRANDOM_IN=0x46800000,
    	SUBTYPE_SELFTESTFULL_IN=0x50800000,
        SUBTYPE_CONTINUESELFTEST_IN=0x53800000,
        SUBTYPE_GETTESTRESULT_IN=0x54800000,
        SUBTYPE_OWNERCLEAR_IN=0x5B800000,
        SUBTYPE_DISABLEOWNERCLEAR_IN=0x5C800000,
    	SUBTYPE_FORCECLEAR_IN=0x5D800000,
        SUBTYPE_DISABLEFORCECLEAR_IN=0x5E800000,
    	SUBTYPE_GETCAPABILITY_IN=0x65800000,
    	SUBTYPE_PHYSICALENABLE_IN=0x6F800000,
        SUBTYPE_PHYSICALDISABLE_IN=0x70800000,
    	SUBTYPE_PHYSICALSETDEACTIVATED_IN=0x72800000,
    	SUBTYPE_CREATEEKPAIR_IN=0x78800000,
	    SUBTYPE_MAKEIDENTITY_IN=0x79800000,
	    SUBTYPE_ACTIVATEIDENTITY_IN=0x7A800000,
	    SUBTYPE_READPUBEK_IN=0x7C800000,
        SUBTYPE_OWNERREADINTERNALPUB_IN=0x81800000,
    	SUBTYPE_STARTUP_IN=0x99800000,
        SUBTYPE_FLUSHSPECIFIC_IN=0xBA800000,
        SUBTYPE_WRAPKEY_IN=0xBD800000,
        SUBTYPE_APCREATE_IN=0xBF800000,
        SUBTYPE_APTERMINATE_IN=0xC0800000,
        SUBTYPE_SM4ENCRYPT_IN=0xC5800000,
        SUBTYPE_SM4DECRYPT_IN=0xC6800000,
        SUBTYPE_PCRRESET_IN=0xC8800000,
        SUBTYPE_NV_DEFINESPACE_IN=0xCC800000,
        SUBTYPE_NV_READVALUE_IN=0xCF800000,
        SUBTYPE_NV_WRITEVALUE_IN=0xCD800000,
        SUBTYPE_SM3START_IN=0xEA800000,
        SUBTYPE_SM3UPDATE_IN=0xEB800000,
        SUBTYPE_SM3COMPLETE_IN=0xEC800000,
        SUBTYPE_SM3COMPLETEEXTEND_IN=0xED800000,
        SUBTYPE_SM2DECRYPT_IN=0xEE800000,
        SUBTYPE_LOADKEY_IN=0xEF800000
};

enum tcm_out_subtype
{
    	SUBTYPE_PHYSICALPRESENCE_OUT=0x0A000040,
        SUBTYPE_CHANGEAUTH_OUT=0x0C800000,
	    SUBTYPE_TAKEOWNERSHIP_OUT=0x0D800000,
        SUBTYPE_CHANGEAUTHOWNER_OUT=0x10800000,
        SUBTYPE_QUOTE_OUT=0x16800000,
	    SUBTYPE_EXTEND_OUT=0x14800000,
	    SUBTYPE_PCRREAD_OUT=0x15800000,
	    SUBTYPE_SEAL_OUT=0x17800000,
	    SUBTYPE_UNSEAL_OUT=0x18800000,
        SUBTYPE_CREATEWRAPKEY_OUT=0x1F800000,
        SUBTYPE_CERTIFYKEY_OUT=0x32800000,
        SUBTYPE_SIGN_OUT=0x3C800000,
        SUBTYPE_SETCAPABILITY_OUT=0x3F800000,
        SUBTYPE_GETRANDOM_OUT=0x46800000,
	    SUBTYPE_SELFTESTFULL_OUT=0x50800000,
        SUBTYPE_CONTINUESELFTEST_OUT=0x53800000,
        SUBTYPE_GETTESTRESULT_OUT=0x54800000,
        SUBTYPE_OWNERCLEAR_OUT=0x5B800000,
        SUBTYPE_DISABLEOWNERCLEAR_OUT=0x5C800000,
	    SUBTYPE_FORCECLEAR_OUT=0x5D800000,
        SUBTYPE_DISABLEFORCECLEAR_OUT=0x5E800000,
	    SUBTYPE_GETCAPABILITY_OUT=0x65800000,
    	SUBTYPE_PHYSICALENABLE_OUT=0x6F800000,
        SUBTYPE_PHYSICALDISABLE_OUT=0x70800000,
    	SUBTYPE_PHYSICALSETDEACTIVATED_OUT=0x72800000,
	    SUBTYPE_CREATEEKPAIR_OUT=0x78800000,
	    SUBTYPE_MAKEIDENTITY_OUT=0x79800000,
	    SUBTYPE_ACTIVATEIDENTITY_OUT=0x7A800000,
	    SUBTYPE_READPUBEK_OUT=0x7C800000,
        SUBTYPE_OWNERREADINTERNALPUB_OUT=0x81800000,
	    SUBTYPE_STARTUP_OUT=0x99800000,
        SUBTYPE_FLUSHSPECIFIC_OUT=0xBA800000,
        SUBTYPE_WRAPKEY_OUT=0xBD800000,
        SUBTYPE_APCREATE_OUT=0xBF800000,
        SUBTYPE_APTERMINATE_OUT=0xC0800000,
        SUBTYPE_SM4ENCRYPT_OUT=0xC5800000,
        SUBTYPE_SM4DECRYPT_OUT=0xC6800000,
        SUBTYPE_PCRRESET_OUT=0xC8800000,
        SUBTYPE_NV_DEFINESPACE_OUT=0xCC800000,
        SUBTYPE_NV_READVALUE_OUT=0xCF800000,
        SUBTYPE_NV_WRITEVALUE_OUT=0xCD800000,
        SUBTYPE_SM3START_OUT=0xEA800000,
        SUBTYPE_SM3UPDATE_OUT=0xEB800000,
        SUBTYPE_SM3COMPLETE_OUT=0xEC800000,
        SUBTYPE_SM3COMPLETEEXTEND_OUT=0xED800000,
        SUBTYPE_SM2DECRYPT_OUT=0xEE800000,
        SUBTYPE_LOADKEY_OUT=0xEF800000
};

//By Search2016  start-- 
enum vtcm_general_type
{
	    DTYPE_VTCM_INTERNAL=0x2001,
	    DTYPE_VTCM_EXTERNAL=0x2002,	
	    DTYPE_VTCM_IN_CAP=0x2003,
	    DTYPE_VTCM_IN_KEY=0x2004,
    	DTYPE_VTCM_NV=0x2005,
    	DTYPE_VTCM_PCR=0x2006,
    	DTYPE_VTCM_AUTH=0x2007,
        DTYPE_VTCM_KEY=0x2008,
	    DTYPE_VTCM_IDENTITY=0x2009,
	    DTYPE_VTCM_SEAL=0x200A

};

enum tcm_internal_subtype
{
	SUBTYPE_CURRENT_TICKS_INTERNAL=0x01	
};

enum vtcm_external_subtype
{
	SUBTYPE_INPUT_COMMAND_EXTERNAL=0x01,
	SUBTYPE_RETURN_DATA_EXTERNAL=0x02
};

enum subtype_vtcm_capability_struct
{
	SUBTYPE_TCM_CAP_VERSION_INFO=0x01,
    SUBTYPE_TCM_CAP_VERSION_STRUCT=0x02
};
enum subtype_vtcm_key_struct
{
    SUBTYPE_TCM_BIN_KEY_PARMS=0x01,
    SUBTYPE_TCM_BIN_PUBKEY,
    SUBTYPE_TCM_BIN_STORE_PUBKEY,
    SUBTYPE_TCM_BIN_RSA_KEY_PARMS,
    SUBTYPE_TCM_BIN_SM2_ASYMKEY_PARAMETERS,
    SUBTYPE_TCM_BIN_SYMMETRIC_KEY_PARMS,
    SUBTYPE_TCM_BIN_KEY,
    SUBTYPE_TCM_BIN_STORE_ASYMKEY,
    SUBTYPE_TCM_BIN_STORE_SYMKEY,
    SUBTYPE_TCM_BIN_STORE_PRIVKEY,
    SUBTYPE_TCM_BIN_SYMMETRIC_KEY
};

enum subtype_vtcm_pcr_struct
{
    SUBTYPE_TCM_PCR_ATTRIBUTES=0x01,
    SUBTYPE_TCM_PCR_SELECTION,
    SUBTYPE_TCM_PCR_COMPOSITE,
    SUBTYPE_TCM_PCR_INFO_SHORT,
    SUBTYPE_TCM_PCR_INFO_LONG,
    SUBTYPE_TCM_QUOTE_INFO
};
enum subtype_vtcm_identity
{
 	SUBTYPE_TCM_IDENTITY_CONTENTS=0x01,
        SUBTYPE_TCM_IDENTITY_REQ,
        SUBTYPE_TCM_PEK_REQ,
        SUBTYPE_TCM_IDENTITY_PROOF,
        SUBTYPE_TCM_PEK_PROOF,
	SUBTYPE_TCM_ASYM_CA_CONTENTS,
        SUBTYPE_TCM_STRUCT_VER,
        SUBTYPE_TCM_SYMMETRIC_KEY

};

enum subtype_vtcm_seal
{
    SUBTYPE_TCM_SEALED_DATA=0x01,
    SUBTYPE_TCM_STORED_DATA=0x02
};
//--end

struct tcm_internal_current_ticks
{
    int pcrIndex;
}__attribute__((packed));

struct vtcm_external_input_command
{
    UINT16 tag;
    int paramSize;
    UINT32 ordinal;
}__attribute__((packed));

struct vtcm_external_output_command
{
    UINT16 tag;
    int paramSize;
    UINT32 returnCode;
}__attribute__((packed));


struct tcm_in_pcrread
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    int pcrIndex;
} __attribute__((packed));


struct tcm_out_pcrread
{
    UINT16 tag ;
    int paramSize ;
    int returnCode ;
    BYTE outDigest[DIGEST_SIZE];
}__attribute__((packed)) ;


struct tcm_in_pcrreset
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    TCM_PCR_SELECTION pcrSelection;
} __attribute__((packed));


struct tcm_out_pcrreset
{
    UINT16 tag ;
    int paramSize ;
    int returnCode ;
}__attribute__((packed)) ;


struct tcm_in_extend
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    int pcrNum;
    BYTE inDigest[DIGEST_SIZE];
} __attribute__((packed));
//by Search2016

struct tcm_out_extend
{
    UINT16 tag;
    int paramSize;
    int returnCode;
    BYTE outDigest[DIGEST_SIZE];
} __attribute__((packed));

//By Search2016 start--

struct tcm_in_Startup
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    UINT16 startupType;
}__attribute__((packed));

struct tcm_out_Startup
{
    UINT16 tag ;
    int paramSize ;
    int returnCode ;
}__attribute__((packed)) ;

struct tcm_in_GetCapability
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    int capArea;
    int subCapSize;
    BYTE *subCap;
}__attribute__((packed));

struct tcm_out_GetCapability
{
    UINT16 tag ;
    int paramSize ;
    int returnCode ;
    int respSize ;
    BYTE *resp ;
}__attribute__((packed)) ;


struct tcm_in_SetCapability
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    int capArea;
    int subCapSize;
    BYTE *subCap;
    int setValueSize;
    BYTE *setValue;
    int authHandle;
    BYTE authCode[32];
}__attribute__((packed));

struct tcm_out_SetCapability
{
    UINT16 tag ;
    int paramSize ;
    int returnCode ;
    int resAuth[32];
}__attribute__((packed)) ;

struct tcm_in_PhysicalPresence
{
    UINT16 tag ;
    int paramSize ;
    int ordinal ;
    UINT16 physicalPresence ;
}__attribute__((packed)) ;

struct tcm_out_PhysicalPresence
{
    UINT16 tag ;
    int paramSize ;
    int returnCode ;
}__attribute__((packed)) ;
    
struct tcm_in_PhysicalEnable
{
    UINT16 tag ;
    int paramSize ;
    int ordinal ;
}__attribute__((packed)) ;

struct tcm_out_PhysicalEnable
{
    UINT16 tag ;
    int paramSize ;
    int returnCode ;
}__attribute__((packed)) ;

struct tcm_in_PhysicalDisable
{
    UINT16 tag ;
    int paramSize ;
    int ordinal ;
}__attribute__((packed)) ;

struct tcm_out_PhysicalDisable
{
    UINT16 tag ;
    int paramSize ;
    int returnCode ;
}__attribute__((packed)) ;

struct tcm_in_PhysicalSetDeactivated
{
    UINT16 tag ;
    int paramSize ;
    int ordinal ;
    BYTE state ;
}__attribute__((packed)) ;

struct tcm_out_PhysicalSetDeactivated
{
    UINT16 tag ;
    int paramSize ;
    int returnCode ;
}__attribute__((packed)) ;

struct tcm_in_CreateEKPair
{
    UINT16 tag ;
    int paramSize ;
    int ordinal ;
    BYTE antiReplay[DIGEST_SIZE] ;
    TCM_KEY_PARMS keyInfo ;
}__attribute__((packed)) ;

struct tcm_out_CreateEKPair
{
    UINT16 tag ;
    int paramSize ;
    int returnCode ;
    TCM_PUBKEY pubEndorsementKey ;
    TCM_DIGEST checksum ;
}__attribute__((packed)) ;

struct tcm_in_ReadPubek
{
    UINT16 tag ;
    int paramSize ;
    int ordinal ;
    BYTE antiReplay[DIGEST_SIZE] ;
}__attribute__((packed)) ;

struct tcm_out_ReadPubek
{
    UINT16 tag ;
    int paramSize ;
    int returnCode ;
    TCM_PUBKEY pubEndorsementKey ;
    TCM_DIGEST checksum ;
}__attribute__((packed)) ;
/*
struct tcm_in_OIAP
{
    UINT16 tag ;
    int paramSize ;
    int ordinal ;
}__attribute__((packed)) ;
*/

struct tcm_in_APCreate
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    UINT16 entityType;
    int entityValue;
    BYTE nonce[DIGEST_SIZE];
    BYTE authCode[DIGEST_SIZE];
}__attribute__((packed)) ;


struct tcm_out_APCreate
{
    UINT16 tag ;
    int paramSize ;
    int returnCode ;
    int authHandle ;
    BYTE nonceEven[DIGEST_SIZE] ;
    int sernum;
    BYTE authCode[DIGEST_SIZE];
}__attribute__((packed)) ;


struct tcm_in_APTerminate
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    int authHandle;
    BYTE authCode[DIGEST_SIZE];
}__attribute__((packed)) ;


struct tcm_out_APTerminate
{
    UINT16 tag;
    int paramSize;
    int returnCode;
}__attribute__((packed)) ;


struct tcm_in_TakeOwnership
{
    UINT16 tag ;
    int paramSize ;
    int ordinal ;
    UINT16 protocolID ; 
    int encOwnerAuthSize ;
    BYTE *encOwnerAuth ;
    int encSmkAuthSize ;
    BYTE *encSmkAuth ;
    TCM_KEY smkParams ;
    int authHandle ;
    BYTE authCode[DIGEST_SIZE] ;
}__attribute__((packed)) ;

struct tcm_out_TakeOwnership
{
    UINT16 tag ;
    int paramSize ;
    int returnCode ;
    TCM_KEY smkPub ;
    BYTE resAuth[DIGEST_SIZE] ; // TCM_AUTHDATA
}__attribute__((packed)) ;

struct tcm_in_ForceClear
{
    UINT16 tag ;
    int paramSize ;
    int ordinal ;
}__attribute__((packed)) ;

struct tcm_out_ForceClear
{
    UINT16 tag ;
    int paramSize ;
    int returnCode ;
}__attribute__((packed));

struct tcm_in_DisableForceClear
{
    UINT16 tag ;
    int paramSize ;
    int ordinal ;
}__attribute__((packed)) ;

struct tcm_out_DisableForceClear
{
    UINT16 tag ;
    int paramSize ;
    int returnCode ;
}__attribute__((packed));

struct tcm_in_SelfTestFull
{
    UINT16 tag ;
    int paramSize ;
    int ordinal ;
}__attribute__((packed)) ;

struct tcm_out_SelfTestFull
{
    UINT16 tag ;
    int paramSize ;
    int returnCode ;
}__attribute__((packed));

struct tcm_in_GetRandom
{
    UINT16 tag ;
    int paramSize ;
    int ordinal ;
    int bytesRequested ;
}__attribute__((packed));

struct tcm_out_GetRandom
{
    UINT16 tag ;
    int paramSize ;
    int returnCode ;
    int randomBytesSize ;
    BYTE * randomBytes ;
}__attribute__((packed));
//--NV--

struct tcm_in_NV_DefineSpace
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    TCM_NV_DATA_PUBLIC pubInfo;
    BYTE encAuth[32];
    int authHandle;
    BYTE ownerAuth[32];
}__attribute__((packed));

struct tcm_out_NV_DefineSpace
{
    UINT16 tag;
    int paramSize;
    int returnCode;
    BYTE ownerAuth[32];
}__attribute__((packed));

struct tcm_in_NV_WriteValue
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    int nvIndex;
    int offset;
    int dataSize;
    BYTE * data;
    TCM_AUTHHANDLE authHandle;
    BYTE ownerAuth[DIGEST_SIZE];
}__attribute__((packed));

struct tcm_out_NV_WriteValue
{
    UINT16 tag;
    int paramSize;
    int returnCode;
    BYTE ownerAuth[32];
}__attribute__((packed));

struct tcm_in_NV_ReadValue
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    int nvIndex;
    int offset;
    int dataSize;
    TCM_AUTHHANDLE authHandle;
    BYTE authCode[DIGEST_SIZE];
}__attribute__((packed));
struct tcm_out_NV_ReadValue
{
    UINT16 tag;
    int paramSize;
    int returnCode;
    int dataSize;
    BYTE * data;
    BYTE ownerAuth[32];
}__attribute__((packed));
struct tcm_in_Sm3Start
{
    UINT16 tag;
    int paramSize;
    int ordinal;
}__attribute__((packed));
struct tcm_out_Sm3Start
{
    UINT16 tag;
    int paramSize;
    int returnCode;
    int sm3MaxBytes;
}__attribute__((packed));
struct tcm_in_Sm3Update
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    int dataBlockSize;
    BYTE * dataBlock;
}__attribute__((packed));
struct tcm_out_Sm3Update
{
    UINT16 tag;
    int paramSize;
    int returnCode;
}__attribute__((packed));
struct tcm_in_Sm3Complete
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    int dataBlockSize;
    BYTE * dataBlock;
}__attribute__((packed));
struct tcm_out_Sm3Complete
{
    UINT16 tag;
    int paramSize;
    int returnCode;
    BYTE calResult[32];
}__attribute__((packed));
struct tcm_in_DisableOwnerClear
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    int authHandle;
    BYTE ownerAuth[32];
}__attribute__((packed));
struct tcm_out_DisableOwnerClear
{
    UINT16 tag;
    int paramSize;
    int returnCode;
    BYTE resAuth[32];
}__attribute__((packed));
struct tcm_in_Sm3CompleteExtend
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    int pcrIndex;
    int dataBlockSize;
    BYTE * dataBlock;
}__attribute__((packed));
struct tcm_out_Sm3CompleteExtend
{
    UINT16 tag;
    int paramSize;
    int returnCode;
    BYTE calResult[32];
    BYTE pcrResult[32];
}__attribute__((packed));
struct tcm_in_GetTestResult
{
    UINT16 tag;
    int paramSize;
    int ordinal;
}__attribute__((packed));
struct tcm_out_GetTestResult
{
    UINT16 tag;
    int paramSize;
    int returnCode;
    int outDataSize;
    BYTE * outData;
}__attribute__((packed));
struct tcm_in_ContinueSelfTest
{
    UINT16 tag;
    int paramSize;
    int ordinal;
} __attribute__((packed));
struct tcm_out_ContinueSelfTest
{
    UINT16 tag ;
    int paramSize ;
    int returnCode ;
}__attribute__((packed));
struct tcm_in_FlushSpecific
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    int handle;
    int resourceType;
} __attribute__((packed));
struct tcm_out_FlushSpecific
{
    UINT16 tag ;
    int paramSize ;
    int returnCode ;
}__attribute__((packed));
struct tcm_in_OwnerClear
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    int authHandle;
    BYTE ownerAuth[32];
}__attribute__((packed));
struct tcm_out_OwnerClear
{
    UINT16 tag;
    int paramSize;
    int returnCode;
    BYTE resAuth[32];
}__attribute__((packed));
struct tcm_in_CreateWrapKey
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    int parentHandle;
    BYTE dataUsageAuth[32];
    BYTE dataMigrationAuth[32];
    TCM_KEY keyInfo;
    int authHandle;
    BYTE pubAuth[32];
}__attribute__((packed));
struct tcm_out_CreateWrapKey
{
    UINT16 tag;
    int paramSize;
    int returnCode;
    TCM_KEY wrappedKey;
    BYTE resAuth[32];
}__attribute__((packed));
struct tcm_in_LoadKey
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    int parentHandle;
    TCM_KEY inKey;
    int authHandle;
    BYTE parentAuth[32];
}__attribute__((packed));
struct tcm_out_LoadKey
{
    UINT16 tag;
    int paramSize;
    int returnCode;
    int inKeyHandle;
    BYTE resAuth[32];
}__attribute__((packed));
struct tcm_in_WrapKey
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    int parentHandle;
    BYTE dataUsageAuth[32];
    BYTE dataMigrationAuth[32];
    TCM_KEY keyInfo;
    int authHandle;
    BYTE pubAuth[32];
}__attribute__((packed));
struct tcm_out_WrapKey
{
    UINT16 tag;
    int paramSize;
    int returnCode;
    TCM_KEY wrappedKey;
    BYTE resAuth[32];
}__attribute__((packed));

struct tcm_in_Sm2Decrypt
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    int keyHandle;
    int DecryptDataSize;
    BYTE *DecryptData;
    int DecryptAuthHandle;
    BYTE DecryptAuthVerfication[32];
}__attribute__((packed));

struct tcm_out_Sm2Decrypt
{
    UINT16 tag;
    int paramSize;
    int returnCode;
    int DecryptedDataSize;
    BYTE *DecryptedData;
    BYTE DecryptedAuthVerfication[32];
}__attribute__((packed));

struct tcm_in_Quote
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    int keyHandle;
    BYTE externalData[32];
    TCM_PCR_SELECTION targetPCR;
    int authHandle;
    BYTE privAuth[32];
}__attribute__((packed));

struct tcm_out_Quote
{
    UINT16 tag;
    int paramSize;
    int returnCode;
    TCM_PCR_COMPOSITE pcrData;
    int sigSize;
    BYTE * sig;
    BYTE resAuth[32];
}__attribute__((packed));

struct tcm_in_Sm4Encrypt
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    int keyHandle;
    BYTE CBCusedIV[16];
    int EncryptDataSize;
    BYTE *EncryptData;
    int EncryptAuthHandle;
    BYTE EncryptAuthVerfication[32];
}__attribute__((packed));

struct tcm_out_Sm4Encrypt
{
    UINT16 tag;
    int paramSize;
    int returnCode;
    int EncryptedDataSize;
    BYTE *EncryptedData;
    BYTE EncryptedAuthVerfication[32];
}__attribute__((packed));

struct tcm_in_Sm4Decrypt
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    int keyHandle;
    BYTE CBCusedIV[16];
    int DecryptDataSize;
    BYTE *DecryptData;
    int DecryptAuthHandle;
    BYTE DecryptAuthVerfication[32];
}__attribute__((packed));

struct tcm_out_Sm4Decrypt
{
    UINT16 tag;
    int paramSize;
    int returnCode;
    int DecryptedDataSize;
    BYTE *DecryptedData;
    BYTE DecryptedAuthVerfication[32];
}__attribute__((packed));

struct tcm_in_Sign
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    int keyHandle;
    int areaToSignSize;
    BYTE * areaToSign;
    int authHandle;
    BYTE privAuth[32];
}__attribute__((packed));

struct tcm_out_Sign
{
    UINT16 tag;
    int paramSize;
    int returnCode;
    int sigSize;
    BYTE * sig;
    BYTE resAuth[32];
}__attribute__((packed));


struct tcm_in_Seal
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    int keyHandle;
    BYTE encAuth[32];
    int pcrInfoSize;
    BYTE *pcrInfo;
    int InDataSize;
    BYTE *InData;
    int authHandle;
    BYTE authCode[32];
}__attribute__((packed));

struct tcm_out_Seal
{
    UINT16 tag;
    int paramSize;
    int returnCode;
    TCM_STORED_DATA sealedData;
    BYTE authCode[32];
}__attribute__((packed));

struct tcm_in_UnSeal
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    int keyHandle;
    TCM_STORED_DATA encAuth;
    int UnAuthHandle;
    BYTE UnAuthCode[32];
    int authHandle;
    BYTE authCode[32];
}__attribute__((packed));

struct tcm_out_UnSeal
{
    UINT16 tag;
    int paramSize;
    int returnCode;
    int PrintDataSize;
    BYTE *PrintData;
    BYTE UnauthCode[32];
    BYTE authCode[32];
}__attribute__((packed));

struct tcm_in_ChangeAuth
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    int parentHandle;
    UINT16 protocolID;
    BYTE newAuth[32];
    UINT16 entityType;
    int encDataSize;
    BYTE * encData;
    int parentAuthHandle;
    BYTE parentAuth[32];
    int entityAuthHandle;
    BYTE entityAuth[32];
}__attribute__((packed));

struct tcm_out_ChangeAuth
{
    UINT16 tag;
    int paramSize;
    int returnCode;
    int outDataSize;
    BYTE outData;
    BYTE resAuth[32];
    BYTE entityAuth[32];
}__attribute__((packed));

struct tcm_in_OwnerReadInternalPub
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    int keyHandle;
    int authHandle;
    BYTE ownerAuth[32];
}__attribute__((packed));

struct tcm_out_OwnerReadInternalPub
{
    UINT16 tag;
    int paramSize;
    int returnCode;
    TCM_PUBKEY publicPortion;
    BYTE resAuth[32];
}__attribute__((packed));

struct tcm_in_ChangeAuthOwner
{
    UINT16 tag;
    int paramSize;
    int ordinal;
    UINT16 protocolID;
    BYTE newAuth[32];
    UINT16 entityType;
    int ownerAuthHandle;
    BYTE ownerAuth[32];
}__attribute__((packed));

struct tcm_out_ChangeAuthOwner
{
    UINT16 tag;
    int paramSize;
    int returnCode;
    BYTE resAuth[32];
}__attribute__((packed));

struct tcm_utils_input
{
    int param_num;
    BYTE * params;
}__attribute__((packed));

struct tcm_utils_output
{
    int param_num;
    BYTE * params;
}__attribute__((packed));
//--END--




//new addition
typedef struct tdTCM_ORDINAL_TABLE 
{
    int ordinal ;
}TCM_ORDINAL_TABLE ;

static TCM_ORDINAL_TABLE tcm_ordinal_table[] =
{
    0x000000b4,
    0x000000b6
} ;

//--end

//unsigned char tcm_default_rsa_exponent[] = {0x01, 0x00, 0x01} ;

/*
enum EntityType
{
    TCM_ET_KEYHANDLE=0x01,
    TCM_ET_OWNER=0x02,
    TCM_ET_DATA=0x03,
    TCM_ET_SMK=0x04,
    TCM_ET_KEY=0x05,
    TCM_ET_REVOKE=0x06,
    TCM_ET_COUNTER=0x0A,
    TCM_ET_NV=0x0B,
    TCM_ET_KEYSM4=0x11,
    TCM_ET_NONE=0x12,
    TCM_ET_AUTHDATA_ID=0x13,
    TCM_ET_RESERVED_HANDLE=0x40
};
*/
enum subtype_vtcm_nv
{
    SUBTYPE_TCM_NV_DATA_PUBLIC=0x01,
    SUBTYPE_TCM_NV_ATTRIBUTES=0x02,
    SUBTYPE_TCM_NV_DATA_SENSITIVE=0x03
};
enum subtype_vtcm_auth
{
    SUBTYPE_TCM_AUTH_SESSION_DATA=0x01
};
enum subtype_vtcm_key
{
    SUBTYPE_KEY_HANDLE_ENTRY=0x01
};
#endif
