#include "tcm_structures.h" 

#ifndef VTCM_PIKSTRUCT_H
#define VTCM_PIKSTRUCT_H

struct tcm_in_MakeIdentity
{
    UINT16 tag ;
    int paramSize ;
    int ordinal ;
    BYTE pikAuth[DIGEST_SIZE];
    BYTE pubDigest[DIGEST_SIZE]; 
    TCM_KEY pikParams ;
    int smkHandle ;
    BYTE smkAuth[DIGEST_SIZE];
    int ownerHandle;
    BYTE ownerAuth[DIGEST_SIZE];
}__attribute__((packed)) ;

struct tcm_out_MakeIdentity
{
    UINT16 tag ;
    int paramSize ;
    int returnCode ;
    TCM_KEY pik ;
    int CertSize;
    BYTE * CertData;
    BYTE smkAuth[DIGEST_SIZE];		
    BYTE ownerAuth[DIGEST_SIZE] ; // TCM_AUTHDATA
}__attribute__((packed)) ;

struct tcm_in_ActivateIdentity
{
    UINT16 tag ;
    int paramSize ;
    int ordinal ;
    int pikHandle ;
    int encDataSize;
    BYTE *encData;
    int pikAuthHandle ;
    BYTE pikAuth[DIGEST_SIZE];		
    int ownerAuthHandle ;
    BYTE ownerAuth[DIGEST_SIZE];		
}__attribute__((packed)) ;

struct tcm_out_ActivateIdentity
{
    UINT16 tag ;
    int paramSize ;
    int returnCode ;
    TCM_SYMMETRIC_KEY symmkey ;
    BYTE pikAuth[DIGEST_SIZE] ; 
    BYTE ownerAuth[DIGEST_SIZE]; 
}__attribute__((packed)) ;

struct tcm_in_CertifyKey
{
    UINT16 tag ;
    int paramSize ;
    int ordinal ;
    int keyCertified;
    int keyCertify;
    int encDataSize;
    BYTE *encData;
    int pikAuthHandle ;
    BYTE pikAuth[DIGEST_SIZE];		
    int ownerAuthHandle ;
    BYTE ownerAuth[DIGEST_SIZE];		
}__attribute__((packed)) ;

struct tcm_out_CertifyKey
{
    UINT16 tag ;
    int paramSize ;
    int returnCode ;
    TCM_SYMMETRIC_KEY symmkey ;
    BYTE pikAuth[DIGEST_SIZE] ; 
    BYTE ownerAuth[DIGEST_SIZE]; 
}__attribute__((packed)) ;

typedef struct tcm_pik_cert
{
	TCM_PAYLOAD_TYPE payLoad;   // should be 0x19
	BYTE userDigest[DIGEST_SIZE];
	BYTE pubDigest[DIGEST_SIZE];
	int signLen;
	BYTE * signData;
}__attribute__((packed)) TCM_PIK_CERT;

#endif
