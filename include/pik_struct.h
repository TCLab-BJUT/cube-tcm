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
    TCM_KEY pikPub ;
    BYTE pikAuth[DIGEST_SIZE] ; 
    BYTE ownerAuth[DIGEST_SIZE]; 
}__attribute__((packed)) ;

#endif
