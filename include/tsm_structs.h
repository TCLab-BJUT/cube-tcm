/*++

TSM structures for TSM

*/

#ifndef __TSM_STRUCTS_H__
#define __TSM_STRUCTS_H__

#include "tsm_typedef.h"
#include "tsm_error.h"

#define TSM_VERSION TCM_STRUCT_VER

typedef struct tdTSM_PCR_EVENT 
{
    TSM_VERSION   versionInfo;
    UINT32        ulPcrIndex;
    TSM_EVENTTYPE eventType;
    UINT32        ulPcrValueLength;
    BYTE*         rgbPcrValue;
    UINT32        ulEventLength;
    BYTE*         rgbEvent;
} TSM_PCR_EVENT;


typedef struct tdTSM_EVENT_CERT
{
    TSM_VERSION       versionInfo;
    UINT32    ulCertificateHashLength;
    BYTE*     rgbCertificateHash;
    UINT32    ulEntityDigestLength;
    BYTE*     rgbEntityDigest;
    TSM_BOOL  fDigestChecked;
    TSM_BOOL  fDigestVerified;
    UINT32    ulIssuerLength;
    BYTE*     rgbIssuer;
} TSM_EVENT_CERT;

typedef struct tdTSM_UUID 
{
    UINT32  ulTimeLow;
    UINT16  usTimeMid;
    UINT16  usTimeHigh;
    BYTE   bClockSeqHigh;
    BYTE   bClockSeqLow;
    BYTE   rgbNode[6];
} TSM_UUID;

/*
typedef struct tdTSM_KM_KEYINFO 
{
    TSM_VERSION  versionInfo;
    TSM_UUID     keyUUID;
    TSM_UUID     parentKeyUUID;
    BYTE         bAuthDataUsage;   // whether auth is needed to load child keys
    TSM_BOOL     fIsLoaded;           // TRUE: actually loaded in TCM
    UINT32       ulVendorDataLength;  // may be 0
#ifdef __midl
    [size_is(ulVendorDataLength)]
#endif
    BYTE        *rgbVendorData;       // may be NULL
} TSM_KM_KEYINFO;


typedef struct tdTSM_KM_KEYINFO2
{
    TSM_VERSION  versionInfo;
    TSM_UUID     keyUUID;
    TSM_UUID     parentKeyUUID;
    BYTE         bAuthDataUsage;   // whether auth is needed to load child keys
    TSM_FLAG     persistentStorageType;
    TSM_FLAG     persistentStorageTypeParent;
    TSM_BOOL     fIsLoaded;           // TRUE: actually loaded in TCM
    UINT32       ulVendorDataLength;  // may be 0
#ifdef __midl
    [size_is(ulVendorDataLength)]
#endif
    BYTE        *rgbVendorData;       // may be NULL
} TSM_KM_KEYINFO2;


typedef struct tdTSM_NONCE
{
    BYTE  nonce[TCM_SHA1BASED_NONCE_LEN];
} TSM_NONCE;


typedef struct tdTSM_VALIDATION
{ 
    TSM_VERSION  versionInfo;
    UINT32       ulExternalDataLength;
#ifdef __midl
    [size_is(ulExternalDataLength)]
#endif
    BYTE*        rgbExternalData;
    UINT32       ulDataLength;
#ifdef __midl
    [size_is(ulDataLength)]
#endif
    BYTE*     rgbData;
    UINT32    ulValidationDataLength;
#ifdef __midl
    [size_is(ulValidationDataLength)]
#endif
    BYTE*     rgbValidationData;
} TSM_VALIDATION;

////////////////////////////////////////////////////////////////////

*/
#endif // __TSM_STRUCTS_H__

