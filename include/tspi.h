#if !defined(_TSPI_H_)
#define _TSPI_H_

//#define TSM_UUID_SMK  {0, 0, 0, 0, 0, {0, 0, 0, 0, 0, 1}} // Storage root key
extern TSM_UUID TSM_UUID_SMK;
//
// TCM well-known secret
//
#define TSM_WELL_KNOWN_SECRET \
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00\
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

#define   TSM_OBJECT_TYPE_TCM    (0x00)      // Tcm object
#define   TSM_OBJECT_TYPE_POLICY    (0x01)      // Policy object
#define   TSM_OBJECT_TYPE_KEY       (0x02)      // RSA-Key object
#define   TSM_OBJECT_TYPE_ENCDATA   (0x03)      // Encrypted data object
#define   TSM_OBJECT_TYPE_PCRS      (0x04)      // PCR composite object
#define   TSM_OBJECT_TYPE_HASH      (0x05)      // Hash object
#define   TSM_OBJECT_TYPE_NV        (0x06)      // NV object
#define   TSM_OBJECT_TYPE_MIGDATA   (0x07)      // CMK Migration data object
#define   TSM_OBJECT_TYPE_EXCHANGE  (0x08)      // Key exchange object

#define TSM_KEY_KEYTYPE_MASK    (UINT32)(0x000000FF) // indicate a 128-bit key
#define TSM_KEY_SIZEVAL_MASK    (UINT32)(0x00000F00) // indicate a 128-bit key
#define TSM_KEY_VOLATILE_MASK   (UINT32)(0x0000F000) // indicate a 128-bit key
#define TSM_KEY_AUTH_MASK       (UINT32)(0x000F0000) // indicate a 128-bit key
#define TSM_KEY_MIG_MASK        (UINT32)(0x00F00000) // indicate a 128-bit key

#define TSM_KEY_SIZEVAL_128BIT  (UINT32)(0x00000100) // indicate a 128-bit key
#define TSM_KEY_SIZEVAL_256BIT  (UINT32)(0x00000200) // indicate a 256-bit key
#define TSM_KEY_SIZEVAL_512BIT  (UINT32)(0x00000300) // indicate a 512-bit key

//   Non Volatile                                             |0|
//   Volatile                                                 |1|
//
#define    TSM_KEY_NON_VOLATILE      (0x00000000)   // Key is non-volatile
#define    TSM_KEYFLAG_VOLATILEKEY   (0x00004000)   // Key is volatile
//   Never                                                      |0 0|
//   Always                                                     |0 1|
//   Private key always                                         |1 0|
//
#define   TSM_KEYAUTH_AUTH_NEVER              (0x00000000) // no auth needed
                                                           // for this key
#define   TSM_KEYAUTH_AUTH_ALWAYS             (0x00010000) // key needs auth
                                                           // for all ops
#define   TSM_KEYAUTH_AUTH_PRIV_USE_ONLY      (0x00020000) // key needs auth

#define    TSM_KEYFLAG_MIGRATABLE             (0x00100000)   // Key is volatile

#define TSM_SECRET_MODE_NONE     (0x00000800) // No authorization will be
                                              // processed
#define TSM_SECRET_MODE_SM3     (0x00001000) // Secret string will not be
                                              // touched by TSP 
#define TSS_SECRET_MODE_PLAIN    (0x00001800) // Secret string will be hashed
                                              // using SM3
#define TSS_SECRET_MODE_POPUP    (0x00002000) // TSM SP will ask for a secret

#include "tsm_typedef.h"
#include "tsm_error.h"
#include "tsm_structs.h"

#if defined ( __cplusplus )
extern "C" {
#endif /* __cplusplus */

// Tspi_Context Class Definitions
TSM_RESULT Tspi_Context_Create
(
    TSM_HCONTEXT*       phContext                      // out
);

TSM_RESULT Tspi_Context_Close
(
    TSM_HCONTEXT        hContext                       // in
);

TSM_RESULT Tspi_Context_Connect
(
    TSM_HCONTEXT        hContext,                      // in
    TSM_UNICODE*        wszDestination                 // in
);

TSM_RESULT Tspi_Context_GetTcmObject
(
    TSM_HCONTEXT        hContext,                      // in
    TSM_HTCM*           phTCM                          // out
);


TSM_RESULT Tspi_TCM_PcrExtend
(
    TSM_HTCM            hTCM,                          // in
    UINT32              ulPcrIndex,                    // in
    UINT32              ulPcrDataLength,               // in
    BYTE*               pbPcrData,                     // in
    TSM_PCR_EVENT*      pPcrEvent,                     // in
    UINT32*             pulPcrValueLength,             // out
    BYTE**              prgbPcrValue                   // out
);

TSM_RESULT Tspi_TCM_PcrRead
(
    TSM_HTCM            hTCM,                          // in
    UINT32              ulPcrIndex,                    // in
    UINT32*             pulPcrValueLength,             // out
    BYTE**              prgbPcrValue                   // out
);

TSM_RESULT Tspi_TCM_PcrReset
(
    TSM_HTCM            hTCM,                          // in
    TSM_HPCRS           hPcrComposite                  // in
);

TSM_RESULT Tspi_Context_LoadKeyByUUID
(
    TSM_HCONTEXT        hContext,                      // in
    TSM_FLAG            persistentStorageType,         // in
    TSM_UUID            uuidData,                      // in
    TSM_HKEY*           phKey                          // out
);

/*
// Class-independent ASN.1 conversion functions
TSPICALL Tspi_EncodeDER_TssBlob
(
    UINT32              rawBlobSize,                   // in
    BYTE*               rawBlob,                       // in
    UINT32              blobType,                      // in
    UINT32*             derBlobSize,                   // in, out
    BYTE*               derBlob                        // out
);

TSPICALL Tspi_DecodeBER_TssBlob
(
    UINT32              berBlobSize,                   // in
    BYTE*               berBlob,                       // in
    UINT32*             blobType,                      // out
    UINT32*             rawBlobSize,                   // in, out
    BYTE*               rawBlob                        // out
);



// Common Methods
TSPICALL Tspi_SetAttribUint32
(
    TSM_HOBJECT         hObject,                       // in
    TSM_FLAG            attribFlag,                    // in
    TSM_FLAG            subFlag,                       // in
    UINT32              ulAttrib                       // in
);

TSPICALL Tspi_GetAttribUint32
(
    TSM_HOBJECT         hObject,                       // in
    TSM_FLAG            attribFlag,                    // in
    TSM_FLAG            subFlag,                       // in
    UINT32*             pulAttrib                      // out
);

TSPICALL Tspi_SetAttribData
(
    TSM_HOBJECT         hObject,                       // in
    TSM_FLAG            attribFlag,                    // in
    TSM_FLAG            subFlag,                       // in
    UINT32              ulAttribDataSize,              // in
    BYTE*               rgbAttribData                  // in
);

TSPICALL Tspi_GetAttribData
(
    TSM_HOBJECT         hObject,                       // in
    TSM_FLAG            attribFlag,                    // in
    TSM_FLAG            subFlag,                       // in
    UINT32*             pulAttribDataSize,             // out
    BYTE**              prgbAttribData                 // out
);

TSPICALL Tspi_ChangeAuth
(
    TSM_HOBJECT         hObjectToChange,               // in
    TSM_HOBJECT         hParentObject,                 // in
    TSM_HPOLICY         hNewPolicy                     // in
);

TSPICALL Tspi_ChangeAuthAsym
(
    TSM_HOBJECT         hObjectToChange,               // in
    TSM_HOBJECT         hParentObject,                 // in
    TSM_HKEY            hIdentKey,                     // in
    TSM_HPOLICY         hNewPolicy                     // in
);

TSPICALL Tspi_GetPolicyObject
(
    TSM_HOBJECT         hObject,                       // in
    TSM_FLAG            policyType,                    // in
    TSM_HPOLICY*        phPolicy                       // out
);



TSPICALL Tspi_Context_FreeMemory
(
    TSM_HCONTEXT        hContext,                      // in
    BYTE*               rgbMemory                      // in
);

TSPICALL Tspi_Context_GetDefaultPolicy
(
    TSM_HCONTEXT        hContext,                      // in
    TSM_HPOLICY*        phPolicy                       // out
);
*/
TSM_RESULT Tspi_Context_CreateObject
(
    TSM_HCONTEXT        hContext,                      // in
    TSM_FLAG            objectType,                    // in
    TSM_FLAG            initFlags,                     // in
    TSM_HOBJECT*        phObject                       // out
);
/*
TSPICALL Tspi_Context_CloseObject
(
    TSM_HCONTEXT        hContext,                      // in
    TSM_HOBJECT         hObject                        // in
);

TSPICALL Tspi_Context_GetCapability
(
    TSM_HCONTEXT        hContext,                      // in
    TSM_FLAG            capArea,                       // in
    UINT32              ulSubCapLength,                // in
    BYTE*               rgbSubCap,                     // in
    UINT32*             pulRespDataLength,             // out
    BYTE**              prgbRespData                   // out
);

TSPICALL Tspi_Context_SetTransEncryptionKey
(
    TSM_HCONTEXT        hContext,                      // in
    TSM_HKEY            hKey                           // in
);

TSPICALL Tspi_Context_CloseSignTransport
(
    TSM_HCONTEXT        hContext,                      // in
    TSM_HKEY            hSigningKey,                   // in
    TSM_VALIDATION*     pValidationData                // in, out
);

TSPICALL Tspi_Context_LoadKeyByBlob
(
    TSM_HCONTEXT        hContext,                      // in
    TSM_HKEY            hUnwrappingKey,                // in
    UINT32              ulBlobLength,                  // in
    BYTE*               rgbBlobData,                   // in
    TSM_HKEY*           phKey                          // out
);

TSPICALL Tspi_Context_LoadKeyByUUID
(
    TSM_HCONTEXT        hContext,                      // in
    TSM_FLAG            persistentStorageType,         // in
    TSM_UUID            uuidData,                      // in
    TSM_HKEY*           phKey                          // out
);

TSPICALL Tspi_Context_RegisterKey
(
    TSM_HCONTEXT        hContext,                      // in
    TSM_HKEY            hKey,                          // in
    TSM_FLAG            persistentStorageType,         // in
    TSM_UUID            uuidKey,                       // in
    TSM_FLAG            persistentStorageTypeParent,   // in
    TSM_UUID            uuidParentKey                  // in
);

TSPICALL Tspi_Context_UnregisterKey
(
    TSM_HCONTEXT        hContext,                      // in
    TSM_FLAG            persistentStorageType,         // in
    TSM_UUID            uuidKey,                       // in
    TSM_HKEY*           phkey                          // out
);

TSPICALL Tspi_Context_GetKeyByUUID
(
    TSM_HCONTEXT        hContext,                      // in
    TSM_FLAG            persistentStorageType,         // in
    TSM_UUID            uuidData,                      // in
    TSM_HKEY*           phKey                          // out
);

TSPICALL Tspi_Context_GetKeyByPublicInfo
(
    TSM_HCONTEXT        hContext,                      // in
    TSM_FLAG            persistentStorageType,         // in
    TSM_ALGORITHM_ID    algID,                         // in
    UINT32              ulPublicInfoLength,            // in
    BYTE*               rgbPublicInfo,                 // in
    TSM_HKEY*           phKey                          // out
);

TSPICALL Tspi_Context_GetRegisteredKeysByUUID
(
    TSM_HCONTEXT        hContext,                      // in
    TSM_FLAG            persistentStorageType,         // in
    TSM_UUID*           pUuidData,                     // in
    UINT32*             pulKeyHierarchySize,           // out
    TSM_KM_KEYINFO**    ppKeyHierarchy                 // out
);

TSPICALL Tspi_Context_GetRegisteredKeysByUUID2
(
    TSM_HCONTEXT        hContext,                      // in
    TSM_FLAG            persistentStorageType,         // in
    TSM_UUID*           pUuidData,                     // in
    UINT32*             pulKeyHierarchySize,           // out
    TSM_KM_KEYINFO2**   ppKeyHierarchy                 // out
);


// Policy class definitions
TSPICALL Tspi_Policy_SetSecret
(
    TSM_HPOLICY         hPolicy,                       // in
    TSM_FLAG            secretMode,                    // in
    UINT32              ulSecretLength,                // in
    BYTE*               rgbSecret                      // in
);

TSPICALL Tspi_Policy_FlushSecret
(
    TSM_HPOLICY         hPolicy                        // in
);

TSPICALL Tspi_Policy_AssignToObject
(
    TSM_HPOLICY         hPolicy,                       // in
    TSM_HOBJECT         hObject                        // in
);



// TCM Class Definitions
TSPICALL Tspi_TCM_KeyControlOwner
(
    TSM_HTCM            hTCM,                          // in
    TSM_HKEY            hKey,                          // in
    UINT32              attribName,                    // in
    TSM_BOOL            attribValue,                   // in
    TSM_UUID*           pUuidData                      // out
);

TSPICALL Tspi_TCM_CreateEndorsementKey
(
    TSM_HTCM            hTCM,                          // in
    TSM_HKEY            hKey,                          // in
    TSM_VALIDATION*     pValidationData                // in, out
);

TSPICALL Tspi_TCM_CreateRevocableEndorsementKey
(
    TSM_HTCM            hTCM,                          // in
    TSM_HKEY            hKey,                          // in
    TSM_VALIDATION*     pValidationData,               // in, out
    UINT32*             pulEkResetDataLength,          // in, out
    BYTE**              rgbEkResetData                 // in, out
);

TSPICALL Tspi_TCM_RevokeEndorsementKey
(
    TSM_HTCM            hTCM,                          // in
    UINT32              ulEkResetDataLength,           // in
    BYTE*               rgbEkResetData                 // in
);

TSPICALL Tspi_TCM_GetPubEndorsementKey
(
    TSM_HTCM            hTCM,                          // in
    TSM_BOOL            fOwnerAuthorized,              // in
    TSM_VALIDATION*     pValidationData,               // in, out
    TSM_HKEY*           phEndorsementPubKey            // out
);

TSPICALL Tspi_TCM_OwnerGetSRKPubKey
(
    TSM_HTCM            hTCM,                          // in
    UINT32*             pulPubKeyLength,               // out
    BYTE**              prgbPubKey                     // out
);

TSPICALL Tspi_TCM_TakeOwnership
(
    TSM_HTCM            hTCM,                          // in
    TSM_HKEY            hKeySRK,                       // in
    TSM_HKEY            hEndorsementPubKey             // in
);

TSPICALL Tspi_TCM_ClearOwner
(
    TSM_HTCM            hTCM,                          // in
    TSM_BOOL            fForcedClear                   // in
);

TSPICALL Tspi_TCM_CollateIdentityRequest
(
    TSM_HTCM            hTCM,                          // in
    TSM_HKEY            hKeySRK,                       // in
    TSM_HKEY            hCAPubKey,                     // in
    UINT32              ulIdentityLabelLength,         // in
    BYTE*               rgbIdentityLabelData,          // in
    TSM_HKEY            hIdentityKey,                  // in
    TSM_ALGORITHM_ID    algID,                         // in
    UINT32*             pulTCPAIdentityReqLength,      // out
    BYTE**              prgbTCPAIdentityReq            // out
);

TSPICALL Tspi_TCM_ActivateIdentity
(
    TSM_HTCM            hTCM,                          // in
    TSM_HKEY            hIdentKey,                     // in
    UINT32              ulAsymCAContentsBlobLength,    // in
    BYTE*               rgbAsymCAContentsBlob,         // in
    UINT32              ulSymCAAttestationBlobLength,  // in
    BYTE*               rgbSymCAAttestationBlob,       // in
    UINT32*             pulCredentialLength,           // out
    BYTE**              prgbCredential                 // out
);

TSPICALL Tspi_TCM_CreateMaintenanceArchive
(
    TSM_HTCM            hTCM,                          // in
    TSM_BOOL            fGenerateRndNumber,            // in
    UINT32*             pulRndNumberLength,            // out
    BYTE**              prgbRndNumber,                 // out
    UINT32*             pulArchiveDataLength,          // out
    BYTE**              prgbArchiveData                // out
);

TSPICALL Tspi_TCM_KillMaintenanceFeature
(
    TSM_HTCM            hTCM                           // in
);

TSPICALL Tspi_TCM_LoadMaintenancePubKey
(
    TSM_HTCM            hTCM,                          // in
    TSM_HKEY            hMaintenanceKey,               // in
    TSM_VALIDATION*     pValidationData                // in, out
);

TSPICALL Tspi_TCM_CheckMaintenancePubKey
(
    TSM_HTCM            hTCM,                          // in
    TSM_HKEY            hMaintenanceKey,               // in
    TSM_VALIDATION*     pValidationData                // in, out
);

TSPICALL Tspi_TCM_SetOperatorAuth
(
    TSM_HTCM            hTCM,                          // in
    TSM_HPOLICY         hOperatorPolicy                // in
);

TSPICALL Tspi_TCM_SetStatus
(
    TSM_HTCM            hTCM,                          // in
    TSM_FLAG            statusFlag,                    // in
    TSM_BOOL            fTpmState                      // in
);

TSPICALL Tspi_TCM_GetStatus
(
    TSM_HTCM            hTCM,                          // in
    TSM_FLAG            statusFlag,                    // in
    TSM_BOOL*           pfTpmState                     // out
);

TSPICALL Tspi_TCM_GetCapability
(
    TSM_HTCM            hTCM,                          // in
    TSM_FLAG            capArea,                       // in
    UINT32              ulSubCapLength,                // in
    BYTE*               rgbSubCap,                     // in
    UINT32*             pulRespDataLength,             // out
    BYTE**              prgbRespData                   // out
);

TSPICALL Tspi_TCM_GetCapabilitySigned
(
    TSM_HTCM            hTCM,                          // in
    TSM_HKEY            hKey,                          // in
    TSM_FLAG            capArea,                       // in
    UINT32              ulSubCapLength,                // in
    BYTE*               rgbSubCap,                     // in
    TSM_VALIDATION*     pValidationData,               // in, out
    UINT32*             pulRespDataLength,             // out
    BYTE**              prgbRespData                   // out
);

TSPICALL Tspi_TCM_SelfTestFull
(
    TSM_HTCM            hTCM                           // in
);

TSPICALL Tspi_TCM_CertifySelfTest
(
    TSM_HTCM            hTCM,                          // in
    TSM_HKEY            hKey,                          // in
    TSM_VALIDATION*     pValidationData                // in, out
);

TSPICALL Tspi_TCM_GetTestResult
(
    TSM_HTCM            hTCM,                          // in
    UINT32*             pulTestResultLength,           // out
    BYTE**              prgbTestResult                 // out
);
*/
TSM_RESULT Tspi_TCM_GetRandom
(
    TSM_HTCM            hTCM,                          // in
    UINT32              ulRandomDataLength,            // in
    BYTE**              prgbRandomData                 // out
);
/*
TSPICALL Tspi_TCM_StirRandom
(
    TSM_HTCM            hTCM,                          // in
    UINT32              ulEntropyDataLength,           // in
    BYTE*               rgbEntropyData                 // in
);

TSPICALL Tspi_TCM_GetEvent
(
    TSM_HTCM            hTCM,                          // in
    UINT32              ulPcrIndex,                    // in
    UINT32              ulEventNumber,                 // in
    TSM_PCR_EVENT*      pPcrEvent                      // out
);

TSPICALL Tspi_TCM_GetEvents
(
    TSM_HTCM            hTCM,                          // in
    UINT32              ulPcrIndex,                    // in
    UINT32              ulStartNumber,                 // in
    UINT32*             pulEventNumber,                // in, out
    TSM_PCR_EVENT**     prgPcrEvents                   // out
);

TSPICALL Tspi_TCM_GetEventLog
(
    TSM_HTCM            hTCM,                          // in
    UINT32*             pulEventNumber,                // out
    TSM_PCR_EVENT**     prgPcrEvents                   // out
);

TSPICALL Tspi_TCM_Quote
(
    TSM_HTCM            hTCM,                          // in
    TSM_HKEY            hIdentKey,                     // in
    TSM_HPCRS           hPcrComposite,                 // in
    TSM_VALIDATION*     pValidationData                // in, out
);

TSPICALL Tspi_TCM_Quote2
(
    TSM_HTCM            hTCM,                          // in
    TSM_HKEY            hIdentKey,                     // in
    TSM_BOOL            fAddVersion,                   // in
    TSM_HPCRS           hPcrComposite,                 // in
    TSM_VALIDATION*     pValidationData,               // in, out
    UINT32*             versionInfoSize,               // out
    BYTE**              versionInfo                    // out
);

TSPICALL Tspi_TCM_AuthorizeMigrationTicket
(
    TSM_HTCM            hTCM,                          // in
    TSM_HKEY            hMigrationKey,                 // in
    TSM_MIGRATE_SCHEME  migrationScheme,               // in
    UINT32*             pulMigTicketLength,            // out
    BYTE**              prgbMigTicket                  // out
);

TSPICALL Tspi_TCM_CMKSetRestrictions
(
    TSM_HTCM            hTCM,                          // in
    TSM_CMK_DELEGATE    CmkDelegate                    // in
);

TSPICALL Tspi_TCM_CMKApproveMA
(
    TSM_HTCM            hTCM,                          // in
    TSM_HMIGDATA        hMaAuthData                    // in
);

TSPICALL Tspi_TCM_CMKCreateTicket
(
    TSM_HTCM            hTCM,                          // in
    TSM_HKEY            hVerifyKey,                    // in
    TSM_HMIGDATA        hSigData                       // in
);

TSPICALL Tspi_TCM_ReadCounter
(
    TSM_HTCM            hTCM,                          // in
    UINT32*             counterValue                   // out
);

TSPICALL Tspi_TCM_ReadCurrentTicks
(
    TSM_HTCM            hTCM,                          // in
    TCM_CURRENT_TICKS*  tickCount                      // out
);

TSPICALL Tspi_TCM_DirWrite
(
    TSM_HTCM            hTCM,                          // in
    UINT32              ulDirIndex,                    // in
    UINT32              ulDirDataLength,               // in
    BYTE*               rgbDirData                     // in
);

TSPICALL Tspi_TCM_DirRead
(
    TSM_HTCM            hTCM,                          // in
    UINT32              ulDirIndex,                    // in
    UINT32*             pulDirDataLength,              // out
    BYTE**              prgbDirData                    // out
);

TSPICALL Tspi_TCM_Delegate_AddFamily
(
    TSM_HTCM            hTCM,                          // in, must not be NULL
    BYTE                bLabel,                        // in
    TSM_HDELFAMILY*     phFamily                       // out
);

TSPICALL Tspi_TCM_Delegate_GetFamily
(
    TSM_HTCM            hTCM,                          // in, must not NULL
    UINT32              ulFamilyID,                    // in
    TSM_HDELFAMILY*     phFamily                       // out
);

TSPICALL Tspi_TCM_Delegate_InvalidateFamily
(
    TSM_HTCM            hTCM,                          // in, must not be NULL
    TSM_HDELFAMILY      hFamily                        // in
);

TSPICALL Tspi_TCM_Delegate_CreateDelegation
(
    TSM_HOBJECT         hObject,                       // in
    BYTE                bLabel,                        // in
    UINT32              ulFlags,                       // in
    TSM_HPCRS           hPcr,                          // in, may be NULL
    TSM_HDELFAMILY      hFamily,                       // in
    TSM_HPOLICY         hDelegation                    // in, out
);

TSPICALL Tspi_TCM_Delegate_CacheOwnerDelegation
(
    TSM_HTCM            hTCM,                          // in, must not be NULL
    TSM_HPOLICY         hDelegation,                   // in, out
    UINT32              ulIndex,                       // in
    UINT32              ulFlags                        // in
);

TSPICALL Tspi_TCM_Delegate_UpdateVerificationCount
(
    TSM_HTCM            hTCM,                          // in
    TSM_HPOLICY         hDelegation                    // in, out
);

TSPICALL Tspi_TCM_Delegate_VerifyDelegation
(
    TSM_HPOLICY         hDelegation                    // in, out
);

TSPICALL Tspi_TCM_Delegate_ReadTables
(
    TSM_HCONTEXT                  hContext,                      // in
    UINT32*                       pulFamilyTableSize,            // out
    TSM_FAMILY_TABLE_ENTRY**      ppFamilyTable,                 // out
    UINT32*                       pulDelegateTableSize,          // out
    TSM_DELEGATION_TABLE_ENTRY**  ppDelegateTable                // out
);

TSPICALL Tspi_TCM_DAA_JoinInit
(
    TSM_HTCM                      hTCM,                          // in
    TSM_HDAA_ISSUER_KEY           hIssuerKey,                    // in
    UINT32                        daaCounter,                    // in
    UINT32                        issuerAuthPKsLength,           // in
    TSM_HKEY*                     issuerAuthPKs,                 // in
    UINT32                        issuerAuthPKSignaturesLength,  // in
    UINT32                        issuerAuthPKSignaturesLength2, // in
    BYTE**                        issuerAuthPKSignatures,        // in
    UINT32*                       capitalUprimeLength,           // out
    BYTE**                        capitalUprime,                 // out
    TSM_DAA_IDENTITY_PROOF**      identityProof,                 // out
    UINT32*                       joinSessionLength,             // out
    BYTE**                        joinSession                    // out
);

TSPICALL Tspi_TCM_DAA_JoinCreateDaaPubKey
(
    TSM_HTCM                      hTCM,                          // in
    TSM_HDAA_CREDENTIAL           hDAACredential,                // in
    UINT32                        authenticationChallengeLength, // in
    BYTE*                         authenticationChallenge,       // in
    UINT32                        nonceIssuerLength,             // in
    BYTE*                         nonceIssuer,                   // in
    UINT32                        attributesPlatformLength,      // in
    UINT32                        attributesPlatformLength2,     // in
    BYTE**                        attributesPlatform,            // in
    UINT32                        joinSessionLength,             // in
    BYTE*                         joinSession,                   // in
    TSM_DAA_CREDENTIAL_REQUEST**  credentialRequest              // out
);

TSPICALL Tspi_TCM_DAA_JoinStoreCredential
(
    TSM_HTCM                      hTCM,                          // in
    TSM_HDAA_CREDENTIAL           hDAACredential,                // in
    TSM_DAA_CRED_ISSUER*          credIssuer,                    // in
    UINT32                        joinSessionLength,             // in
    BYTE*                         joinSession                    // in
);

TSPICALL Tspi_TCM_DAA_Sign
(
    TSM_HTCM                      hTCM,                          // in
    TSM_HDAA_CREDENTIAL           hDAACredential,                // in
    TSM_HDAA_ARA_KEY              hARAKey,                       // in
    TSM_DAA_SELECTED_ATTRIB*      revealAttributes,              // in
    UINT32                        verifierNonceLength,           // in
    BYTE*                         verifierNonce,                 // in
    UINT32                        verifierBaseNameLength,        // in
    BYTE*                         verifierBaseName,              // in
    TSM_HOBJECT                   signData,                      // in
    TSM_DAA_SIGNATURE**           daaSignature                   // out
);

TSPICALL Tspi_TCM_GetAuditDigest
(
    TSM_HTCM            hTCM,                          // in
    TSM_HKEY            hKey,                          // in
    TSM_BOOL            closeAudit,                    // in
    UINT32*             pulAuditDigestSize,            // out
    BYTE**              prgbAuditDigest,               // out
    TCM_COUNTER_VALUE*  pCounterValue,                 // out
    TSM_VALIDATION*     pValidationData,               // out
    UINT32*             ordSize,                       // out
    UINT32**            ordList                        // out
);



// PcrComposite Class Definitions
TSPICALL Tspi_PcrComposite_SelectPcrIndex
(
    TSM_HPCRS           hPcrComposite,                 // in
    UINT32              ulPcrIndex                     // in
);
*/
TSM_RESULT Tspi_PcrComposite_SelectPcrIndex
(
    TSM_HPCRS           hPcrComposite,                 // in
    UINT32              ulPcrIndex,                    // in
    UINT32              Direction                      // in
);
/*
TSPICALL Tspi_PcrComposite_SetPcrValue
(
    TSM_HPCRS           hPcrComposite,                 // in
    UINT32              ulPcrIndex,                    // in
    UINT32              ulPcrValueLength,              // in
    BYTE*               rgbPcrValue                    // in
);

TSPICALL Tspi_PcrComposite_GetPcrValue
(
    TSM_HPCRS           hPcrComposite,                 // in
    UINT32              ulPcrIndex,                    // in
    UINT32*             pulPcrValueLength,             // out
    BYTE**              prgbPcrValue                   // out
);

TSPICALL Tspi_PcrComposite_SetPcrLocality
(
    TSM_HPCRS           hPcrComposite,                 // in
    UINT32              LocalityValue                  // in
);

TSPICALL Tspi_PcrComposite_GetPcrLocality
(
    TSM_HPCRS           hPcrComposite,                 // in
    UINT32*             pLocalityValue                 // out
);

TSPICALL Tspi_PcrComposite_GetCompositeHash
(
    TSM_HPCRS           hPcrComposite,                 // in
    UINT32*             pLen,                          // in
    BYTE**              ppbHashData                    // out
);



// Key Class Definition
TSPICALL Tspi_Key_LoadKey
(
    TSM_HKEY            hKey,                          // in
    TSM_HKEY            hUnwrappingKey                 // in
);

TSPICALL Tspi_Key_UnloadKey
(
    TSM_HKEY            hKey                           // in
);

TSPICALL Tspi_Key_GetPubKey
(
    TSM_HKEY            hKey,                          // in
    UINT32*             pulPubKeyLength,               // out
    BYTE**              prgbPubKey                     // out
);

TSPICALL Tspi_Key_CertifyKey
(
    TSM_HKEY            hKey,                          // in
    TSM_HKEY            hCertifyingKey,                // in
    TSM_VALIDATION*     pValidationData                // in, out
);

TSPICALL Tspi_Key_CreateKey
(
    TSM_HKEY            hKey,                          // in
    TSM_HKEY            hWrappingKey,                  // in
    TSM_HPCRS           hPcrComposite                  // in, may be NULL
);

TSPICALL Tspi_Key_WrapKey
(
    TSM_HKEY            hKey,                          // in
    TSM_HKEY            hWrappingKey,                  // in
    TSM_HPCRS           hPcrComposite                  // in, may be NULL
);

TSPICALL Tspi_Key_CreateMigrationBlob
(
    TSM_HKEY            hKeyToMigrate,                 // in
    TSM_HKEY            hParentKey,                    // in
    UINT32              ulMigTicketLength,             // in
    BYTE*               rgbMigTicket,                  // in
    UINT32*             pulRandomLength,               // out
    BYTE**              prgbRandom,                    // out
    UINT32*             pulMigrationBlobLength,        // out
    BYTE**              prgbMigrationBlob              // out
);

TSPICALL Tspi_Key_ConvertMigrationBlob
(
    TSM_HKEY            hKeyToMigrate,                 // in
    TSM_HKEY            hParentKey,                    // in
    UINT32              ulRandomLength,                // in
    BYTE*               rgbRandom,                     // in
    UINT32              ulMigrationBlobLength,         // in
    BYTE*               rgbMigrationBlob               // in
);

TSPICALL Tspi_Key_MigrateKey
(
    TSM_HKEY            hMaKey,                        // in
    TSM_HKEY            hPublicKey,                    // in
    TSM_HKEY            hMigData                       // in
);

TSPICALL Tspi_Key_CMKCreateBlob
(
    TSM_HKEY            hKeyToMigrate,                 // in
    TSM_HKEY            hParentKey,                    // in
    TSM_HMIGDATA        hMigrationData,                // in
    UINT32*             pulRandomLength,               // out
    BYTE**              prgbRandom                     // out
);

TSPICALL Tspi_Key_CMKConvertMigration
(
    TSM_HKEY            hKeyToMigrate,                 // in
    TSM_HKEY            hParentKey,                    // in
    TSM_HMIGDATA        hMigrationData,                // in
    UINT32              ulRandomLength,                // in
    BYTE*               rgbRandom                      // in
);



// Hash Class Definition
TSPICALL Tspi_Hash_Sign
(
    TSM_HHASH           hHash,                         // in
    TSM_HKEY            hKey,                          // in
    UINT32*             pulSignatureLength,            // out
    BYTE**              prgbSignature                  // out
);

TSPICALL Tspi_Hash_VerifySignature
(
    TSM_HHASH           hHash,                         // in
    TSM_HKEY            hKey,                          // in
    UINT32              ulSignatureLength,             // in
    BYTE*               rgbSignature                   // in
);

TSPICALL Tspi_Hash_SetHashValue
(
    TSM_HHASH           hHash,                         // in
    UINT32              ulHashValueLength,             // in
    BYTE*               rgbHashValue                   // in
);

TSPICALL Tspi_Hash_GetHashValue
(
    TSM_HHASH           hHash,                         // in
    UINT32*             pulHashValueLength,            // out
    BYTE**              prgbHashValue                  // out
);

TSPICALL Tspi_Hash_UpdateHashValue
(
    TSM_HHASH           hHash,                         // in
    UINT32              ulDataLength,                  // in
    BYTE*               rgbData                        // in
);

TSPICALL Tspi_Hash_TickStampBlob
(
    TSM_HHASH           hHash,                         // in
    TSM_HKEY            hIdentKey,                     // in
    TSM_VALIDATION*     pValidationData                // in
);



// EncData Class Definition
TSPICALL Tspi_Data_Bind
(
    TSM_HENCDATA        hEncData,                      // in
    TSM_HKEY            hEncKey,                       // in
    UINT32              ulDataLength,                  // in
    BYTE*               rgbDataToBind                  // in
);

TSPICALL Tspi_Data_Unbind
(
    TSM_HENCDATA        hEncData,                      // in
    TSM_HKEY            hKey,                          // in
    UINT32*             pulUnboundDataLength,          // out
    BYTE**              prgbUnboundData                // out
);

TSPICALL Tspi_Data_Seal
(
    TSM_HENCDATA        hEncData,                      // in
    TSM_HKEY            hEncKey,                       // in
    UINT32              ulDataLength,                  // in
    BYTE*               rgbDataToSeal,                 // in
    TSM_HPCRS           hPcrComposite                  // in
);

TSPICALL Tspi_Data_Unseal
(
    TSM_HENCDATA        hEncData,                      // in
    TSM_HKEY            hKey,                          // in
    UINT32*             pulUnsealedDataLength,         // out
    BYTE**              prgbUnsealedData               // out
);



// NV Class Definition
TSPICALL Tspi_NV_DefineSpace
(
    TSM_HNVSTORE        hNVStore,                      // in
    TSM_HPCRS           hReadPcrComposite,             // in, may be NULL
    TSM_HPCRS           hWritePcrComposite             // in, may be NULL
);

TSPICALL Tspi_NV_ReleaseSpace
(
    TSM_HNVSTORE        hNVStore                       // in
);

TSPICALL Tspi_NV_WriteValue
(
    TSM_HNVSTORE        hNVStore,                      // in
    UINT32              offset,                        // in
    UINT32              ulDataLength,                  // in
    BYTE*               rgbDataToWrite                 // in
);

TSPICALL Tspi_NV_ReadValue
(
    TSM_HNVSTORE        hNVStore,                      // in
    UINT32              offset,                        // in
    UINT32*             ulDataLength,                  // in, out
    BYTE**              rgbDataRead                    // out
);

*/

#if defined ( __cplusplus )
}
#endif /* __cplusplus */


#endif /* _TSPI_H_ */
