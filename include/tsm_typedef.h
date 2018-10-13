/*++

Global typedefs for TSM
 
*/

#ifndef __TSM_TYPEDEF_H__
#define __TSM_TYPEDEF_H__

//--------------------------------------------------------------------
// definitions for TSM Service Provider (TSP)
//
typedef  char    TSM_BOOL;
typedef  UINT16  TSM_UNICODE;

#define  TRUE    0x01
#define  FALSE   0x00
typedef  UINT32  TSM_HANDLE;

typedef  UINT32  TSM_FLAG;  // object attributes
typedef  UINT32  TSM_HOBJECT;     // basic object handle
typedef  UINT32  TSM_ALGORITHM_ID;
typedef  UINT32  TSM_KEY_USAGE_ID;
typedef  UINT16  TSM_KEY_ENC_SCHEME;
typedef  UINT16  TSM_KEY_SIG_SCHEME;
typedef  UINT32  TSM_EVENTTYPE;
typedef  UINT32  TSM_COUNTER_ID;
typedef  UINT32  TSM_RESULT;  // the return code from a TSM function

typedef  TSM_HOBJECT     TSM_HCONTEXT;    // context object handle
typedef  TSM_HOBJECT     TSM_HPOLICY;     // policy object handle
typedef  TSM_HOBJECT     TSM_HTCM;        // TCM object handle
typedef  TSM_HOBJECT     TSM_HKEY;        // key object handle
typedef  TSM_HOBJECT     TSM_HENCDATA;    // encrypted data object handle
typedef  TSM_HOBJECT     TSM_HPCRS;       // PCR composite object handle
typedef  TSM_HOBJECT     TSM_HHASH;       // hash object handle
typedef  TSM_HOBJECT     TSM_HNVSTORE;    // NV storage object handle
typedef  TSM_HOBJECT     TSM_HMIGDATA;    // migration data utility obj handle
typedef  TSM_HOBJECT     TSM_HEXCHANGE;   // key exchange obj handle

typedef UINT32  TSM_NV_INDEX;

#endif // __TSM_TYPEDEF_H__

