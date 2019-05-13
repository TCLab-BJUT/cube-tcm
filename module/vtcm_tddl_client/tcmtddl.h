#include<stdio.h>
#include<stdlib.h>
#include"data_type.h"
//typedef HRESULT TSM_RESULT;/

typedef unsigned long   ULONG;
typedef long TSM_RESULT;
#define TDDL_SUCCESS 0L
typedef struct {
	char	*pBuffer;
	ULONG	nBufferLen;
	ULONG	nError;
} TCM_INFO_STRUCT;

typedef struct{
	DWORD nOrdinal;
	DWORD nCommandCode;
} COMMAND_TO_SML;


#define TDDL_DRIVER_STATUS 0x0001
#define TDDL_DEVICE_STATUS 0x0002

#define	TDDL_DRIVER_OK			0x0000
#define	TDDL_DRIVER_FAILED		0x0001
#define	TDDL_DRIVER_NOT_OPENED	0x0002

#define	TDDL_DEVICE_OK				0x0000
#define	TDDL_DEVICE_UNRECOVERABLE	0x0001
#define	TDDL_DEVICE_RECOVERABLE		0x0002
#define	TDDL_DEVICE_NOT_FOUND		0x0003


//From tddli.h----yinping
#define TDDL_CAP_VERSION   0x0100
#define TDDL_CAP_VER_DRV   0x0101
#define TDDL_CAP_VER_FW    0x0102
#define TDDL_CAP_VER_FW_DATE   0x0103
#define TDDL_CAP_PROPERTY   0x0200
#define TDDL_CAP_PROP_MANUFACTURER  0x0201
#define TDDL_CAP_PROP_MODULE_TYPE  0x0202
#define TDDL_CAP_PROP_GLOBAL_STATE  0x0203

__attribute__((visibility("default"))) TSM_RESULT Tddli_open();		  
__attribute__((visibility("default"))) TSM_RESULT Tddli_close();
__attribute__((visibility("default"))) TSM_RESULT Tddli_TransmitData(BYTE* pTransmitBuf,UINT32 TransmitBufLen,BYTE    * pReceiveBuf,UINT32* pReceiveBufLen);
