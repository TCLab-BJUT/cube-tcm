#ifndef VTCM_NV_H
#define VTCM_NV_H

#include "../../include/tcm_structures.h"
#include "../../include/tcm_global.h"
#include "../../include/app_struct.h"

#define ERR_MASK 0x80000000
#define TCM_MAX_BUFF_SIZE 4096

//typedef unsigned int uint16_t;
//typedef long unsigned int uint32_t;
//typedef unsigned long long uint64_t;

//typedef uint32_t UINT32;
//typedef uint16_t UINT16;
//typedef uint64_t UINT64;
//typedef unsigned char BYTE;
//typedef UINT32 TCM_NV_INDEX;
//typedef UINT16 TCM_STRUCTURE_TAG;
//typedef BYTE TCM_LOCALITY_SELECTION;


/*typedef struct tdTCM_NV_DATA_PUBLIC {
	TCM_STRUCTURE_TAG tag;
	TCM_NV_INDEX nvIndex;
	UINT32 dataSize;
} TCM_NV_DATA_PUBLIC;

typedef struct tdTCM_NV_DATA_SENSITIVE {
	TCM_STRUCTURE_TAG tag;
	TCM_NV_DATA_PUBLIC pubInfo;
	BYTE* data;
} TCM_NV_DATA_SENSITIVE;*/

int vtcm_nv_init(void * sub_proc,void * para);
int vtcm_nv_start(void * sub_proc,void * para);


struct vtcm_nv_scene
{
        int nv_count; //MAX count of NV
        int size;
        TCM_NV_DATA_SENSITIVE  *nv;    
}__attribute__((packed));


#endif

