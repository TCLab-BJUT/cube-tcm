/********************************************************************************/
/*                                                                              */
/*                           Global Variables                                   */
/*                           Written by Ken Goldman                             */
/*                     IBM Thomas J. Watson Research Center                     */
/*            $Id: tcm_global.h 4285 2011-01-17 21:27:05Z kgoldman $            */
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

#ifndef TCM_GLOBAL_H
#define TCM_GLOBAL_H

//#include "tcm_nvram_const.h"
#include "tcm_types.h"
#include "tcm_structures.h"

#define TCM_TEST_STATE_LIMITED  1       /* limited operation mode */
#define TCM_TEST_STATE_FULL     2       /* full operation mode */
#define TCM_TEST_STATE_FAILURE  3       /* failure mode */

typedef struct tdTCM_STATE
{
    /* the number of the virtual TCM */
    uint32_t tcm_number;
    /* 7.1 TCM_PERMANENT_FLAGS */
    TCM_PERMANENT_FLAGS tcm_permanent_flags; 
    /* 7.2 TCM_STCLEAR_FLAGS */
    TCM_STCLEAR_FLAGS tcm_stclear_flags;
    /* 7.3 TCM_STANY_FLAGS  */
    TCM_STANY_FLAGS tcm_stany_flags;
    /* 7.4 TCM_PERMANENT_DATA */
    TCM_PERMANENT_DATA tcm_permanent_data;
    /* 7.5 TCM_STCLEAR_DATA  */
    TCM_STCLEAR_DATA tcm_stclear_data;
    /* 7.6 TCM_STANY_DATA  */
    TCM_STANY_DATA tcm_stany_data;
    /* 5.6 TCM_KEY_HANDLE_ENTRY */
    TCM_KEY_HANDLE_ENTRY tcm_key_handle_entries[TCM_KEY_HANDLES];
    /* Context for SHA1 functions */
    void *sm3_context;
    void *sm3_context_tis;
    TCM_TRANSHANDLE transportHandle;    /* non-zero if the context was set up in a transport
                                           session */
    /* self test shutdown */
    uint32_t testState;
    /* NVRAM volatile data marker.  Cleared at TCM_Startup(ST_Clear), it holds all indexes which
       have been read.  The index not being present indicates that some volatile fields should be
       cleared at first read. */
    TCM_NV_INDEX_ENTRIES tcm_nv_index_entries;
    /* NOTE: members added here should be initialized by TCM_Global_Init() and possibly added to
       TCM_SaveState_Load() and TCM_SaveState_Store() */
}__attribute__((packed)) tcm_state_t ;

/* state for the TCM */
//extern tcm_state_t *tcm_instances[];


/*
  tcm_state_t
*/

TCM_RESULT TCM_Global_Init(tcm_state_t *tcm_state);
TCM_RESULT TCM_Global_Load(tcm_state_t *tcm_state);
TCM_RESULT TCM_Global_Store(tcm_state_t *tcm_state);
void       TCM_Global_Delete(tcm_state_t *tcm_state);


TCM_RESULT TCM_Global_GetPhysicalPresence(TCM_BOOL *physicalPresence,
                                          const tcm_state_t *tcm_state);

#endif
