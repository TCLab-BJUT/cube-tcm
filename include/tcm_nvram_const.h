/********************************************************************************/
/*                                                                              */
/*                              NVRAM Constants                                 */
/*                           Written by Ken Goldman                             */
/*                     IBM Thomas J. Watson Research Center                     */
/*            $Id: tcm_nvram_const.h 4528 2011-03-29 22:16:28Z kgoldman $       */
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

#ifndef TCM_NVRAM_CONST_H
#define TCM_NVRAM_CONST_H

/*
  These are implementation specific constants
*/

/*
  TCMS_MAX defines the maximum number of TCM instances.
*/

#define TCMS_MAX        1

/*
  NVRAM storage directory path
*/


#ifdef TCM_NV_DISK
/* TCM_NV_DISK uses the TCM_PATH environment variable */
#endif

/* Defines the maximum size of the NV defined space, the NV indexes created by TCM_NV_DefineSpace.

   The PC Client requires 2048 bytes.  There is at least (currently) 6 bytes of overhead, a tag and
   a count.
*/

#ifndef TCM_MAX_NV_DEFINED_SIZE
#define TCM_MAX_NV_DEFINED_SIZE 2100
#endif

/* TCM_MAX_NV_SPACE defines the maximum NV space for non-volatile state.

   It does not include the area used for TCM_SaveState.

   See TCM_OWNER_EVICT_KEY_HANDLES, TCM_MIN_COUNTERS, TCM_NUM_FAMILY_TABLE_ENTRY_MIN,
   TCM_NUM_DELEGATE_TABLE_ENTRY_MIN, etc. and the platform specific requirements for NV defined
   space.
*/

#ifndef TCM_MAX_NV_SPACE 



#ifdef TCM_NV_DISK
#define TCM_MAX_NV_SPACE 100000	/* arbitrary value */
#endif

#endif /* TCM_MAX_NV_SPACE */

#ifndef TCM_MAX_NV_SPACE
#error "TCM_MAX_NV_SPACE is not defined"
#endif

/* TCM_MAX_SAVESTATE_SPACE defines the maximum NV space for TCM saved state.

   It is used by TCM_SaveState

   NOTE This macro is based on the maximum number of loaded keys and session.  For example, 3 loaded
   keys, 3 OSAP sessions, and 1 transport session consumes about 2500 bytes.

   See TCM_KEY_HANDLES, TCM_NUM_PCR, TCM_MIN_AUTH_SESSIONS, TCM_MIN_TRANS_SESSIONS,
   TCM_MIN_DAA_SESSIONS, TCM_MIN_SESSION_LIST, etc.
*/

#ifndef TCM_MAX_SAVESTATE_SPACE 



#ifdef TCM_NV_DISK
#define TCM_MAX_SAVESTATE_SPACE 100000	/* arbitrary value */
#endif

#endif	/* TCM_MAX_SAVESTATE_SPACE */

#ifndef TCM_MAX_SAVESTATE_SPACE
#error "TCM_MAX_SAVESTATE_SPACE is not defined"
#endif

/* TCM_MAX_VOLATILESTATE_SPACE defines the maximum NV space for TCM volatile state.

   It is used for applications that save and restore the entire TCM volatile is a non-standard way.
*/

#ifndef TCM_MAX_VOLATILESTATE_SPACE 


#ifdef TCM_NV_DISK
#define TCM_MAX_VOLATILESTATE_SPACE 524288	/* arbitrary value */
#endif

#endif /* TCM_MAX_VOLATILESTATE_SPACE */

#ifndef TCM_MAX_VOLATILESTATE_SPACE
#error "TCM_MAX_VOLATILESTATE_SPACE is not defined"
#endif

#endif
