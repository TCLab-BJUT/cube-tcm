#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <dirent.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <stdbool.h>

#include "data_type.h"
#include "errno.h"
#include "alloc.h"
#include "string.h"
#include "basefunc.h"
#include "struct_deal.h"
#include "crypto_func.h"
#include "memdb.h"
#include "message.h"
#include "ex_module.h"
#include "sys_func.h"

#include "file_struct.h"
#include "tesi_key.h"
#include "tesi_aik_struct.h"
#include "vtcm_state.h"

#include "app_struct.h"
#include "tcm_global.h"
#include "tcm_error.h"
#include "tcm_authlib.h"

#define LOAD32(buffer,offset)   (ntohl(*(uint32_t *)&(buffer)[(offset)])) 

static int proc_vtcm_GetCapability(void * sub_proc,void * recv_msg);
static int proc_vtcm_SetCapability(void * sub_proc,void * recv_msg);

int vtcm_state_init(void * sub_proc,void * para)
{
    tcm_state_t * tcm_instances = proc_share_data_getpointer();
    
    printf("tcm_permanent_data->revMajor  abc\n");
    ex_module_setpointer(sub_proc,&tcm_instances[0]);
    // prepare the slot sock
    return 0;
}

int vtcm_state_start(void * sub_proc,void * para)
{
    int ret;
    int retval;
    void * recv_msg;
    void * context;
    int i;
    int type;
    int subtype;
    void * sock;
    BYTE uuid[DIGEST_SIZE];
    int vtcm_no;

    printf("vtcm_state module start!\n");

    for(i = 0 ;i < 300*1000 ;i++)
    {
        usleep(time_val.tv_usec);
        ret = ex_module_recvmsg(sub_proc,&recv_msg);
        if(ret < 0)
            continue;
        if(recv_msg == NULL)
            continue;
        type = message_get_type(recv_msg);
        subtype = message_get_subtype(recv_msg);

 	// set vtcm instance
     	vtcm_no = vtcm_setscene(sub_proc,recv_msg);
     	if(vtcm_no<0)
     	{
 		printf("Non_exist vtcm copy!\n");
     	}

        if(type == DTYPE_VTCM_IN)
        {
            switch(subtype)
            {
                case SUBTYPE_STARTUP_IN:
                    proc_vtcm_Startup(sub_proc,recv_msg) ;
                    break;
                case SUBTYPE_GETCAPABILITY_IN:
                    proc_vtcm_GetCapability(sub_proc,recv_msg) ;
                    break;
                case SUBTYPE_SETCAPABILITY_IN:
                    proc_vtcm_SetCapability(sub_proc,recv_msg) ;
                    break;
                case SUBTYPE_PHYSICALPRESENCE_IN:
                    //proc_vtcm_physicalpresence(sub_proc ,recv_msg) ;
                    break ;
                case SUBTYPE_PHYSICALENABLE_IN:
		            proc_vtcm_PhysicalEnable(sub_proc ,recv_msg) ;
                    break ;
		        case SUBTYPE_PHYSICALSETDEACTIVATED_IN:
		            proc_vtcm_PhysicalSetDeactivated(sub_proc ,recv_msg) ;
                    break;
		        case SUBTYPE_PHYSICALDISABLE_IN:
		            proc_vtcm_PhysicalDisable(sub_proc ,recv_msg) ;
                    break;
		        case SUBTYPE_DISABLEOWNERCLEAR_IN:
		            proc_vtcm_DisableOwnerClear(sub_proc ,recv_msg) ;
                    break;
                case SUBTYPE_GETRANDOM_IN:
                    proc_vtcm_GetRandom(sub_proc,recv_msg) ;
                    break;
                case SUBTYPE_SELFTESTFULL_IN:
                    proc_vtcm_SelfTestFull(sub_proc,recv_msg) ;
                    break;
                case SUBTYPE_FORCECLEAR_IN:
                    proc_vtcm_ForceClear(sub_proc,recv_msg) ;
                    break;
                case SUBTYPE_DISABLEFORCECLEAR_IN:
                    proc_vtcm_DisableForceClear(sub_proc,recv_msg) ;
                    break;
                case SUBTYPE_CONTINUESELFTEST_IN:
                    proc_vtcm_ContinueSelfTest(sub_proc,recv_msg) ;
                    break;
                case SUBTYPE_GETTESTRESULT_IN:
                    proc_vtcm_GetTestResult(sub_proc,recv_msg) ;
                    break;
                case SUBTYPE_OWNERCLEAR_IN:
                    proc_vtcm_OwnerClear(sub_proc,recv_msg) ;
                    break;
                case SUBTYPE_FLUSHSPECIFIC_IN:
                    proc_vtcm_FlushSpecific(sub_proc,recv_msg) ;
                    break;
		        default:
                    break;
            }        
        }
    }

    return 0 ;
};


int proc_vtcm_Startup(void * sub_proc, void * recv_msg)
{
    printf("proc_vtcm_Startup : Start\n");
    int ret = 0;
    int i = 0;

    struct tcm_in_Startup * tcm_Startup_in;

    ret = message_get_record(recv_msg, &tcm_Startup_in, 0);
    if(ret < 0)
        return ret;
    if(tcm_Startup_in == NULL)
        return -EINVAL;

    //output
    void * command_template = memdb_get_template(DTYPE_VTCM_OUT,SUBTYPE_STARTUP_OUT);
    if(command_template == NULL)
    {
        printf("can't solve this command!\n");
    }
    struct tcm_out_Startup * tcm_Startup_out = malloc(struct_size(command_template));
    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);

    /*
     *Processing
    */
    switch(tcm_Startup_in->startupType) {
        case TCM_ST_CLEAR:
            {
                printf("TCM_Startup_Clear:\n");
                
                //Set the resource handle invalided

                memset(tcm_state->tcm_stclear_data.contextNonceKey,0,sizeof(BYTE)*TCM_NONCE_SIZE);
                tcm_state->tcm_stclear_data.disableResetLock = FALSE;
                memset(tcm_state->tcm_stany_data.contextNonceSession,0,sizeof(BYTE)*TCM_NONCE_SIZE);
                tcm_state->tcm_stany_data.contextCount = 0;
                for(int i = 0; i < TCM_MIN_SESSION_LIST; i++){
                    tcm_state->tcm_stany_data.contextList[i] = 0;
                }
                memset(tcm_state->tcm_stany_data.auditDigest.digest,0,sizeof(BYTE)*TCM_DIGEST_SIZE);

                break;
            }
        case TCM_ST_STATE:
            {
                if(ret != TCM_SUCCESS)  {
                    printf("TCM_Startup_State: Error restoring state\n");
                    ret = TCM_FAILEDSELFTEST;
                    printf("TCM_Strtup_State: Set testState to %u \n",TCM_TEST_STATE_FAILURE);
                    tcm_state->testState = TCM_TEST_STATE_FAILURE;
                }
                break;
            }
        case TCM_ST_DEACTIVATED:
            {
                printf("TCM_Startup_Deactivated:\n");
                if(ret == TCM_SUCCESS) {
                    tcm_state->tcm_stclear_flags.deactivated = TRUE;
                }
                break;
            }
        default:
            break;
    }

    tcm_Startup_out->tag = 0xC400;
    tcm_Startup_out->paramSize = 0x0A;
    tcm_Startup_out->returnCode = 0;
    void *send_msg = message_create(DTYPE_VTCM_OUT,SUBTYPE_STARTUP_OUT,recv_msg);
    if(send_msg == NULL)
        return -EINVAL ;
    message_add_record(send_msg ,tcm_Startup_out) ;

     // add vtcm's expand info	
    ret=vtcm_addcmdexpand(send_msg,recv_msg);
    if(ret<0)
    {
	printf("fail to add vtcm copy info!\n");
    }	
    ret = ex_module_sendmsg(sub_proc ,send_msg) ;
                                            
    return ret;
}

int proc_vtcm_PhysicalEnable(void * sub_proc,void * recv_msg)
{
    printf("proc_vtcm_PhysicalEnable : Start\n") ;
    int ret = 0 ;
    int i = 0 ;
    
    struct tcm_in_PhysicalEnable *vtcm_PhysicalEnable_in ;

    ret = message_get_record(recv_msg, (void **)&vtcm_PhysicalEnable_in, 0) ; // get structure 
    if(ret < 0)
        return ret ;
    if(vtcm_PhysicalEnable_in == NULL)
        return -EINVAL ;

    //output process
    void * command_template = memdb_get_template(DTYPE_VTCM_OUT,SUBTYPE_PHYSICALENABLE_OUT) ;//Get the entire command template
    if(command_template == NULL)
    {
        printf("can't solve this command!\n");
    }
    struct tcm_out_PhysicalEnable * vtcm_PhysicalEnable_out = malloc(struct_size(command_template)) ;

    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);
    /*
      Processing
    */
    /* 1. Validate that physical presence is being asserted, if not return TCM_BAD_PRESENCE */

    /* 2. The TCM SHALL set the TCM_PERMANENT_FLAGS.disable value to FALSE. */
    tcm_state->tcm_permanent_flags.disable = FALSE ;    
    
    
    //Response 

    vtcm_PhysicalEnable_out->tag = 0xC400 ;
    vtcm_PhysicalEnable_out->paramSize = 10 ;
    vtcm_PhysicalEnable_out->returnCode = 0 ;

    void *send_msg = message_create(DTYPE_VTCM_OUT,SUBTYPE_PHYSICALENABLE_OUT,recv_msg) ;
    if(send_msg == NULL)
        return -EINVAL ;
    message_add_record(send_msg ,vtcm_PhysicalEnable_out) ;

     // add vtcm's expand info	
    ret=vtcm_addcmdexpand(send_msg,recv_msg);
    if(ret<0)
    {
	printf("fail to add vtcm copy info!\n");
    }	
    ret = ex_module_sendmsg(sub_proc ,send_msg) ;

    return ret ;
}


int proc_vtcm_PhysicalDisable(void * sub_proc,void * recv_msg)
{
    printf("proc_vtcm_PhysicalDisable : Start\n");
    int ret = 0;
    int i = 0;

    struct tcm_in_PhysicalDisable *vtcm_PhysicalDisable_in ;

    ret = message_get_record(recv_msg, (void **)&vtcm_PhysicalDisable_in, 0) ; // get structure•
    if(ret < 0)
        return ret ;
    if(vtcm_PhysicalDisable_in == NULL)
        return -EINVAL ;

    //output process
    void * command_template = memdb_get_template(DTYPE_VTCM_OUT,SUBTYPE_PHYSICALDISABLE_OUT) ;//Get the entire command template
    if(command_template == NULL)
    {
        printf("can't solve this command!\n");
    }
    struct tcm_out_PhysicalDisable * vtcm_PhysicalDisable_out = malloc(struct_size(command_template)) ;

    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);
 
/*
    Processing
    */
    /* 1. Validate that physical presence is being asserted, if not return TCM_BAD_PRESENCE */

    /* 2. The TCM SHALL set the TCM_PERMANENT_FLAGS.disable value to TRUE */
    tcm_state->tcm_permanent_flags.disable = TRUE ;

    //Response
    vtcm_PhysicalDisable_out->tag = 0xC400 ;
    vtcm_PhysicalDisable_out->paramSize = 10 ;
    vtcm_PhysicalDisable_out->returnCode = 0 ;

    void *send_msg = message_create(DTYPE_VTCM_OUT,SUBTYPE_PHYSICALDISABLE_OUT,recv_msg) ;
    if(send_msg == NULL)
        return -EINVAL ;
    message_add_record(send_msg ,vtcm_PhysicalDisable_out) ;

     // add vtcm's expand info	
    ret=vtcm_addcmdexpand(send_msg,recv_msg);
    if(ret<0)
    {
	printf("fail to add vtcm copy info!\n");
    }	
    ret = ex_module_sendmsg(sub_proc ,send_msg) ;

    return ret ;
}


int proc_vtcm_PhysicalSetDeactivated(void * sub_proc,void * recv_msg)
{
    printf("proc_vtcm_PhysicalSetDeactivated : Start\n");
    int ret = 0;
    int i = 0;
    
    struct tcm_in_PhysicalSetDeactivated *vtcm_PhysicalSetDeactivated_in ;

    ret = message_get_record(recv_msg, (void **)&vtcm_PhysicalSetDeactivated_in, 0) ; // get structure•
    if(ret < 0)
        return ret ;
    if(vtcm_PhysicalSetDeactivated_in == NULL)
        return -EINVAL ;

    //output process
    void * command_template = memdb_get_template(DTYPE_VTCM_OUT,SUBTYPE_PHYSICALSETDEACTIVATED_OUT) ;//Get the entire command template
    if(command_template == NULL)
    {
        printf("can't solve this command!\n");
    }
    struct tcm_out_PhysicalSetDeactivated * vtcm_PhysicalSetDeactivated_out = malloc(struct_size(command_template)) ;

    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);

     /*
     Processing
     */
     /* 1. Validate that physical presence is being asserted, if not return TCM_BAD_PRESENCE */

    /* 2. The TCM SHALL set the TCM_PERMANENT_FLAGS.deactivated flag to the value in the state parameter （TCM的要求为tcm_stclear_flags的deactivated值设置为TRUE）*/
    tcm_state->tcm_stclear_flags.deactivated = TRUE ;
    //Response
    vtcm_PhysicalSetDeactivated_out->tag = 0xC400 ;
    vtcm_PhysicalSetDeactivated_out->paramSize = 10 ;
    vtcm_PhysicalSetDeactivated_out->returnCode = 0 ;
    
    void *send_msg = message_create(DTYPE_VTCM_OUT,SUBTYPE_PHYSICALSETDEACTIVATED_OUT,recv_msg) ;
    if(send_msg == NULL)
        return -EINVAL ;
    message_add_record(send_msg ,vtcm_PhysicalSetDeactivated_out) ;

     // add vtcm's expand info	
    ret=vtcm_addcmdexpand(send_msg,recv_msg);
    if(ret<0)
    {
	printf("fail to add vtcm copy info!\n");
    }	
    ret = ex_module_sendmsg(sub_proc ,send_msg) ;
    
    return ret ;
}


void vtcm_SizedBuffer_Init(TCM_SIZED_BUFFER *tcm_sized_buffer)
{
    tcm_sized_buffer->size = 0 ;
    tcm_sized_buffer->buffer = NULL ;
    return ;
}

void vtcm_SizedBuffer_Delete(TCM_SIZED_BUFFER * tcm_sized_buffer)
{
    printf("SizedBuffer_Delete\n");
    if(tcm_sized_buffer != NULL) {
        free(tcm_sized_buffer->buffer);
        vtcm_SizedBuffer_Init(tcm_sized_buffer);
    }
}

//Condition 1 Start 
int vtcm_OrdinalTable_GetEntry(TCM_ORDINAL_TABLE *ordinalTable ,int ordinal)
{
    printf("vtcm_OrdinalTable_GetEntry :Start \n") ;
    int ret = -1 ;
    
    int i ;
    for(i = 0 ;i < (sizeof(tcm_ordinal_table)/sizeof(TCM_ORDINAL_TABLE))  ; ++i)
    {
        if (ordinalTable[i].ordinal == ordinal) 
        {
            ret = 0 ;
            printf("Ordinal Existence \n") ;
        }
    }

    return ret ;
}


int vtcm_GetCapability_CapOrd(TCM_SIZED_BUFFER *CapabilityResponse ,int ordinal)
{
    printf("vtcm_GetCapability_CapOrd :Start \n") ;
    int ret = 0 ;
    ret = vtcm_OrdinalTable_GetEntry(tcm_ordinal_table ,ordinal) ; 
    
    CapabilityResponse->buffer = (BYTE *)malloc(sizeof(BYTE)*20) ;
    CapabilityResponse->size = 1 ;
    if(!ret)
    {
        CapabilityResponse->buffer[0] = 1 ;
    }
    else
    {
        CapabilityResponse->buffer[0] = 0 ;
    }
    return ret ;
}
// Condition 1 End

//Condition 20 Start

void vtcm_Version_Set(TCM_VERSION *tcm_version ,TCM_PERMANENT_DATA *tcm_permanent_data)
{
    printf(" TCM_Version_Set:\n") ;
    /* This SHALL indicate the major version of the TCM, mostSigVer MUST be 0x01, leastSigVer MUST
     *        be 0x00 */
    tcm_version->major = TCM_MAJOR;
    printf("tcm_version->major = %02x \n",tcm_version->major) ;
    /* This SHALL indicate the minor version of the TCM, mostSigVer MUST be 0x01 or 0x02,
     *        leastSigVer MUST be 0x00 */
    tcm_version->minor = TCM_MINOR;
    printf("tcm_version->minor = %02x \n",tcm_version->minor) ;

    /* This SHALL be the value of the TCM_PERMANENT_DATA -> revMajor */
    //printf("%02x  \n",tcm_permanent_data->revMajor) ;
    tcm_version->revMajor = tcm_permanent_data->revMajor;
    printf("tcm_version->revMajor = %02x \n",tcm_version->revMajor) ;
    //tcm_version->revMajor = 0x01;
    /* This SHALL be the value of the TCM_PERMANENT_DATA -> revMinor */
    tcm_version->revMinor = tcm_permanent_data->revMinor;
    printf("tcm_version->revMinor = %02x \n",tcm_version->revMinor) ;
    //tcm_version->revMinor = 0x01;
    return ;
}

int vtcm_GetCapability_CapVersionVal(TCM_SIZED_BUFFER *CapabilityResponse ,TCM_PERMANENT_DATA *tcm_permanent_data)
{
    printf("vtcm_GetCapability_CapVersionVal :Start\n") ;
    int ret = 0 ;
    //capArea   {0x0000001A}
    //Capability Name   {TCM_CAP_VERSION_VAL}
    //Comments   {TCM_CAP_VERSION_INFO structure. The TCM fills in the structure and
    //returns the information indicating what the TCM currently supports.}
    void *command_template_1 = memdb_get_template(DTYPE_VTCM_IN_CAP ,SUBTYPE_TCM_CAP_VERSION_INFO) ; //get the template
    if(command_template_1 == NULL)
    {
        printf("can't solve this command!\n") ;
    }
    
    TCM_CAP_VERSION_INFO *tcm_cap_version_info = malloc(struct_size(command_template_1)) ;
    //struct_2_blob(void * addr, void * blob, void * struct_template);
    tcm_cap_version_info->tag = 0x3000 ;    
    vtcm_Version_Set(&(tcm_cap_version_info->version), tcm_permanent_data) ;
    printf("vtcm_Version_Set:OK\n") ;
    tcm_cap_version_info->specLevel = TCM_SPEC_LEVEL ;
    printf("tcm_cap_version_info->specLevel = %02x \n" ,tcm_cap_version_info->specLevel) ;
    tcm_cap_version_info->errataRev = TCM_ERRATA_REV ;
    printf("tcm_cap_version_info->errataRev = %02x \n" ,tcm_cap_version_info->errataRev) ;
    memcpy(&(tcm_cap_version_info->tcmVendorID) , TCM_VENDOR_ID ,sizeof(tcm_cap_version_info->tcmVendorID)) ;
    tcm_cap_version_info->vendorSpecificSize = 0 ;
    tcm_cap_version_info->vendorSpecific = NULL ;

    CapabilityResponse->buffer = (BYTE *)malloc(sizeof(BYTE)*20) ;
    ret = struct_2_blob(tcm_cap_version_info ,CapabilityResponse->buffer ,command_template_1) ;
    CapabilityResponse->size = ret ;
    if(ret <= 0)
    {
        printf("struct_2_blob : return %d\n",ret) ;
    }

    return ret ;
}

//Condition 20 End 
int vtcm_CapProperty_Value_Int(TCM_SIZED_BUFFER *CapabilityResponse ,int PCR_value)
{
    printf("vtcm_CapProperty_PCR : Start \n") ;
    int ret = 0 ;
    CapabilityResponse->size = 4 ;
    CapabilityResponse->buffer = (BYTE *)malloc(sizeof(BYTE)*4) ;
    memset(CapabilityResponse->buffer ,sizeof(BYTE) ,0) ;
    CapabilityResponse->buffer[3] = PCR_value ;

    return ret ;
}

/* 
 * TCM_KeyHandleEntries_GetSpace() returns the number of unused key handle entries.
*/

void vtcm_KeyHandleEntries_GetSpace(uint32_t *space ,const TCM_KEY_HANDLE_ENTRY *tcm_key_handle_entries)
{
    printf("vtcm_KeyHandleEntries_GetSpace : Start \n") ;
    int i ;
    for (*space = 0 , i = 0 ; i < TCM_KEY_HANDLES ; i++) 
    {
        if (tcm_key_handle_entries[i].key == NULL) 
        {
            (*space)++;
        }
    }

    return ;
}

int vtcm_CapProperty_Value_Char(TCM_SIZED_BUFFER *CapabilityResponse ,const unsigned char *data ,int Length)
{
    printf("vtcm_CapProperty_Value_Char : Start \n") ;
    int ret = 0 ;
    
    CapabilityResponse->size = Length ;
    CapabilityResponse->buffer = (BYTE *)malloc(sizeof(BYTE)*4) ;
    int i ;
    for(i = 0 ;i < Length ; ++i)
    {
        CapabilityResponse->buffer[i] = data[i] ;
    }

    return ret ;
}


int vtcm_GetCapability_CapProperty(TCM_SIZED_BUFFER *CapabilityResponse ,tcm_state_t *tcm_state ,int subCap_int)
{
    printf("  vtcm_GetCapability_CapProperty : Start\n") ;
    int ret = 0 ;
    int uint32 = 0 ;
    
    printf("  subCap_int = %08x \n" ,subCap_int) ;
    switch(subCap_int)
    {
        case TCM_CAP_PROP_PCR : //Condition 1
             printf("  vtcm_GetCapability_CapProperty : TCM_NUM_PCR = %u\n" ,TCM_NUM_PCR) ;
             ret = vtcm_CapProperty_Value_Int(CapabilityResponse ,TCM_NUM_PCR) ;
             break ;
        case TCM_CAP_PROP_DIR : //Condition 2
             printf("  vtcm_GetCapability_CapProperty : TCM_AUTHDIR_SIZE = %u\n" ,TCM_AUTHDIR_SIZE) ;
             ret = vtcm_CapProperty_Value_Int(CapabilityResponse ,TCM_AUTHDIR_SIZE) ;
             break ;
        case TCM_CAP_PROP_MANUFACTURER :
             printf("  vtcm_GetCapability_CapProperty : TCM_CAP_PROP_MANUFACTURER %.4s\n" ,TCM_MANUFACTURER) ;
             ret = vtcm_CapProperty_Value_Char(CapabilityResponse ,TCM_MANUFACTURER ,4) ;
             break ;
        case TCM_CAP_PROP_MAX_AUTHSESS :
             printf("  vtcm_GetCapability_CapProperty: TCM_CAP_PROP_MAX_AUTHSESS %u\n" ,TCM_MIN_AUTH_SESSIONS);
             ret = vtcm_CapProperty_Value_Int(CapabilityResponse ,TCM_MIN_AUTH_SESSIONS) ;
             break ;
        case TCM_CAP_PROP_KEYS : //Condition 4
             vtcm_KeyHandleEntries_GetSpace(&uint32 ,tcm_state->tcm_key_handle_entries) ;
             printf("  vtcm_GetCapability_CapProperty : TCM_CAP_PROP_KEYS %u\n" , uint32) ;
             ret = vtcm_CapProperty_Value_Int(CapabilityResponse ,uint32) ;
        default :
             printf("  vtcm_GetCapability_CapProperty: Error, illegal subCap_int %08x\n" ,subCap_int) ;
             ret = TCM_BAD_MODE ;
             break ;
    }
    
    return ret ;
}

// Common Condition 7

/* TCM_KeyHandleEntries_StoreHandles() stores only the two members which are part of the
 *    specification.
 *
 *       - the number of loaded keys
 *          - a list of key handles
 *
 *             A TCM_KEY_HANDLE_LIST structure that enumerates all key handles loaded on the TCM. The list only
 *                contains the number of handles that an external manager can operate with and does not include the
 *                   EK or SRK.  This is command is available for backwards compatibility. It is the same as
 *                      TCM_CAP_HANDLE with a resource type of keys.
 *                      */

int vtcm_KeyHandleEntries_StoreHandles(TCM_SIZED_BUFFER *CapabilityResponse ,const TCM_KEY_HANDLE_ENTRY *tcm_key_handle_entries)
{
    printf("vtcm_KeyHandleEntries_StoreHandles : Start \n") ;
    int ret = 0 ;
    int i ,Count ;
    
    Count = 0 ; 
    /* count the number of loaded handles */
    for (i = 0 ; i < TCM_KEY_HANDLES ; i++) 
    {
        if (tcm_key_handle_entries[i].key != NULL) 
        {
            Count++ ;
        }
    }
    printf("  vtcm_KeyHandleEntries_StoreHandles : Count = %d\n" ,Count) ;
    /* store 'loaded' handle count */
    CapabilityResponse->buffer = (BYTE *)malloc(sizeof(BYTE)*20) ;
    memset(CapabilityResponse->buffer ,sizeof(BYTE) ,0) ;

    int Index = 0 ;
    for (i = 0 ; (ret == 0) && (i < TCM_KEY_HANDLES) ; i++) 
    {
        if (tcm_key_handle_entries[i].key != NULL) 
        {   
            /* if the index is loaded */
            CapabilityResponse->buffer[Index++] = tcm_key_handle_entries[i].handle ; /* store it */
        }
     }
     CapabilityResponse->size = 2 ;// 这里为了测试设置成 2

    return ret ;
}


int vtcm_GetCapabilityCommon(TCM_SIZED_BUFFER *CapabilityResponse ,tcm_state_t *tcm_state ,int capArea ,int subCap_int)
{
    printf("vtcm_GetCapability : Start\n") ;
    int ret = 0 ;
    
    printf("capArea = %08x   subCap_int = %08x\n" ,capArea ,subCap_int) ;
    switch(capArea)
    {
        case TCM_CAP_ORD : // Common Condition 1
             ret = vtcm_GetCapability_CapOrd(CapabilityResponse ,subCap_int) ;
             break ;
        case TCM_CAP_PROPERTY : // Common Condition 5
             ret = vtcm_GetCapability_CapProperty(CapabilityResponse ,tcm_state ,subCap_int) ; 
             break ;
        case TCM_CAP_KEY_HANDLE : // Common Condition 7
             ret = vtcm_KeyHandleEntries_StoreHandles(CapabilityResponse ,tcm_state->tcm_key_handle_entries) ;
             break ;
        case TCM_CAP_VERSION_VAL : // Common Condition 20
             ret = vtcm_GetCapability_CapVersionVal(CapabilityResponse ,&(tcm_state->tcm_permanent_data)) ;
             break ;
        default :
             printf("vtcm_GetCapabilityCommon: Error, unsupported capArea %08x" , capArea) ;
             ret = TCM_BAD_MODE ;
             break ;
    }

    return ret ;
}

/***
    proc_vtcm_GetCapability
***/

int proc_vtcm_GetCapability(void * sub_proc,void * recv_msg)
{
    printf("proc_vtcm_GetCapability : Start \n") ;
 
    int ret = TCM_SUCCESS ;
    int capArea ;
    int subCap_int ;

    //input process
    struct tcm_in_GetCapability *vtcm_GetCapability_in ;

    ret = message_get_record(recv_msg ,(void **)&vtcm_GetCapability_in ,0) ; // get structure
    if(ret < 0)
        return ret ;
    if(vtcm_GetCapability_in == NULL)
        return -EINVAL ;

    //output process
    void * template_GetCapability_out = memdb_get_template(DTYPE_VTCM_OUT,SUBTYPE_GETCAPABILITY_OUT) ;//Get the entire command template
    if(template_GetCapability_out == NULL)
    {
        printf("can't solve this command!\n");
    }
    struct tcm_out_GetCapability * vtcm_GetCapability_out = malloc(struct_size(template_GetCapability_out)) ;

    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);

    /*
      Processing
    */

    printf("proc_vtcm_GetCapability : Processing\n") ;
    
    subCap_int = htonl(*(int *)vtcm_GetCapability_in->subCap) ;

    TCM_SIZED_BUFFER CapabilityResponse ;
    vtcm_SizedBuffer_Init(&CapabilityResponse) ;
    ret = vtcm_GetCapabilityCommon(&CapabilityResponse ,tcm_state ,vtcm_GetCapability_in->capArea ,subCap_int) ; 
   
    printf("CapabilityResponse.size = %d\n" ,CapabilityResponse.size) ;
    vtcm_GetCapability_out->resp = (BYTE *)malloc(sizeof(BYTE)*CapabilityResponse.size);
    memcpy(vtcm_GetCapability_out->resp, CapabilityResponse.buffer, CapabilityResponse.size);
    int i ; 
    for(i = 0 ;i < CapabilityResponse.size ; ++i)
    {
        vtcm_GetCapability_out->resp[i] = CapabilityResponse.buffer[i] ;
    }
    vtcm_GetCapability_out->respSize = CapabilityResponse.size ;
    
    // Response
    printf("proc_vtcm_GetCapability : Response \n") ;

    vtcm_GetCapability_out->tag = 0xC400 ;              // TCM_TAG_RSP_COMMAND
    vtcm_GetCapability_out->returnCode = ret ;          //The return code of the operation
   
    int responseSize = 0;                                                                                                                                                                                                                   
    BYTE* response = (BYTE*)malloc(sizeof(BYTE) * 700);
    responseSize = struct_2_blob(vtcm_GetCapability_out, response, template_GetCapability_out);
    vtcm_GetCapability_out->paramSize = responseSize;
    printf("paramSize = %d\n",vtcm_GetCapability_out->paramSize);
    void *send_msg = message_create(DTYPE_VTCM_OUT ,SUBTYPE_GETCAPABILITY_OUT ,recv_msg);
    if(send_msg == NULL)
    {
        printf("send_msg == NULL\n") ;
        return -EINVAL ;
    }
    message_add_record(send_msg ,vtcm_GetCapability_out) ; 

     // add vtcm's expand info	
    ret=vtcm_addcmdexpand(send_msg,recv_msg);
    if(ret<0)
    {
	printf("fail to add vtcm copy info!\n");
    }	
    ret = ex_module_sendmsg(sub_proc ,send_msg) ;
    return ret ;
}
int proc_vtcm_ForceClear(void * sub_proc,void * recv_msg)
{
    printf("proc_vtcm_ForceClear : Start\n");
    int ret = 0;
    int i = 0;

    struct tcm_in_ForceClear *tcm_ForceClear_in;

     ret = message_get_record(recv_msg, (void **)&tcm_ForceClear_in,0);
     if(ret < 0)
         return ret ;
     if(tcm_ForceClear_in == NULL)
         return -EINVAL ;

     //output process
     void * command_template = memdb_get_template(DTYPE_VTCM_OUT,SUBTYPE_FORCECLEAR_OUT);
     if(command_template == NULL)
     {
         printf("can't solve this command!\n");                
     }
     struct tcm_out_ForceClear * tcm_ForceClear_out = malloc(struct_size(command_template));
    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);

     /*
    Processing
     */
    if(tcm_state->tcm_stclear_flags.disableForceClear)
    {return TCM_CLEAR_DISABLED;}
    //Response
    tcm_ForceClear_out->tag = 0xC400 ;
    tcm_ForceClear_out->paramSize = 10 ;
    tcm_ForceClear_out->returnCode = 0 ;

    void *send_msg = message_create(DTYPE_VTCM_OUT,SUBTYPE_FORCECLEAR_OUT,recv_msg);
    if(send_msg == NULL)
        return -EINVAL ;
    message_add_record(send_msg , tcm_ForceClear_out) ;

     // add vtcm's expand info	
    ret=vtcm_addcmdexpand(send_msg,recv_msg);
    if(ret<0)
    {
	printf("fail to add vtcm copy info!\n");
    }	
    ret = ex_module_sendmsg(sub_proc ,send_msg) ;

    return ret ;
}


int proc_vtcm_DisableForceClear(void * sub_proc,void * recv_msg)
{
    printf("proc_vtcm_DisableForceClear : Start\n");
    int ret = 0;
    int i = 0;

    struct tcm_in_DisableForceClear *tcm_DisableForceClear_in;

     ret = message_get_record(recv_msg, (void **)&tcm_DisableForceClear_in,0);
     if(ret < 0)
         return ret ;
     if(tcm_DisableForceClear_in == NULL)
         return -EINVAL ;

     //output process
     void * command_template = memdb_get_template(DTYPE_VTCM_OUT,SUBTYPE_DISABLEFORCECLEAR_OUT);
     if(command_template == NULL)
     {
         printf("can't solve this command!\n");                
     }
     struct tcm_out_DisableForceClear * tcm_DisableForceClear_out = malloc(struct_size(command_template));
    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);

     /*
    Processing
     */
    tcm_state->tcm_stclear_flags.disableForceClear = TRUE ;
    //Response
    tcm_DisableForceClear_out->tag = 0xC400 ;
    tcm_DisableForceClear_out->paramSize = 10 ;
    tcm_DisableForceClear_out->returnCode = 0 ;

    void *send_msg = message_create(DTYPE_VTCM_OUT,SUBTYPE_DISABLEFORCECLEAR_OUT,recv_msg);
    if(send_msg == NULL)
        return -EINVAL ;
    message_add_record(send_msg , tcm_DisableForceClear_out) ;

     // add vtcm's expand info	
    ret=vtcm_addcmdexpand(send_msg,recv_msg);
    if(ret<0)
    {
	printf("fail to add vtcm copy info!\n");
    }	
    ret = ex_module_sendmsg(sub_proc ,send_msg) ;

    return ret ;
}

int vtcm_Nonce_Generate(TCM_NONCE tcm_nonce) {
    int ret = 0;
    printf(" TCM_Nonce_Generate:\n");
    ret = RAND_bytes(tcm_nonce, TCM_NONCE_SIZE);
    return ret;
}

int vtcm_Nonce_Compare(TCM_NONCE expect, const TCM_NONCE actual) {
    int ret = 0;
    printf("TCM_Nonce_Compare:\n");
    ret = memcmp(expect, actual, TCM_NONCE_SIZE);
    if(ret != 0) {
        printf("TCM_Nonce_Compare: Error comparing nonce\n");
        printf("TCM_Nonce_Compare: Expect", expect);
        printf("TCM_Nonce_Compare: Actual", actual);
        ret = TCM_AUTHFAIL;
    }
    return ret;
}

int vtcm_LimitedSelfTestTCM(tcm_state_t * tcm_state)
{
    int ret = 0;
    TCM_SIZED_BUFFER encData;
    TCM_NONCE clrData;
    TCM_NONCE decData;

    printf("LimitedSelfTestTCM\n");

    vtcm_SizedBuffer_Init(&encData);
    if((ret == 0) && (tcm_state->tcm_permanent_data.endorsementKey.keyUsage != TCM_KEY_UNINITIALIZED)) {
//        ret = vtcm_key_CheckPubDataDigest(&(tcm_state->tcm_permanent_data.endorsementKey));
    }
    vtcm_Nonce_Generate(clrData);
    vtcm_Nonce_Compare(clrData, decData);
    vtcm_SizedBuffer_Delete(&encData);
    if(ret != 0) {
        ret = TCM_FAILEDSELFTEST;
    }

}

int vtcm_ContinueSelfTestCmd(tcm_state_t * tcm_state)
{
    int ret = 0;
    
    printf("ContinueSelfTestCmd:\n");
    
    if(ret != 0) {
        ret = TCM_FAILEDSELFTEST;
    }
    if(ret = 0) {
        printf("vtcm_ContinueSelfTestCmd: Set testState to %u \n", TCM_TEST_STATE_FULL);
        tcm_state->testState = TCM_TEST_STATE_FULL;
    }
    else {
        printf("vtcm_ContinueSelfTestCmd: Set testState to %u \n", TCM_TEST_STATE_FAILURE);
        tcm_state->testState = TCM_TEST_STATE_FAILURE;
    }
    return ret;

}

int vtcm_SelfTestFullCmd(tcm_state_t * tcm_state)
{
    int ret = 0;
    printf("SelfTestFullCmd\n");
    ret = vtcm_LimitedSelfTestTCM(tcm_state);
    if(ret = 0) {
        ret = vtcm_ContinueSelfTestCmd(tcm_state);
    }
    return ret;
}

int proc_vtcm_SelfTestFull(void * sub_proc, void * recv_msg)
{
    printf("proc_vtcm_SelfTestFull : Start\n");
    int ret = 0;
    int i = 0;

    struct tcm_in_SelfTestFull *tcm_SelfTestFull_in;
    ret = message_get_record(recv_msg, (void **)&tcm_SelfTestFull_in, 0);
    if(ret < 0)
        return ret;
    if(tcm_SelfTestFull_in == NULL)
        return -EINVAL;
    //output process
    void * command_template = memdb_get_template(DTYPE_VTCM_OUT, SUBTYPE_SELFTESTFULL_OUT);
    if(command_template == NULL)
    {
        printf("can't solve this command!\n");
    }
    struct tcm_out_SelfTestFull * tcm_SelfTestFull_out = malloc(struct_size(command_template));

    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);

    /*
    Processing
    */
    //printf("SelfTestFull : Succeed!\n");
    ret = vtcm_SelfTestFullCmd(tcm_state);

    //Reponse
    tcm_SelfTestFull_out->tag = 0xC400;
    tcm_SelfTestFull_out->paramSize = 10;
    tcm_SelfTestFull_out->returnCode = 0;
    void *send_msg = message_create(DTYPE_VTCM_OUT, SUBTYPE_SELFTESTFULL_OUT, recv_msg);
    if(send_msg == NULL)
        return -EINVAL;
    message_add_record(send_msg, tcm_SelfTestFull_out);

     // add vtcm's expand info	
    ret=vtcm_addcmdexpand(send_msg,recv_msg);
    if(ret<0)
    {
	printf("fail to add vtcm copy info!\n");
    }	
    ret = ex_module_sendmsg(sub_proc, send_msg);
    return ret;
}

int proc_vtcm_ContinueSelfTest(void * sub_proc,void * recv_msg)
{
    printf("proc_vtcm_ContinueSelfTest : Start\n") ;
    int ret = 0 ;
    int i = 0 ;
    
    struct tcm_in_ContinueSelfTest *tcm_ContinueSelfTest_in ;

    ret = message_get_record(recv_msg, (void **)&tcm_ContinueSelfTest_in, 0) ; // get structure 
    if(ret < 0)
        return ret;
    if(tcm_ContinueSelfTest_in == NULL)
        return -EINVAL;

    //output process
    void * command_template = memdb_get_template(DTYPE_VTCM_OUT,SUBTYPE_CONTINUESELFTEST_OUT);//Get the entire command template
    if(command_template == NULL)
    {
        printf("can't solve this command!\n");
    }
    struct tcm_out_ContinueSelfTest * tcm_ContinueSelfTest_out = malloc(struct_size(command_template));

    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);

    //Processing

    ret = vtcm_ContinueSelfTestCmd(tcm_state);
    
    //Response 

    tcm_ContinueSelfTest_out->tag = 0xC400;
    tcm_ContinueSelfTest_out->paramSize = 10;
    tcm_ContinueSelfTest_out->returnCode = ret;

    void *send_msg = message_create(DTYPE_VTCM_OUT,SUBTYPE_CONTINUESELFTEST_OUT,recv_msg);
    if(send_msg == NULL)
        return -EINVAL;
    message_add_record(send_msg ,tcm_ContinueSelfTest_out);

     // add vtcm's expand info	
    ret=vtcm_addcmdexpand(send_msg,recv_msg);
    if(ret<0)
    {
	printf("fail to add vtcm copy info!\n");
    }	
    ret = ex_module_sendmsg(sub_proc ,send_msg);

    return ret;
}

int proc_vtcm_GetRandom(void * sub_proc, void * recv_msg)
{
    printf("proc_vtcm_GetRandom : Start\n");
    int ret = 0;
    int i = 0;
    BYTE * randomBytes;
    

    struct tcm_in_GetRandom *tcm_GetRandom_in;
    ret = message_get_record(recv_msg, (void *)&tcm_GetRandom_in, 0);
    if(ret < 0)
        return ret;
    if(tcm_GetRandom_in == NULL)
        return -EINVAL;
    //output process
    void * command_template = memdb_get_template(DTYPE_VTCM_OUT, SUBTYPE_GETRANDOM_OUT);
    if(command_template == NULL)
    {
        printf("can't solve this command!\n");
    }
    struct tcm_out_GetRandom * tcm_GetRandom_out = malloc(struct_size(command_template));

    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);

    /*
    Processing
    */
    tcm_GetRandom_out->tag = 0xC400;
    tcm_GetRandom_out->returnCode = 0;
    tcm_GetRandom_out->randomBytesSize = 0x10;
//    tcm_GetRandom_out->randomBytes = 0x2F7E88F6C6905EA8489AC339DA962AD5;
//    tcm_GetRandom_out->paramSize = 10+sizeof(int)+tcm_GetRandom_out->randomBytesSize;
    tcm_GetRandom_out->paramSize = 0x1E;
    
    tcm_GetRandom_out->randomBytes=malloc(tcm_GetRandom_out->randomBytesSize);
    if(tcm_GetRandom_out->randomBytes==NULL)
        return -ENOMEM;
    ret = RAND_bytes(tcm_GetRandom_out->randomBytes,tcm_GetRandom_out->randomBytesSize);
    printf("Random figure is : %d",ret);
    //Reponse
    void *send_msg = message_create(DTYPE_VTCM_OUT, SUBTYPE_GETRANDOM_OUT, recv_msg);
    if(send_msg == NULL)
        return -EINVAL;
    message_add_record(send_msg, tcm_GetRandom_out);

     // add vtcm's expand info	
    ret=vtcm_addcmdexpand(send_msg,recv_msg);
    if(ret<0)
    {
	printf("fail to add vtcm copy info!\n");
    }	
    ret = ex_module_sendmsg(sub_proc, send_msg);
    return ret;
}
/*
int vtcm_AuthData_Check_OwnerClear(int ordinal,
                                   TCM_SESSION_DATA *auth_session_data,
                                   BYTE *authCode)
{
    printf("vtcm_AuthData_Check_OwnerClear: Start\n");
    
    int ret = TCM_SUCCESS;
    TCM_BOOL flag = TRUE;

    BYTE *Str_Hash_In = (BYTE *)malloc(sizeof(BYTE) * 500);
    BYTE *Str_Hash_Out = (BYTE *)malloc(sizeof(BYTE) * 100);
    BYTE *checksum = (BYTE *)malloc(sizeof(BYTE) * TCM_NONCE_SIZE);
    int temp = htonl(ordinal);
    memcpy(Str_Hash_In, &temp, sizeof(int));

    int Str_Hash_Len = sizeof(int);
    vtcm_SM3(Str_Hash_Out, Str_Hash_In, Str_Hash_Len);
    
    //auth_session_data->SERIAL = 0;
    temp = htonl(auth_session_data->SERIAL);
    printf("li Serial is %08x\n", auth_session_data->SERIAL);
    memcpy(Str_Hash_Out + TCM_NONCE_SIZE, &temp, sizeof(int));
    vtcm_HMAC_SM3(auth_session_data->sharedSecret, TCM_NONCE_SIZE, Str_Hash_Out,
                  TCM_NONCE_SIZE + sizeof(int), checksum);
    //Compare authCode
    for(int i = 0; i< 32; i++) {
        printf("%02x ", auth_session_data->sharedSecret[i]);
    }
    printf("\n");
    for(int i = 0; i < 32; i++){
        printf("%02x ", checksum[i]);
        if(authCode[i] != checksum[i]) {
            flag = FALSE;
            printf("came in\n");
        }
    }
    printf("flag is %0x\n", flag);
    printf("\n");
    if(flag)
    {
        printf("Verification authCode Success\n");
    }
    else
    {
        printf("Verification authCode Fail\n");
        ret = -1;
    }
    free(Str_Hash_In);
    free(Str_Hash_Out);
    free(checksum);
    return ret;
}

int vtcm_AuthData_Check_OwnerClearout(int returnCode,
                                      int ordinal,
                                      TCM_SESSION_DATA *auth_session_data,
                                      BYTE *authCode)
{
    printf("vtcm_AuthData_Check_OwnerClearout: Start\n");
    
    int ret = TCM_SUCCESS;
    

    BYTE *Str_Hash_In = (BYTE *)malloc(sizeof(BYTE) * 500);
    BYTE *Str_Hash_Out = (BYTE *)malloc(sizeof(BYTE) * 100);
    BYTE *checksum = (BYTE *)malloc(sizeof(BYTE) * TCM_NONCE_SIZE);
    int temp = htonl(returnCode);
    int temp2 = htonl(ordinal);
    memcpy(Str_Hash_In, &temp, sizeof(int));
    memcpy(Str_Hash_In + sizeof(int), &temp2, sizeof(int));


    int Str_Hash_Len = sizeof(int) * 2;
    vtcm_SM3(Str_Hash_Out, Str_Hash_In, Str_Hash_Len);
    
    //auth_session_data->SERIAL = 0;
    temp = htonl(auth_session_data->SERIAL);
    memcpy(Str_Hash_Out + TCM_NONCE_SIZE, &temp, sizeof(int));
    vtcm_HMAC_SM3(auth_session_data->sharedSecret, TCM_NONCE_SIZE, Str_Hash_Out, 
                  TCM_NONCE_SIZE + sizeof(int), authCode);
    //Compare authCode
    free(Str_Hash_In);
    free(Str_Hash_Out);
    free(checksum);
    return ret;
}
*/
int proc_vtcm_DisableOwnerClear(void * sub_proc, void * recv_msg)
{
    printf("proc_vtcm_DisableOwnerClear : Start\n");
    int ret = 0;
    TCM_SESSION_DATA *auth_session_data = NULL;
    BYTE CheckData[TCM_HASH_SIZE];

    struct tcm_in_DisableOwnerClear *tcm_DisableOwnerClear_in;
    ret = message_get_record(recv_msg, (void **)&tcm_DisableOwnerClear_in, 0);
    if(ret < 0)
        return ret;
    if(tcm_DisableOwnerClear_in == NULL)
        return -EINVAL;

    //output
    void * command_template = memdb_get_template(DTYPE_VTCM_OUT, SUBTYPE_DISABLEOWNERCLEAR_OUT);
    if(command_template == NULL)
    {
        printf("Can't solve this command!\n");
    }
    struct tcm_out_DisableOwnerClear * tcm_DisableOwnerClear_out = malloc(struct_size(command_template));
    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);
    
    /*
     *Processing
    */
    if(ret == TCM_SUCCESS) {
        vtcm_AuthSessions_GetEntry(&auth_session_data,
                                   tcm_state->tcm_stany_data.sessions,
                                   tcm_DisableOwnerClear_in->authHandle);
            printf("Serial is %08x\n", auth_session_data->SERIAL);
    }

    if(ret == TCM_SUCCESS) {
      memcpy(CheckData, auth_session_data->sharedSecret, TCM_HASH_SIZE);
      ret = vtcm_Compute_AuthCode(tcm_DisableOwnerClear_in, DTYPE_VTCM_IN, SUBTYPE_DISABLEOWNERCLEAR_IN, auth_session_data, CheckData);
    }
    if(ret == TCM_SUCCESS) {
      if(memcmp(tcm_DisableOwnerClear_in->ownerAuth, CheckData, TCM_HASH_SIZE) != 0){
        ret = TCM_AUTHFAIL;
        printf("\nerror, checkdata is wrong\n");
      }
    }
    /*
    if(ret == TCM_SUCCESS) {
        vtcm_AuthData_Check_OwnerClear(tcm_DisableOwnerClear_in->ordinal,
                                       auth_session_data,
                                       tcm_DisableOwnerClear_in->ownerAuth);
    }
    */
    tcm_state->tcm_permanent_flags.disableOwnerClear = TRUE;

    //output
    tcm_DisableOwnerClear_out->tag = 0xC500;
    tcm_DisableOwnerClear_out->paramSize = 0x2A;
    tcm_DisableOwnerClear_out->returnCode = ret;

    //tcm_DisableOwnerClear_out->resAuth = ;

    
    if(ret == TCM_SUCCESS) {
      ret = vtcm_Compute_AuthCode(tcm_DisableOwnerClear_out,
                                  DTYPE_VTCM_OUT,
                                  SUBTYPE_DISABLEOWNERCLEAR_OUT,
                                  auth_session_data,
                                  tcm_DisableOwnerClear_out->resAuth);
    }
    
    void *send_msg = message_create(DTYPE_VTCM_OUT, SUBTYPE_DISABLEOWNERCLEAR_OUT, recv_msg);
    if(send_msg == NULL)
        return -EINVAL;
    message_add_record(send_msg, tcm_DisableOwnerClear_out);

     // add vtcm's expand info	
    ret=vtcm_addcmdexpand(send_msg,recv_msg);
    if(ret<0)
    {
	printf("fail to add vtcm copy info!\n");
    }	
    ret = ex_module_sendmsg(sub_proc, send_msg);

    return ret;

}
int  vtcm_Malloc(unsigned char **buffer, uint32_t size)
{
    int rc = 0;
    
    if (rc == 0) {
        if (*buffer != NULL) {
            printf("vtcm_Malloc: Error (fatal), *buffer %p should be NULL before malloc\n", *buffer);
            rc = TCM_FAIL;
        }
    }
    /* verify that the size is not "too large" */
    if (rc == 0) {
        if (size > TCM_ALLOC_MAX) {
            printf("vtcm_Malloc: Error, size %u greater than maximum allowed\n", size);
            rc = TCM_SIZE;
        }       
    }
    /* verify that the size is not 0, this would be implementation defined and should never occur */
    if (rc == 0) {
        if (size == 0) {
            printf("vtcm_Malloc: Error (fatal), size is zero\n");
            rc = TCM_FAIL;
        }       
    }
    if (rc == 0) {
        *buffer = malloc(size);
        if (*buffer == NULL) {
            printf("vtcm_Malloc: Error allocating %u bytes\n", size);
            rc = TCM_SIZE;
        }
    }
    return rc;
}
int vtcm_SizedBuffer_Allocate(TCM_SIZED_BUFFER *tcm_sized_buffer,
                              uint32_t size)
{
    int ret = 0;
    printf("vtcm_SizedBuffer_Allocate: Size %u\n", size);
    tcm_sized_buffer->size = size;
    ret = vtcm_Malloc(&(tcm_sized_buffer->buffer), size);
    return ret;
}

int proc_vtcm_GetTestResult(void * sub_proc, void * recv_msg)
{
    printf("proc_vtcm_GetTestResult : Start\n");
    int ret = 0;
    TCM_SIZED_BUFFER outData;

    struct tcm_in_GetTestResult *tcm_GetTestResult_in;
    ret = message_get_record(recv_msg, (void **)&tcm_GetTestResult_in, 0);
    if(ret < 0)
        return ret;
    if(tcm_GetTestResult_in == NULL)
        return -EINVAL;

    //output
    void * command_template = memdb_get_template(DTYPE_VTCM_OUT, SUBTYPE_GETTESTRESULT_OUT);
    if(command_template == NULL)
    {
        printf("Can't solve this command!\n");
    }
    struct tcm_out_GetTestResult * tcm_GetTestResult_out = malloc(struct_size(command_template));
    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);
    
    /*
     *Processing
    */

    //buffer init
    vtcm_SizedBuffer_Init(&outData);
  
    //allocate
    if(ret == TCM_SUCCESS) {
        ret = vtcm_SizedBuffer_Allocate(&outData, 128);
    }
    //Malloc
    //if(ret == TCM_SUCCESS)  {
    //    outData.size = sprintf((char *)(outData.buffer), "Shutdown %08x\n", tcm_state->testState);
    //}

    //output
    tcm_GetTestResult_out->tag = 0xC400;
    tcm_GetTestResult_out->outDataSize = 0x04;
    tcm_GetTestResult_out->paramSize = 0x12;
    tcm_GetTestResult_out->returnCode = 0;
    tcm_GetTestResult_out->outData = (BYTE *)malloc(sizeof(BYTE)*4);
    memset(tcm_GetTestResult_out->outData,0,4);
    //tcm_GetTestResult_out->outData = 0;
    //memcpy(tcm_GetTestResult_out->outData, outData.buffer, 4);

    
    //BYTE *Str_buffer = (BYTE *)malloc(sizeof(BYTE)*100);

    //ret = struct_2_blob(tcm_GetTestResult_out,Str_buffer,command_template);
    void *send_msg = message_create(DTYPE_VTCM_OUT, SUBTYPE_GETTESTRESULT_OUT, recv_msg);
    if(send_msg == NULL)
        return -EINVAL;
    message_add_record(send_msg, tcm_GetTestResult_out);

     // add vtcm's expand info	
    ret=vtcm_addcmdexpand(send_msg,recv_msg);
    if(ret<0)
    {
	printf("fail to add vtcm copy info!\n");
    }	
    ret = ex_module_sendmsg(sub_proc, send_msg);

    int i = 0 ;
    return ret;

}

/* These are subCaps to TPM_SetCapability -> TPM_SET_VENDOR capArea, the vendor specific area.*/    
        
static int vtcm_SetCapability_CapVendor(tcm_state_t *tcm_state,
                                        TCM_BOOL ownerAuthorized,
                                        TCM_BOOL presenceAuthorized,
                                        uint32_t subCap32,
                                        TCM_SIZED_BUFFER *setValue)
{
    int ret = 0;
        
    printf(" vtcm_SetCapability_CapVendor:\n");
    ownerAuthorized = ownerAuthorized;      /* not used */
    presenceAuthorized = presenceAuthorized;    /* not used */
    setValue = setValue;
    /* make temporary copies so the setValue is not touched */
    if (ret == 0) 
    {
        switch(subCap32) 
        {
            default:
                printf("  vtcm_SetCapability_CapVendor: Error, unsupported subCap %08x\n", subCap32);
                tcm_state = tcm_state;          /* not used */
                ret = TCM_BAD_PARAMETER;
                break;                                          
        }
    }
    return ret;
}

/* vtcm_Global_GetPhysicalPresence() returns 'physicalPresence' TRUE if either TPM_STCLEAR_FLAGS ->
 *    physicalPresence is TRUE or hardware physical presence is indicated.
 *    */

int vtcm_Global_GetPhysicalPresence(TCM_BOOL *physicalPresence,
                                    const tcm_state_t *tcm_state)
{
    int ret = 0;
    /* check for physicalPresence set by the command ordinal */
    *physicalPresence = tcm_state->tcm_stclear_flags.physicalPresence;
    printf("  vtcm_Global_GetPhysicalPresence: physicalPresence flag is %02x\n", *physicalPresence);
    /* if the software flag is true, result is true, no need to check the hardware */
    /* if the TPM_STCLEAR_FLAGS flag is FALSE, check the hardware */
    if (!(*physicalPresence)) 
    {
        /* if physicalPresenceHWEnable is FALSE, the hardware signal is disabled */
        if (tcm_state->tcm_permanent_flags.physicalPresenceHWEnable) 
        {
            /* If it's TRUE, check the hardware signal */
            //ret = TPM_IO_GetPhysicalPresence(physicalPresence, tcm_state->tcm_number);
            printf("  TPM_Global_GetPhysicalPresence: physicalPresence signal is %02x\n",
                       *physicalPresence);
                                            
        }   
            
    }   
    return ret; 
}

/*
int vtcm_SetCapability_CapPermData(tcm_state_t *tcm_state,                                                                                                                                
                                   TCM_BOOL ownerAuthorized,
                                   TCM_BOOL presenceAuthorized,
                                   uint32_t subCap32,
                                   uint32_t valueUint32)

{
    printf("vtcm_SetCapability_CapPermData : Start\n");

    int ret = TCM_SUCCESS;
    TCM_BOOL    writeAllNV = FALSE;             // TRUE if the structure has been changed 
        
    presenceAuthorized = presenceAuthorized;    // not used 
    if (ret == TCM_SUCCESS) 
    {                              
        switch (subCap32) 
        {
            case TCM_PD_RESTRICTDELEGATE:
                printf("  TPM_SetCapability_CapPermData: TPM_PD_RESTRICTDELEGATE\n");
                // Owner authorization.  Not available when TCM deactivated or disabled 
                // TCM_CMK_SetRestrictions 
                if (ret == TCM_SUCCESS) 
                { 
                    if (!ownerAuthorized) 
                    {
                        printf(" vtcm_SetCapability_CapPermData: Error, not owner authorized\n");
                        ret = TCM_AUTHFAIL;                                                                  
                    }    
                 }
                if (ret == TCM_SUCCESS) 
                { 
                    if (tcm_state->tcm_permanent_flags.disable) 
                    {
                        printf("  vtcm_SetCapability_CapPermData: Error, disabled\n");
                        ret = TCM_DISABLED;
                                                    
                    }    
                }    
                if (ret == TCM_SUCCESS) 
                { 
                    if (tcm_state->tcm_stclear_flags.deactivated) 
                    {
                        printf("  vtcm_SetCapability_CapPermData: Error, deactivated\n");
                        ret = TCM_DEACTIVATED;                                    
                    }
                }
               /* if (ret == 0) 
                {
                    if (tcm_state->tcm_permanent_data.restrictDelegate != valueUint32) 
                    {
                        tcm_state->tcm_permanent_data.restrictDelegate = valueUint32;
                        writeAllNV = TRUE;                                    
                    }            
                }
                break;
            case TCM_PD_DAAPROOF:
                // TPM_PD_DAAPROOF This capability has no value.  When specified by TPM_SetCapability, a
                // new daaProof, tpmDAASeed, and daaBlobKey are generated.
                ret = vtcm_PermanentData_InitDaa(&(tcm_state->tcm_permanent_data));
                writeAllNV = TRUE;
                break;
            case TCM_PD_REVMAJOR:
            case TCM_PD_REVMINOR:
            case TCM_PD_TCMPROOF:
            case TCM_PD_OWNERAUTH:
            case TCM_PD_OPERATORAUTH:
            case TCM_PD_MANUMAINTPUB:
            case TCM_PD_ENDORSEMENTKEY:
            case TCM_PD_SRK:
            case TCM_PD_DELEGATEKEY:
            case TCM_PD_CONTEXTKEY:
            case TCM_PD_AUDITMONOTONICCOUNTER:
            case TCM_PD_MONOTONICCOUNTER:
            case TCM_PD_PCRATTRIB:
            case TCM_PD_ORDINALAUDITSTATUS:
            case TCM_PD_AUTHDIR:
            case TCM_PD_RNGSTATE:
            case TCM_PD_FAMILYTABLE:
            case TCM_DELEGATETABLE:
            case TCM_PD_EKRESET:
            case TCM_PD_LASTFAMILYID:
            case TCM_PD_NOOWNERNVWRITE:
            case TCM_PD_TCMDAASEED:
            default:
                    printf("  vtcm_SetCapability_CapPermData: Error, bad subCap32 %u\n", subCap32);                                                                                                                                                                          
                    ret = TCM_BAD_PARAMETER;
         }
    }
    //ret = vtcm_PermanentAll_NVStore(tcm_state,
    //                                writeAllNV,
    //                                ret);
    return ret;
}
*/
/* vtcm_SizedBuffer_GetBool() converts from a TPM_SIZED_BUFFER to a TPM_BOOL.
 * If the size does not indicate a TPM_BOOL, an error is returned.
 */

int vtcm_SizedBuffer_GetBool(TCM_BOOL *tcm_bool,
                             TCM_SIZED_BUFFER *tcm_sized_buffer)
{
    printf("vtcm_SizeBuffer_GetBool : Start\n");   
    
    int ret = TCM_SUCCESS;
    if (tcm_sized_buffer->size == sizeof(TCM_BOOL)) 
    {
        *tcm_bool = *(TCM_BOOL *)tcm_sized_buffer->buffer;
        printf("  vtcm_SizedBuffer_GetBool: bool %02x\n", *tcm_bool);
    }   
    else 
    {
        printf("vtcm_SizedBuffer_GetBool: Error, buffer size %08x is not a BOOL\n", tcm_sized_buffer->size);
        ret = TCM_BAD_PARAMETER;                
    }   
    return ret;
}


/* vtcm_SizedBuffer_GetUint32() converts from a TPM_SIZED_BUFFER to a uint32_t.
 * If the size does not indicate a uint32_t, an error is returned.
 */

int vtcm_SizedBuffer_GetUint32(uint32_t *uint32,
                               TCM_SIZED_BUFFER *tcm_sized_buffer)
{
    printf("vtcm_SizedBuffer_GetUint32 : Start\n");
    int ret = TCM_SUCCESS;

    if (ret == TCM_SUCCESS) 
    {
        if (tcm_sized_buffer->size != sizeof(uint32_t)) 
        {
            printf("vtcm_GetUint32: Error, buffer size %08x is not a uint32_t\n", tcm_sized_buffer->size);
            ret = TCM_BAD_PARAMETER;                        
        }   
    }   
    if (ret == TCM_SUCCESS) 
        *uint32 = LOAD32(tcm_sized_buffer->buffer, 0);
    return ret; 
}


int vtcm_SetCapability_CapStclearFlags(tcm_state_t *tcm_state,                                                                                                                                
                                       TCM_BOOL ownerAuthorized,
                                       TCM_BOOL presenceAuthorized,
                                       uint32_t subCap32,
                                       TCM_BOOL valueBool)
{
    printf("  vtcm_SetCapability_CapStclearFlags : Start\n");

    int ret = TCM_SUCCESS;
    ownerAuthorized = ownerAuthorized;          // not used 
    presenceAuthorized = presenceAuthorized;    // not used 
    if (ret == TCM_SUCCESS) 
    {                              
        switch (subCap32) 
        {
            case TCM_SF_DISABLEFORCECLEAR:
                printf("  vtcm_SetCapability_CapStclearFlags: TCM_SF_DISABLEFORCECLEAR\n");
                // Not available when TPM deactivated or disabled
                // TPM_DisableForceClear
                if (ret == TCM_SUCCESS) 
                { 
                    if (tcm_state->tcm_permanent_flags.disable) 
                    {
                        printf("  vtcm_SetCapability_CapStclearFlags: Error, disabled\n");
                        ret = TCM_DISABLED;                                
                    }    
                }    
                if (ret == TCM_SUCCESS) 
                { 
                    if (tcm_state->tcm_stclear_flags.deactivated) 
                    {
                        printf("  vtcm_SetCapability_CapStclearFlags: Error, deactivated\n");
                        ret = TCM_DEACTIVATED;                                
                    }    
                }
                // Can only set to TRUE
                if (ret == TCM_SUCCESS) 
                { 
                    if (!valueBool) 
                    {
                        printf("  vtcm_SetCapability_CapStclearFlags: Error, cannot set FALSE\n");
                        ret = TCM_BAD_PARAMETER;                                
                    }
                }
                if (ret == TCM_SUCCESS) 
                {
                    tcm_state->tcm_stclear_flags.disableForceClear = TRUE;             
                }
                break;
            case TCM_SF_DEACTIVATED:
            case TCM_SF_PHYSICALPRESENCE:
            case TCM_SF_PHYSICALPRESENCELOCK:
            case TCM_SF_BGLOBALLOCK:
            default:
                printf("  vtcm_SetCapability_CapStclearFlags: Error, bad subCap32 %u\n", subCap32);
                ret = TCM_BAD_PARAMETER;
        }
    }
    return ret;
}


int vtcm_SetCapability_CapStclearData(tcm_state_t *tcm_state,                                                                                                                                
                                      TCM_BOOL ownerAuthorized,
                                      TCM_BOOL presenceAuthorized,
                                      uint32_t subCap32,
                                      uint32_t valueUint32)
{
    printf("vtcm_SetCapability_CapStclearData : Start\n");

    int ret = TCM_SUCCESS; 
#if  (TCM_REVISION < 103)               // added for rev 103
    tcm_state = tcm_state;              // to quiet the compiler 
    presenceAuthorized = presenceAuthorized;
    valueUint32 = valueUint32;
#endif
    ownerAuthorized = ownerAuthorized;      // not used
    if (ret == TCM_SUCCESS) 
    {
        switch (subCap32) 
        {
#if  (TCM_REVISION >= 103)              // added for rev 103
            case TCM_SD_DEFERREDPHYSICALPRESENCE:
                printf("  vtcm_SetCapability_CapStclearData: TCM_SD_DEFERREDPHYSICALPRESENCE\n");
                // Can only set to TRUE if PhysicalPresence is asserted.  Can set to FALSE at any time.
                // 1. If physical presence is not asserted
                // a. If TPM_SetCapability -> setValue has a bit set that is not already set in
                // TCM_STCLEAR_DATA -> deferredPhysicalPresence, return TPM_BAD_PRESENCE.
                if (ret == TCM_SUCCESS) 
                {
                    if (!presenceAuthorized) 
                    {
                       // if (~(tcm_state->tcm_stclear_data.deferredPhysicalPresence) & valueUint32) 
                       // {
                       //     printf("  vtcm_SetCapability_CapStclearData: "
                      //             "Error, no physicalPresence and deferredPhysicalPresence %08x\n",
                      //      tcm_state->tcm_stclear_data.deferredPhysicalPresence);
                      //      ret = TCM_BAD_PRESENCE;                            
                      //  }
                    }   
                }
                // 2.Set TPM_STCLEAR_DATA -> deferredPhysicalPresence to TPM_SetCapability -> setValue.
                if (ret == TCM_SUCCESS) 
                {
                    printf("   vtcm_SetCapability_CapStclearData: deferredPhysicalPresence now %08x\n", valueUint32);
                    //tcm_state->tcm_stclear_data.deferredPhysicalPresence = valueUint32;                        
                }
                break;
#endif
            case TCM_SD_CONTEXTNONCEKEY:
            case TCM_SD_COUNTID:
            case TCM_SD_OWNERREFERENCE:
            case TCM_SD_DISABLERESETLOCK:
            case TCM_SD_PCR:
            default:
                printf("  vtcm_SetCapability_CapStclearData: Error, bad subCap32 %u\n", subCap32);
                ret = TCM_BAD_PARAMETER;
        }
    }
    return ret;
}


/* vtcm_Locality_Check() checks that a bit in the TPM_LOCALITY_SELECTION (BYTE) bitmap is set for bit
 * TCM_STANY_FLAGS -> TPM_MODIFIER_INDICATOR (uint32_t) -> localityModifier
 *
 * 'tpm_locality_selection' is typically localityAtRelease, pcrResetLocal, pcrExtendLocal
 *  'localityModifier' is TPM_STANY_FLAGS.localityModifier
 */

int vtcm_Locality_Check(TCM_LOCALITY_SELECTION tcm_locality_selection,                  // BYTE bitmap
                        TCM_MODIFIER_INDICATOR localityModifier) // uint32_t from TCM_STANY_FLAGS
{
    printf("vtcm_Locality_Check : Start\n");

    int ret = TCM_SUCCESS;
    switch (localityModifier) 
    {
        case 0:
            if ((tcm_locality_selection & TCM_LOC_ZERO) == 0) 
            {
                ret = TCM_BAD_LOCALITY;                                  
            }
            break;
        case 1:
            if ((tcm_locality_selection & TCM_LOC_ONE) == 0) 
            {
                ret = TCM_BAD_LOCALITY;                                            
            }
            break;
        case 2:
            if ((tcm_locality_selection & TCM_LOC_TWO) == 0) 
            {
                ret = TCM_BAD_LOCALITY;                    
            }
            break;
        case 3:
            if ((tcm_locality_selection & TCM_LOC_THREE) == 0) 
            {
                ret = TCM_BAD_LOCALITY;                                     
            }
            break;
        case 4:
            if ((tcm_locality_selection & TCM_LOC_FOUR) == 0) 
            {
                ret = TCM_BAD_LOCALITY;                    
            }
            break;
        default:
            // This should never occur.  The code that sets TPM_STANY_FLAGS should screen out bad values
            printf("  vtcm_Locality_Check: Error (fatal), localityModifier %u out of range\n", localityModifier);
            ret = TCM_FAIL;
        }
    return ret;

}


int vtcm_SetCapability_CapStanyFlags(tcm_state_t *tcm_state,                                                                                                                                
                                     TCM_BOOL ownerAuthorized,
                                     TCM_BOOL presenceAuthorized,
                                     uint32_t subCap32,
                                     TCM_BOOL valueBool)
{
    printf("vtcm_SetCapability_CapStanyFlags : Start\n");

    int ret = TCM_SUCCESS;
    ownerAuthorized = ownerAuthorized;           // not used
    presenceAuthorized = presenceAuthorized;     // not used
    if (ret == TCM_SUCCESS) 
    {                         
        switch (subCap32) 
        {
            case TCM_AF_TOSPRESENT:
                printf("  vtcm_SetCapability_CapStanyFlags: TCM_AF_TOSPRESENT\n");
                // locality 3 or 4 
                // Not available when TPM deactivated or disabled
                if (ret == TCM_SUCCESS) 
                {
                    ret = vtcm_Locality_Check(TCM_LOC_THREE | TCM_LOC_FOUR,
                                              tcm_state->tcm_stany_flags.localityModifier);
                }
                if (ret == TCM_SUCCESS) 
                {
                    if(tcm_state->tcm_permanent_flags.disable) 
                    {
                        printf("  vtcm_SetCapability_CapStanyFlags: Error, disabled\n");
                        ret = TCM_DISABLED;                                 
                    }                 
                }
                if (ret == TCM_SUCCESS) 
                {
                    if (tcm_state->tcm_stclear_flags.deactivated) 
                    {
                        printf("  vtcm_SetCapability_CapStanyFlags: Error, deactivated\n");
                        ret = TCM_DEACTIVATED;                        
                    }
                }
                // can only be set to FALSE 
                if (ret == TCM_SUCCESS) 
                {
                    if (valueBool) 
                    {
                        printf("  vtcm_SetCapability_CapStanyFlags: Error, cannot set TRUE\n");
                        ret = TCM_BAD_PARAMETER;                        
                    }
                }
                if (ret == TCM_SUCCESS) 
                {
                    tcm_state->tcm_stany_flags.TOSPresent = FALSE;
                }
                break;
            case TCM_AF_POSTINITIALISE:
            case TCM_AF_LOCALITYMODIFIER:
            case TCM_AF_TRANSPORTEXCLUSIVE:
            default:
                printf("  vtcm_SetCapability_CapStanyFlags: Error, bad subCap32 %u\n", subCap32);
                ret = TCM_BAD_PARAMETER;
        }
    }
    return ret;
}


/* 
    TPM_SetCapabilityCommon() is common code for setting a capability from setValue
    NOTE: This function assumes that the caller has validated either owner authorization or physical
    presence!
 */

int vtcm_SetCapabilityCommon(tcm_state_t *tcm_state,
                            TCM_BOOL ownerAuthorized,
                            TCM_BOOL presenceAuthorized,
                            TCM_CAPABILITY_AREA capArea, 
                            uint32_t subCap32,
                            TCM_SIZED_BUFFER *setValue)
{
    printf("  vtcm_SetCapabilityCommon : Start\n");
    int ret = TCM_SUCCESS;
    
    TCM_BOOL    valueBool;
    uint32_t    valueUint32 = 0;    // start with illegal value 
    if (ret == TCM_SUCCESS) 
    {
        if ((capArea == TCM_SET_PERM_FLAGS) || (capArea == TCM_SET_STCLEAR_FLAGS) || (capArea == TCM_SET_STANY_FLAGS)) 
        {
            ret = vtcm_SizedBuffer_GetBool(&valueBool, setValue);
        }
    }
    else if (((capArea == TCM_SET_PERM_DATA) && (subCap32 != TCM_PD_DAAPROOF)) || (capArea == TCM_SET_STCLEAR_DATA)) 
    {   // deferredPhysicalPresence 
        ret = vtcm_SizedBuffer_GetUint32(&valueUint32, setValue);
    }
    if(ret == TCM_SUCCESS)
    {
        switch(capArea)
        {
            case TCM_SET_STCLEAR_FLAGS:
                ret = vtcm_SetCapability_CapStclearFlags(tcm_state,
                                                         ownerAuthorized,
                                                         presenceAuthorized,
                                                         subCap32,
                                                         valueBool);
                break;
            case TCM_SET_STANY_FLAGS:
                ret =  vtcm_SetCapability_CapStanyFlags(tcm_state,
                                                        ownerAuthorized,
                                                        presenceAuthorized,
                                                        subCap32,
                                                        valueBool);
                break;
            case TCM_SET_STCLEAR_DATA:
                ret = vtcm_SetCapability_CapStclearData(tcm_state,
                                                        ownerAuthorized,
                                                        presenceAuthorized,
                                                        subCap32,
                                                        valueUint32);
                break;
            case TCM_SET_VENDOR:
                ret = vtcm_SetCapability_CapVendor(tcm_state, 
                                                   ownerAuthorized, 
                                                   presenceAuthorized,
                                                   subCap32, 
                                                   setValue);
                break;
            case TCM_SET_PERM_DATA:
            case TCM_SET_STANY_DATA:
            default:
                printf("  vtcm_SetCapabilityCommon: Error, unsupported capArea %08x", capArea);
                ret = TCM_BAD_MODE;
                break;
        }
    }
    return ret;
}



int vtcm_Check_AuthCode_SetCap(struct tcm_in_SetCapability *tcm_input,     
                                   TCM_SESSION_DATA *authSession,
                                   BYTE *authCode)
{
    printf("vtcm_Check_AuthCode_SetCap : Start\n");

    int ret = TCM_SUCCESS;
    BYTE *Str_Hash_In = (BYTE *)malloc(sizeof(BYTE)*300);
    BYTE *Str_Hash_Out = (BYTE *)malloc(sizeof(BYTE)*100);
    BYTE *Str_Hash_SetCap = (BYTE *)malloc(sizeof(BYTE)*300);
    BYTE *checksum = (BYTE *)malloc(sizeof(BYTE)*100);
    void * template = memdb_get_template(DTYPE_VTCM_IN,SUBTYPE_SETCAPABILITY_IN);  //Get the TCM_KEY template
    if(template == NULL)
    {
        printf("can't get SetCapability template!\n");              
    }
    int Len_SetCap = struct_2_blob(tcm_input, Str_Hash_SetCap, template);
    if(Len_SetCap == 0)
    {
        printf("Error, struct_2_blob : SetCapability\n");                                  
    }
    memcpy(Str_Hash_In, Str_Hash_SetCap + 6, Len_SetCap-42);
    int Hash_In_Len = Len_SetCap - 42;
    vtcm_SM3(Str_Hash_Out, Str_Hash_In, Hash_In_Len);
    int temp = htonl(authSession->SERIAL);
    memcpy(Str_Hash_Out + TCM_NONCE_SIZE, &temp, sizeof(int));
    vtcm_HMAC_SM3(authSession->sharedSecret, TCM_NONCE_SIZE, Str_Hash_Out, TCM_NONCE_SIZE + sizeof(int), checksum);
    //Compare authCode
    if(!strcmp(authCode ,checksum))
    {
        printf("Verification authCode Success\n");
    }
    else
    {
        printf("Verification authCode Fail\n");
        ret = -1;
    }
    free(Str_Hash_In);                                                                                                                                                                         
    free(Str_Hash_Out);
    free(Str_Hash_SetCap);
    free(checksum);
    return ret;
}

int vtcm_Compute_AuthCode_SetCap(int value_ret,
                                 int value_ordinal,
                                 TCM_SESSION_DATA  *authSession,
                                 BYTE *resAuth)  
{
    printf("vtcm_Compute_AuthCode_Sm2Decrypt : Start\n");
    int ret = TCM_SUCCESS;
    BYTE *Str_Hash_In = (BYTE *)malloc(sizeof(BYTE) * 100);
    BYTE *Str_Hash_Out = (BYTE *)malloc(sizeof(BYTE) * 100);

    int temp = htonl(value_ret);
    memcpy(Str_Hash_In, &temp, sizeof(int));
    temp = htonl(value_ordinal);
    memcpy(Str_Hash_In + sizeof(int), &temp, sizeof(int));
    vtcm_SM3(Str_Hash_Out, Str_Hash_In, sizeof(int)*2);
    
    uint32_t sernum = htonl(authSession->SERIAL);
    memcpy(Str_Hash_Out + TCM_NONCE_SIZE, &sernum, sizeof(uint32_t)); 
    vtcm_HMAC_SM3(authSession->sharedSecret, TCM_NONCE_SIZE,  Str_Hash_Out, TCM_NONCE_SIZE + sizeof(uint32_t), resAuth);
    return ret;
}

int proc_vtcm_SetCapability(void * sub_proc,void * recv_msg)
{
    printf("proc_vtcm_SetCapability : Start\n");

    int ret = TCM_SUCCESS;
    uint32_t        subCap_int;                     // the subCap as a uint32_t 
    TCM_BOOL        ownerAuthorized = FALSE;        // TRUE if owner authorization validated 
    TCM_BOOL        presenceAuthorized = FALSE;     // TRUE if physicalPresence validated 
    TCM_SIZED_BUFFER    setValue;                   // The value to set 
    TCM_SESSION_DATA *auth_session_data = NULL;

    //input process
    struct tcm_in_SetCapability *vtcm_input ;
    ret = message_get_record(recv_msg ,(void **)&vtcm_input ,0) ; // get structure
    if(ret < 0)
        return ret ;
    if(vtcm_input == NULL)
        return -EINVAL ;
    //output process
    void * template_out = memdb_get_template(DTYPE_VTCM_OUT,SUBTYPE_SETCAPABILITY_OUT) ;//Get the entire command template
    if(template_out == NULL)
    {
        printf("can't solve this command!\n");
    }
    struct tcm_out_SetCapability * vtcm_output = malloc(struct_size(template_out)) ;
    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);

    //Processing
    //Get AuthSession
    if(ret == TCM_SUCCESS && vtcm_input->tag != TCM_TAG_RSP_COMMAND)
    {    
            ret = vtcm_AuthSessions_GetEntry(&auth_session_data,
                                             tcm_state->tcm_stany_data.sessions,
                                             vtcm_input->authHandle);
    }
    //Verification authCode
    if(ret == TCM_SUCCESS)
    {
        if(vtcm_input->tag == TCM_TAG_RSP_COMMAND)
        {
            ownerAuthorized = TRUE;        // TRUE if owner authorization validated 
        }
        else 
        {
            ret = vtcm_Check_AuthCode_SetCap(vtcm_input,
                                             auth_session_data,
                                             vtcm_input->authCode);
            ownerAuthorized = !ret;
        }
    }
    if (ret == TCM_SUCCESS) 
    {
        ret = vtcm_Global_GetPhysicalPresence(&presenceAuthorized, tcm_state);                               
    } 
    //SetCapability Start
    if (ret == TCM_SUCCESS) 
    {
        subCap_int = htonl(*(int *)vtcm_input->subCap) ;
        ret = vtcm_SetCapabilityCommon(tcm_state, 
                                       ownerAuthorized, 
                                       presenceAuthorized,
                                       vtcm_input->capArea,  
                                       subCap_int, 
                                       &setValue);
    } 
    //Compute DecryptedAuthVerfication
    if(ret == TCM_SUCCESS)
    {
        ret = vtcm_Compute_AuthCode_SetCap(ret,
                                           vtcm_input->ordinal,
                                           auth_session_data,
                                           vtcm_output->resAuth);
    }
    //Response
    printf("proc_vtcm_APCreate : Response \n");
    vtcm_output->tag = 0xC400;
    vtcm_output->returnCode = ret; 
     
    BYTE* response = (BYTE*)malloc(sizeof(BYTE) * 700);
    int responseSize = struct_2_blob(vtcm_output, response, template_out);
    vtcm_output->paramSize = responseSize;
    void *send_msg = message_create(DTYPE_VTCM_OUT ,SUBTYPE_SETCAPABILITY_OUT ,recv_msg);
    if(send_msg == NULL)
    {
        printf("send_msg == NULL\n");
        return -EINVAL;                          
    }
    message_add_record(send_msg, vtcm_output);
    // add vtcm's expand info	
    ret = vtcm_addcmdexpand(send_msg,recv_msg);
    if(ret < 0)
    {
	    printf("fail to add vtcm copy info!\n");
    }	
    ret = ex_module_sendmsg(sub_proc, send_msg);
    return ret;
}

int vtcm_ContextList_GetEntry(uint32_t *entry, const uint32_t *contextList, uint32_t value)
{
    int ret = 0;
    printf("vtcm_ContextList_GetEntry:\n");
    if(value == 0) {
        printf("vtcm_ContextList_GetEntry: Error, value %d never found\n", value);
        ret = TCM_BADCONTEXT;
    }
    if(ret == 0) {
        for(*entry = 0; *entry < TCM_MIN_SESSION_LIST; (*entry)++) {
            if(contextList[*entry] == value) {
                break;
            }
        }
        if(*entry == TCM_MIN_SESSION_LIST) {
            printf("vtcm_ContextList_GetEntry: Error, value %d not found\n", value);
            ret = TCM_BADCONTEXT;
        }
    }
    return ret;
}

int vtcm_KeyHandleEntries_GetEntry(TCM_KEY_HANDLE_ENTRY ** tcm_key_handle_entry, TCM_KEY_HANDLE_ENTRY ** tcm_key_handle_entries, TCM_KEY_HANDLE tcm_key_handle)
{
    int ret = 0;
    size_t i;
    bool found;

    printf("vtcm_KeyHandleEntries_GetEntry: Get entry for handle %08x\n", tcm_key_handle);
    for(i = 0, found = FALSE; (i < TCM_KEY_HANDLES) && !found ; i++) {
        //if((tcm_key_handle_entries[i].handle == tcm_key_handle) && (tcm_key_handle_entries[i].key != NULL)) {
            found = TRUE;
            *tcm_key_handle_entry = &(tcm_key_handle_entries[i]);
        //}
    }
    if(!found) {
        printf("vtcm_KeyHandleEntries_GetEntry: key handle %08x not found\n", tcm_key_handle);
        ret = TCM_INVALID_KEYHANDLE;
    }
    else {
        printf("vtcm_KeyHandleEntries_GetEntry: key handle %08x found\n", tcm_key_handle);
    }
    return ret;
}

int vtcm_KeyHandleEntry_FlushSpecific(tcm_state_t *tcm_state, TCM_KEY_HANDLE_ENTRY * tcm_key_handle_entry)
{
    int ret = 0;
    printf("vtcm_KeyHandleEntry_FlushSpecific:\n");
    if(tcm_key_handle_entry->key == NULL) {
        printf("vtcm_KeyHandleEntry_FlushSpecific: Error (fatal), key is NULL\n");
        ret = TCM_FAIL;
    }
    if(ret == 0) {
        //vtcm_AuthSessions_TerminateEntry();
        //printf("vtcm_KeyHandleEntry_FlushSpecific: Flushing key handle %08x\n", tcm_key_handle_entry->handle);
        //vtcm_KeyHandleEntry_Delete(tcm_key_handle_entry);
    }
    return ret;
}

int vtcm_AuthSessions_TerminateHandle(TCM_SESSION_DATA * sessions, TCM_AUTHHANDLE authHandle)
{
    int ret = 0;
    TCM_SESSION_DATA * tcm_session_data;
    printf("vtcm_AuthSessions_TerminateHandle: Handle %08x\n", authHandle);
    //ret = vtcm_AuthSessions_GetEntry(&tcm_session_data, sessions, authHandle);
    if(ret == 0) {
        //vtcm_AuthSessionData_Delete(tcm_session_data);
    }
    return ret;
}

int vtcm_DaaSessions_TerminateHandle(TCM_DAA_SESSION_DATA * daaSessions, TCM_HANDLE daaHandle)
{
    int ret = 0;
    TCM_DAA_SESSION_DATA * tcm_daa_session_data;
    printf("vtcm_DaaSessions_TerminateHandle : daaHandle %08x\n", daaHandle);
    //ret = vtcm_DaaSessions_GetEntry();
    if(ret == 0) {
        //ret = vtcm_DaaSessions_Delete();
    }
    return ret;
}

int proc_vtcm_FlushSpecific(void * sub_proc,void * recv_msg)
{
    printf("proc_vtcm_FlushSpecific : Start\n") ;
    int ret = 0 ;
    int i = 0 ;
    uint32_t rlResource;
   
    TCM_KEY_HANDLE_ENTRY *tcm_key_handle_entry;
    //TCM_HANDLE handle;
    TCM_RESOURCE_TYPE resourceType = 0;
    struct tcm_in_FlushSpecific *tcm_FlushSpecific_in ;

    ret = message_get_record(recv_msg, (void **)&tcm_FlushSpecific_in, 0) ; // get structure 
    if(ret < 0)
        return ret;
    if(tcm_FlushSpecific_in == NULL)
        return -EINVAL;

    //output process
    void * command_template = memdb_get_template(DTYPE_VTCM_OUT,SUBTYPE_FLUSHSPECIFIC_OUT);//Get the entire command template
    if(command_template == NULL)
    {
        printf("can't solve this command!\n");
    }
    struct tcm_out_FlushSpecific * tcm_FlushSpecific_out = malloc(struct_size(command_template));

    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);

    //Processing
   
    switch (resourceType) {
    case TCM_RT_CONTEXT:
        if(ret == 0) {
            printf("vtcm_FlushSpecific: Flushing context count %08x\n", tcm_FlushSpecific_in->handle);
            ret = vtcm_ContextList_GetEntry(&rlResource, tcm_state->tcm_stany_data.contextList, tcm_FlushSpecific_in->handle);
            if(ret != 0) {
                printf("vtcm_FlushSpecific: Error, context count %08x not found\n", tcm_FlushSpecific_in->handle);
            }
        }
        if(ret == 0) {
            tcm_state->tcm_stany_data.contextList[rlResource] = 0;
        }
        break;
    case TCM_RT_KEY:
        if(ret == 0) {
            printf("vtcm_FlushSpecific: Flushing context count %08x\n", tcm_FlushSpecific_in->handle);
            ret = vtcm_KeyHandleEntries_GetEntry(&tcm_key_handle_entry, tcm_state->tcm_key_handle_entries, tcm_FlushSpecific_in->handle);
            if(ret != 0) {
                printf("vtcm_FlushSpecific: Error, key handle %08x not found\n", tcm_FlushSpecific_in->handle);
                ret = TCM_BAD_PARAMETER;
            }
        }
        if(ret == 0) {
            if(tcm_key_handle_entry->keyControl & TCM_KEY_CONTROL_OWNER_EVICT) {
                printf("vtcm_FlushSpecific: Error, keyHandle specifies owner evict\n");
                ret = TCM_KEY_OWNER_CONTROL;
            }
        }
        if(ret == 0) {
            ret = vtcm_KeyHandleEntry_FlushSpecific(tcm_state, tcm_key_handle_entry);
        }
        break;
    case TCM_RT_AUTH:
        printf("vtcm_FlushSpecific: Flushing authorization session handle %08x\n", tcm_FlushSpecific_in->handle);
        ret = vtcm_AuthSessions_TerminateHandle(tcm_state->tcm_stany_data.sessions, tcm_FlushSpecific_in->handle);
        break;
    case TCM_RT_TRANS:
        printf("vtcm_FlushSpecific: Flushing transport session handle %08x\n", tcm_FlushSpecific_in->handle);
        break;
    case TCM_RT_DAA_TCM:
        printf("vtcm_FlushSpecific: Flushing DAA session handle %08x\n", tcm_FlushSpecific_in->handle);
        ret = vtcm_DaaSessions_TerminateHandle(tcm_state->tcm_stany_data.sessions, tcm_FlushSpecific_in->handle);
        break;
    default:
        printf("vtcm_FlushSpecific: Error, invalid resourceType %08x\n", resourceType);
        ret = TCM_INVALID_RESOURCE;
        break;
    }
    //Response 

    tcm_FlushSpecific_out->tag = 0xC400;
    tcm_FlushSpecific_out->paramSize = 10;
    tcm_FlushSpecific_out->returnCode = 0;

    void *send_msg = message_create(DTYPE_VTCM_OUT,SUBTYPE_FLUSHSPECIFIC_OUT,recv_msg);
    if(send_msg == NULL)
        return -EINVAL;
    message_add_record(send_msg ,tcm_FlushSpecific_out);

     // add vtcm's expand info	
    ret=vtcm_addcmdexpand(send_msg,recv_msg);
    if(ret<0)
    {
	printf("fail to add vtcm copy info!\n");
    }	
    ret = ex_module_sendmsg(sub_proc ,send_msg);

    return ret;
}

int proc_vtcm_OwnerClear(void * sub_proc,void * recv_msg)
{
    printf("proc_vtcm_OwnerClear : Start\n") ;
    int ret = 0;
    TCM_SESSION_DATA *auth_session_data = NULL;
    BYTE CheckData[TCM_HASH_SIZE];  
    
    struct tcm_in_OwnerClear *tcm_input;

    ret = message_get_record(recv_msg, (void **)&tcm_input, 0) ; // get structure 
    if(ret < 0)
        return ret;
    if(tcm_input == NULL)
        return -EINVAL;

    //output process
    void * command_template = memdb_get_template(DTYPE_VTCM_OUT,SUBTYPE_OWNERCLEAR_OUT);//Get the entire command template
    if(command_template == NULL)
    {
        printf("can't solve this command!\n");
    }
    struct tcm_out_OwnerClear * tcm_output = malloc(struct_size(command_template));

    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);

    //Processing
    if(ret == TCM_SUCCESS) {
        vtcm_AuthSessions_GetEntry(&auth_session_data,
                                   tcm_state->tcm_stany_data.sessions,
                                   tcm_input->authHandle);
            printf("Serial is %08x\n", auth_session_data->SERIAL);
    }
    if(ret == TCM_SUCCESS)
    {
      Memcpy(CheckData, auth_session_data->sharedSecret, TCM_HASH_SIZE);
      ret = vtcm_Compute_AuthCode(tcm_input, DTYPE_VTCM_IN, SUBTYPE_OWNERCLEAR_IN, auth_session_data, CheckData);

    }
    if(ret == TCM_SUCCESS) {
      if(memcmp(tcm_input->ownerAuth, CheckData, TCM_HASH_SIZE) != 0 ) {
        ret = TCM_AUTHFAIL;
        printf("\nerror! The CheckData is wrong\n");
      }
    }
    //Response 
    tcm_output->tag = 0xC500;
    tcm_output->paramSize = 42;
    tcm_output->returnCode = 0;

    
    if(ret == TCM_SUCCESS) {
      ret = vtcm_Compute_AuthCode(tcm_output,
                                   DTYPE_VTCM_OUT,
                                   SUBTYPE_OWNERCLEAR_OUT,
                                   auth_session_data,
                                   tcm_output->resAuth);
    }
    
    void *send_msg = message_create(DTYPE_VTCM_OUT,SUBTYPE_OWNERCLEAR_OUT,recv_msg);
    if(send_msg == NULL)
        return -EINVAL;
    message_add_record(send_msg ,tcm_output);

     // add vtcm's expand info	
    ret=vtcm_addcmdexpand(send_msg,recv_msg);
    if(ret<0)
    {
	printf("fail to add vtcm copy info!\n");
    }	
    ret = ex_module_sendmsg(sub_proc ,send_msg);

    return ret;
}
//Universal template ↓↓↓↓
/*
int proc_vtcm_XX(void * sub_proc,void * recv_msg)
{
    printf("proc_vtcm_XX : Start\n") ;
    int ret = 0 ;
    
    struct tcm_in_XX *tcm_input;

    ret = message_get_record(recv_msg, (void **)&tcm_input, 0) ; // get structure 
    if(ret < 0)
        return ret;
    if(tcm_input == NULL)
        return -EINVAL;

    //output process
    void * command_template = memdb_get_template(DTYPE_VTCM_OUT,SUBTYPE_XXX_OUT);//Get the entire command template
    if(command_template == NULL)
    {
        printf("can't solve this command!\n");
    }
    struct tcm_out_XX * tcm_output = malloc(struct_size(command_template));

    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);

    //Processing
    
    //Response 

    tcm_output->tag = 0xC400;
    tcm_output->paramSize = 10;
    tcm_output->returnCode = 0;

    void *send_msg = message_create(DTYPE_VTCM_OUT,SUBTYPE_XXX_OUT,recv_msg);
    if(send_msg == NULL)
        return -EINVAL;
    message_add_record(send_msg ,tcm_output);

     // add vtcm's expand info	
    ret=vtcm_addcmdexpand(send_msg,recv_msg);
    if(ret<0)
    {
	printf("fail to add vtcm copy info!\n");
    }	
    ret = ex_module_sendmsg(sub_proc ,send_msg);

    return ret;
}
*/

