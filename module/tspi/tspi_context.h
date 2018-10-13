typedef struct proc_init_parameter
{
	char * name;
	int type;
	int (* init) (void *,void *);
	int (* start) (void *,void *);
}PROC_INIT;
struct context_init
{
        int count;
        UINT32 handle;
}__attribute__((packed));


enum tsmd_context_state
{       
        TSMD_CONTEXT_INIT=0x01,
        TSMD_CONTEXT_BUILD,
        TSMD_CONTEXT_APICALL,
        TSMD_CONTEXT_SENDDATA,
        TSMD_CONTEXT_RECVDATA,
        TSMD_CONTEXT_APIRETURN,
        TSMD_CONTEXT_CLOSE,
        TSMD_CONTEXT_ERROR
};

typedef struct tsmd_context_struct
{
        int count;
        UINT32 handle;
        int shmid;
        enum tsmd_context_state state;

        int tsmd_API;
        int curr_step;
	int shm_size;
        void * tsmd_context;
        BYTE * tsmd_send_buf;
        BYTE * tsmd_recv_buf;
        CHANNEL * tsmd_API_channel;
}__attribute__((packed)) TSMD_CONTEXT;

extern TSMD_CONTEXT this_context;



int lib_read(int fd,int type,int subtype,void ** record);
int lib_write(int fd, int type,int subtype, void * record);

int lib_gettype(char * libname, int * typeno,int * subtypeno);

