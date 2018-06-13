#ifndef TPM_INIT_CHANNEL_H
#define TPM_INIT_CHANNEL_H
int tpm_init_channel_init(void * sub_proc,void * para);
int tpm_init_channel_start(void * sub_proc,void * para);

struct tpm_init_para
{
     char * ex_channel;
     char * in_channel;
}__attribute__((packed));
#endif
