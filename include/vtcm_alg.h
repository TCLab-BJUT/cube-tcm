#ifndef VTCM_ALG_H
#define VTCM_ALG_H

int vtcm_sm3(char * hashout,...);

int vtcm_Random(BYTE* buffer, size_t bytes);

int vtcm_hmac_sm3(char * hashout,BYTE * key, int keylen,...);


int vtcm_ex_sm3(char * hashout,...);

int vtcm_ex_Random(BYTE* buffer, size_t bytes);

int vtcm_ex_hmac_sm3(char * hashout,BYTE * key, int keylen,...);

#endif
