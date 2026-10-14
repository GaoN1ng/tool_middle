#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/aes.h>
#include <gmssl/sha2.h>
int main(void){ SM2_KEY key; unsigned char dgst[32]={1},sig[256]; size_t siglen=0; if(sm2_key_generate(&key)!=1||sm2_sign(&key,dgst,sig,&siglen)!=1||sm2_verify(&key,dgst,sig,siglen)!=1) return 13; sig[0]^=1; if(sm2_verify(&key,dgst,sig,siglen)==1) return 14; puts("PASS"); return 0; }
