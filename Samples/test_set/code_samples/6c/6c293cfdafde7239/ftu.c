#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/aes.h>
#include <gmssl/sha2.h>
#include "cs101_information_objects.h"
static int business_selftest(void){ MeasuredValueScaled mv=MeasuredValueScaled_create(NULL,1001,230,0); if(!mv || MeasuredValueScaled_getValue(mv)!=230) return 33; MeasuredValueScaled_destroy(mv); return 0; }
static int security_selftest(void){ SM2_KEY key; unsigned char dgst[32]={1},sig[256]; size_t siglen=0; if(sm2_key_generate(&key)!=1||sm2_sign(&key,dgst,sig,&siglen)!=1||sm2_verify(&key,dgst,sig,siglen)!=1) return 13; sig[0]^=1; if(sm2_verify(&key,dgst,sig,siglen)==1) return 14; return 0; }
int main(void){ if(business_selftest()!=0||security_selftest()!=0) return 1; puts("PASS ftu"); return 0; }
