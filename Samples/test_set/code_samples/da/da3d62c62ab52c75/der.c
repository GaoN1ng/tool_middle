#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/aes.h>
#include <gmssl/sha2.h>
#include "cs101_information_objects.h"
static int business_selftest(void){ int requested_kw=75; if(requested_kw<0 || requested_kw>100) return 34; SetpointCommandScaled cmd=SetpointCommandScaled_create(NULL,2001,requested_kw,true,0); if(!cmd || SetpointCommandScaled_getValue(cmd)!=75) return 35; InformationObject_destroy((InformationObject)cmd); return 0; }
static int security_selftest(void){ unsigned char k[16]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10},out[16]; const unsigned char expected[16]={0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46}; SM4_KEY key; sm4_set_encrypt_key(&key,k); sm4_encrypt(&key,k,out); if(memcmp(out,expected,16)) return 12; return 0; }
int main(void){ if(business_selftest()!=0||security_selftest()!=0) return 1; puts("PASS der"); return 0; }
