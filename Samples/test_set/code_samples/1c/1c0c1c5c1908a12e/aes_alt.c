#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "aes.h"
int main(void){ struct AES_ctx ctx; unsigned char k[16]={0},out[16]={0}; const unsigned char expected[16]={0x66,0xe9,0x4b,0xd4,0xef,0x8a,0x2c,0x3b,0x88,0x4c,0xfa,0x59,0xca,0x34,0x2b,0x2e}; AES_init_ctx(&ctx,k); AES_ECB_encrypt(&ctx,out); if(memcmp(out,expected,16)) return 16; puts("PASS"); return 0; }
