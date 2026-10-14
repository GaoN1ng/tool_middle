#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/aes.h>
#include <gmssl/sha2.h>
int main(void){ AES_KEY key; unsigned char k[16]={0},plain[16]={0},out[16]; const unsigned char expected[16]={0x66,0xe9,0x4b,0xd4,0xef,0x8a,0x2c,0x3b,0x88,0x4c,0xfa,0x59,0xca,0x34,0x2b,0x2e}; if(aes_set_encrypt_key(&key,k,16)!=1) return 15; aes_encrypt(&key,plain,out); if(memcmp(out,expected,16)) return 16; puts("PASS"); return 0; }
