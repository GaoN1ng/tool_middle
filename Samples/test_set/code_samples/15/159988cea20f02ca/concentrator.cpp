#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/aes.h>
#include <gmssl/sha2.h>
#include "GXDLMSClient.h"
#include "GXDLMSRegister.h"
static int business_selftest(void){ CGXDLMSClient client; std::vector<CGXByteBuffer> packets; if(client.AARQRequest(packets)!=0 || packets.empty()) return 31; return 0; }
static int security_selftest(void){ SM3_CTX c; unsigned char out[32]; sm3_init(&c); sm3_update(&c,(const unsigned char*)"abc",3); sm3_finish(&c,out); const unsigned char expected[32]={0x66,0xc7,0xf0,0xf4,0x62,0xee,0xed,0xd9,0xd1,0xf2,0xd4,0x6b,0xdc,0x10,0xe4,0xe2,0x41,0x67,0xc4,0x87,0x5c,0xf2,0xf7,0xa2,0x29,0x7d,0xa0,0x2b,0x8f,0x4b,0xa8,0xe0}; if(memcmp(out,expected,32)) return 11; return 0; }
int main(void){ if(business_selftest()!=0||security_selftest()!=0) return 1; puts("PASS concentrator"); return 0; }
