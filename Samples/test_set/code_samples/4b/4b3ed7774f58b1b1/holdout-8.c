#include <mbedtls/sha1.h>
int holdout_sha1(const unsigned char *b,size_t n,unsigned char *o){return mbedtls_sha1(b,n,o);}
