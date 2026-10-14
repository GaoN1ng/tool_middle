#include <mbedtls/aes.h>
int holdout_aes(mbedtls_aes_context *c, unsigned char *i, unsigned char *o){return mbedtls_aes_crypt_ecb(c,1,i,o);}
