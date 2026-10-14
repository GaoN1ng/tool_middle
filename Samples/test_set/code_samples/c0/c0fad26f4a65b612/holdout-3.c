#include <mbedtls/chacha20.h>
int holdout_chacha(mbedtls_chacha20_context *c, const unsigned char *k){return mbedtls_chacha20_setkey(c,k);}
