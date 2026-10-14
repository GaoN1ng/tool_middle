#include <mbedtls/des.h>
int holdout_des(mbedtls_des_context *c, unsigned char *i, unsigned char *o){return mbedtls_des_crypt_ecb(c,i,o);}
