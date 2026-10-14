#include <mbedtls/rsa.h>
int holdout_rsa(mbedtls_rsa_context *c,const unsigned char *i,unsigned char *o){return mbedtls_rsa_public(c,i,o);}
