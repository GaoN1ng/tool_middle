#include <mbedtls/ecdh.h>
int holdout_ecdh(mbedtls_ecdh_context *c){return mbedtls_ecdh_setup(c,MBEDTLS_ECP_DP_SECP256R1);}
