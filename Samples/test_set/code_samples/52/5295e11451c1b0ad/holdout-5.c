#include <mbedtls/ecdsa.h>
int holdout_verify(mbedtls_ecp_group *g,const unsigned char *b,size_t n,mbedtls_ecp_point *p,mbedtls_mpi *r,mbedtls_mpi *s){return mbedtls_ecdsa_verify(g,b,n,p,r,s);}
