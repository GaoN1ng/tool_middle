/* CC0-1.0: development equations with real static multiple-precision bodies. */
#include "tommath.h"
int ordinary(mp_int *c,mp_int *dp,mp_int *dq,mp_int *p,mp_int *q,mp_int *qi,mp_int *out){
 mp_int a,b,h;mp_init_multi(&a,&b,&h,NULL);
 mp_exptmod(c,dp,p,&a);mp_exptmod(c,dq,q,&b);mp_submod(&a,&b,p,&h);
 mp_mulmod(&h,qi,p,&h);mp_mul(&h,q,&h);mp_sub(&h,&b,out);
 mp_clear_multi(&a,&b,&h,NULL);return 0;
}
