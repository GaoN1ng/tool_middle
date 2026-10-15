/* CC0-1.0: development equations with real static multiple-precision bodies. */
#include "tommath.h"
int ordinary(mp_int *e,mp_int *x,mp_int *d,mp_int *k,mp_int *n,mp_int *r,mp_int *s){
 mp_int a,b,c;mp_init_multi(&a,&b,&c,NULL);
 mp_addmod(e,x,n,r);mp_add_d(d,1,&a);mp_invmod(&a,n,&b);
 mp_addmod(r,d,n,&c);mp_submod(k,&c,n,s);mp_mulmod(s,&b,n,s);
 mp_clear_multi(&a,&b,&c,NULL);return 0;
}
