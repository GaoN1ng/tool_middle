/* CC0 development negative; not a cryptographic implementation. */
__attribute__((used,noinline)) unsigned int guard(volatile unsigned int *p){unsigned int z=1;for(unsigned i=0;i<96;i++)z=(z+p[i])^(z>>3);return z;}
extern int BN_mod_add(void*,void*,void*,void*,void*);
 extern int EC_POINT_mul(void*,void*,void*,void*,void*,void*);
 extern int BN_cmp(void*,void*);
 int work(void*g,void*p,void*t,void*r,void*s,void*e,void*x,void*n){
 BN_mod_add(t,r,s,n,0);EC_POINT_mul(g,p,s,p,t,0);BN_mod_add(t,e,x,n,0);return BN_cmp(t,r);}
