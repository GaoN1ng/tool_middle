typedef struct opaque N;
extern int BN_mod_add(N*,N*,N*,N*,void*),BN_mod_sub(N*,N*,N*,N*,void*),BN_mod_mul(N*,N*,N*,N*,void*);
extern N*BN_mod_inverse(N*,N*,N*,void*);extern int BN_copy(N*,N*),BN_add_word(N*,unsigned),BN_cmp(N*,N*);
extern int EC_POINT_mul(void*,void*,N*,void*,N*,void*),EC_POINT_get_affine_coordinates(void*,void*,N*,N*,void*);
int ordinary(void*g,void*P,void*pub,N*e,N*x,N*n,N*r,N*s,N*t){
BN_mod_add(t,r,s,n,0);EC_POINT_mul(g,P,s,pub,t,0);
EC_POINT_get_affine_coordinates(g,P,x,0,0);BN_mod_add(t,e,x,n,0);return BN_cmp(t,r);}