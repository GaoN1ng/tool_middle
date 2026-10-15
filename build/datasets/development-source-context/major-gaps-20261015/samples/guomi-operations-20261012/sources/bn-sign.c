typedef struct opaque N;
extern int BN_mod_add(N*,N*,N*,N*,void*),BN_mod_sub(N*,N*,N*,N*,void*),BN_mod_mul(N*,N*,N*,N*,void*);
extern N*BN_mod_inverse(N*,N*,N*,void*);extern int BN_copy(N*,N*),BN_add_word(N*,unsigned),BN_cmp(N*,N*);
extern int EC_POINT_mul(void*,void*,N*,void*,N*,void*),EC_POINT_get_affine_coordinates(void*,void*,N*,N*,void*);
int ordinary(N*e,N*x,N*d,N*n,N*k,N*r,N*s,N*u,N*den){
BN_mod_add(r,e,x,n,0);BN_mod_mul(u,r,d,n,0);BN_copy(den,d);BN_add_word(den,1);
BN_mod_inverse(den,den,n,0);BN_mod_sub(u,k,u,n,0);BN_mod_mul(s,u,den,n,0);return 0;}