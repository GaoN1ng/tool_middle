typedef struct opaque N;
extern int mp_addmod(N*,N*,N*,N*);
extern int mp_submod(N*,N*,N*,N*);
extern int mp_mulmod(N*,N*,N*,N*);
extern int mp_add_d(N*,unsigned,N*);
extern int mp_invmod(N*,N*,N*);
int ordinary(N*x,N*e,N*d,N*n,N*b,N*k,N*r,N*s,N*u,N*v,N*den){
mp_addmod(x,e,n,r);mp_mulmod(r,d,n,u);mp_add_d(d,1,den);
mp_mulmod(den,b,n,den);mp_invmod(den,n,den);
mp_mulmod(k,den,n,v);mp_mulmod(u,den,n,u);
mp_submod(v,u,n,s);mp_mulmod(s,b,n,s);return 0;}
