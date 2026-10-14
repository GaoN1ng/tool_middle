typedef struct opaque N;
extern int sp_addmod(N*,N*,N*,N*);
extern int sp_submod(N*,N*,N*,N*);
extern int sp_mulmod(N*,N*,N*,N*);
extern int sp_add_d(N*,unsigned,N*);
extern int sp_invmod(N*,N*,N*);
int ordinary(N*x,N*e,N*d,N*n,N*b,N*k,N*r,N*s,N*u,N*v,N*den){
sp_addmod(x,e,n,r);sp_mulmod(r,d,n,u);sp_add_d(d,1,den);
sp_mulmod(den,b,n,den);sp_invmod(den,n,den);
sp_mulmod(k,den,n,v);sp_mulmod(u,den,n,u);
sp_submod(v,u,n,s);sp_mulmod(s,b,n,s);return 0;}
