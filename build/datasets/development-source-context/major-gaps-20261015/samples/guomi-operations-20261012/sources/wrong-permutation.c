#include <stdint.h>
static __attribute__((noinline)) uint32_t a(uint32_t x,unsigned n){return (x<<n)|(x>>((32-n)&31));}
static __attribute__((noinline)) uint32_t b(uint32_t x){return x^a(x,9)^a(x,18);}
static __attribute__((noinline)) uint32_t c(uint32_t x){return x^a(x,15)^a(x,23);}
void work(uint32_t *v,uint32_t *w){uint32_t p[68],q[64];
 for(unsigned j=0;j<16;j++)p[j]=w[j];
 for(unsigned j=16;j<68;j++)p[j]=c(p[j-16]^p[j-9]^a(p[j-3],15))^a(p[j-13],7)^p[j-6];
 for(unsigned j=0;j<64;j++)q[j]=p[j]^p[j+4];
 uint32_t A=v[0],B=v[1],C=v[2],D=v[3],E=v[4],F=v[5],G=v[6],H=v[7];
 for(unsigned j=0;j<64;j++){
 uint32_t ff=(j<16)?(A^B^C):((A&B)|(A&C)|(B&C));
 uint32_t gg=(j<16)?(E^F^G):((E&F)|((~E)&G));
 uint32_t t=(j<16)?0x79cc4519:0x7a879d8a;
 uint32_t u=a(a(A,12)+E+a(t,j%32),7),z=u^a(A,12);
 uint32_t x=ff+D+z+q[j],y=gg+H+u+p[j];
 D=C;C=a(B,9);B=A;A=x;H=G;G=a(F,19);F=E;E=b(y);
 }
 v[0]^=A;v[1]^=B;v[2]^=C;v[3]^=D;v[4]^=E;v[5]^=F;v[6]^=G;v[7]^=H;
}