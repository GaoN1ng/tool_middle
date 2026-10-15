/* CC0 development negative; not a cryptographic implementation. */
__attribute__((used,noinline)) unsigned int guard(volatile unsigned int *p){unsigned int z=1;for(unsigned i=0;i<96;i++)z=(z+p[i])^(z>>3);return z;}
static unsigned int turn(unsigned int x,unsigned n){return (x<<n)|(x>>(32-n));}
unsigned int work(unsigned int x,unsigned int y){unsigned int z=0;for(unsigned i=0;i<64;i++){
 z += turn(x,7)+turn(y,12)+turn(z,19)+x+y;
 z ^= x^y^turn(x,9)^turn(x,17)^turn(y,15)^turn(y,23);
 }return z;}
