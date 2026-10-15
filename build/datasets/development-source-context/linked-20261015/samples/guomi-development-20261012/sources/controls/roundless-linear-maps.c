/* CC0 development negative; not a cryptographic implementation. */
__attribute__((used,noinline)) unsigned int guard(volatile unsigned int *p){unsigned int z=1;for(unsigned i=0;i<96;i++)z=(z+p[i])^(z>>3);return z;}
static unsigned int turn(unsigned int x,unsigned n){return (x<<n)|(x>>(32-n));}
unsigned int work(unsigned int x){return x^turn(x,9)^turn(x,17)^turn(x,15)^turn(x,23);}
