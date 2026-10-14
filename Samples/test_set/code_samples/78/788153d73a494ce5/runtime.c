/* CC0-1.0: freestanding memory support; never executed. */
#include <stddef.h>
unsigned _tls_index; void qcs_entry(void) {}
void *memcpy(void *d,const void *s,size_t n){unsigned char *a=d;const unsigned char*b=s;while(n--)*a++=*b++;return d;}
void *memset(void*d,int c,size_t n){unsigned char*a=d;while(n--)*a++=c;return d;}
int memcmp(const void*a,const void*b,size_t n){const unsigned char*x=a,*y=b;while(n--){if(*x!=*y)return *x-*y;++x;++y;}return 0;}

/* CC0-1.0: freestanding 32x32-to-64 multiplication helper. */
unsigned long long __umulsidi3(unsigned a,unsigned b){unsigned p0=(a&65535u)*(b&65535u),p1=(a&65535u)*(b>>16),p2=(a>>16)*(b&65535u),p3=(a>>16)*(b>>16);unsigned middle=(p0>>16)+(p1&65535u)+(p2&65535u);unsigned high=p3+(p1>>16)+(p2>>16)+(middle>>16);return ((unsigned long long)high<<32)|((middle<<16)|(p0&65535u));}
