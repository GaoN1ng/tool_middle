/* CC0-1.0: RFC 8439 quarter-round relationship, neutral names. */
#include <stdint.h>
#define R(x,n) (((x)<<(n))|((x)>>(32-(n))))
void ordinary(uint32_t *s) {
 uint32_t a=s[0],b=s[1],c=s[2],d=s[3];
 a+=b;d^=a;d=R(d,16);c+=d;b^=c;b=R(b,12);
 a+=b;d^=a;d=R(d,8);c+=d;b^=c;b=R(b,6);
 s[0]=a;s[1]=b;s[2]=c;s[3]=d;
}
