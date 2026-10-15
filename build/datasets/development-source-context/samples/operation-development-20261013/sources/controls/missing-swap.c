/* CC0-1.0: RC4 PRGA relation, neutral identifiers. */
void ordinary(unsigned char *s,unsigned i,unsigned j,const unsigned char *in,unsigned char *out,unsigned n) {
 for(unsigned k=0;k<n;k++){
  i=(i+1)&255;unsigned a=s[i];j=(j+a)&255;unsigned b=s[j];
  s[i]=b;out[k]=in[k]^s[(a+b)&255];
 }
}
