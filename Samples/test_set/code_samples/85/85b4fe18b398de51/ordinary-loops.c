/* CC0-1.0: ordinary identity/permutation, no key or output XOR. */
void fill(unsigned char*s){for(unsigned i=0;i<256;++i)s[i]=i;}
void sort(unsigned char*s){for(unsigned i=0;i<256;++i)for(unsigned j=i+1;j<256;++j)if(s[i]>s[j]){unsigned char t=s[i];s[i]=s[j];s[j]=t;}}
