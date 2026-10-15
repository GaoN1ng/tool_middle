/* CC0-1.0 */
unsigned ordinary(unsigned x){for(int i=0;i<64;i++){x^=x<<9;x+=0x12345678;x=(x<<7)|(x>>25);}return x;}
