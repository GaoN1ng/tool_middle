#include "algorithm/sm3.hpp"
extern "C" __attribute__((visibility("default"))) void entry(const unsigned char*p,unsigned long n,unsigned char*out){digestpp::sm3 h;h.absorb(p,n);h.digest(out,32);}
