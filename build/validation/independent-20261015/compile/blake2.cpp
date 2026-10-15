#include "algorithm/blake2.hpp"
extern "C" __attribute__((visibility("default"))) void entry(const unsigned char*p,unsigned long n,unsigned char*out){digestpp::blake2b h;h.absorb(p,n);h.digest(out,64);}
