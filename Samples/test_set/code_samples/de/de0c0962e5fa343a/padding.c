/* CC0-1.0: static-analysis regression wrapper, not an application. */
__attribute__((used,noinline)) unsigned diagnostic_padding(unsigned x){return (x*41u)^23u;}
#ifdef DEFINE_STDIO
static unsigned long fake_stream;void *stderr=&fake_stream;
#endif
