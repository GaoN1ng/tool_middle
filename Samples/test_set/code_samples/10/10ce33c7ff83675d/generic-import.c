extern void *EC_KEY_new(void);extern int EC_KEY_generate_key(void*);extern void *BN_new(void);
int generic_refs(void){void*k=EC_KEY_new();BN_new();return EC_KEY_generate_key(k);}
