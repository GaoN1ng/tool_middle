void generic(){EC_KEY_generate_key(k);mbedtls_ecp_gen_key(g,k,f,p);EVP_EncryptInit_ex(c,selector,0,k,i);BN_new();}
