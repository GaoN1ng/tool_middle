typedef struct rsa_st RSA; typedef struct ec_key_st EC_KEY; typedef struct ec_point_st EC_POINT;
extern int RSA_public_encrypt(int,const unsigned char*,unsigned char*,RSA*,int);
extern int ECDSA_verify(int,const unsigned char*,int,const unsigned char*,int,EC_KEY*);
extern int ECDH_compute_key(void*,unsigned long,const EC_POINT*,const EC_KEY*,void*);
int api_refs(RSA*r,EC_KEY*k,EC_POINT*p,unsigned char*b){return RSA_public_encrypt(0,b,b,r,1)+ECDSA_verify(0,b,0,b,0,k)+ECDH_compute_key(b,0,p,k,0);}
