/* CC0-1.0; QCS semantic controls, not an independent author. */
#include "curves/prj_pt.h"
int ordinary(unsigned char *out,unsigned short len,const unsigned char *peer,unsigned short n,nn_src_t d,ec_shortw_crv_src_t curve){
 prj_pt q; int r=prj_pt_import_from_aff_buf(&q,peer,n,curve);if(r)return r;
 
 r=prj_pt_unique(&q,&q);if(r)return r;
 return fp_export_to_buf(out,len,&q.X);
}
