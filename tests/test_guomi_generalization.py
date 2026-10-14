from support import WORKSPACE
import json
from pathlib import Path
import re
import tempfile
import unittest

from qcs.guomi.linear import leaf, rotate, xor, roles, truncate, shift, merge_shifts
from qcs.guomi.source_semantics import sm2_verify
from qcs.model import predictions
from qcs.scanner import Options, scan

DEV=WORKSPACE/'samples/guomi-development-20261012'
GUOMI={'SM2','SM3','SM4'}

class GuomiGeneralizationTests(unittest.TestCase):
    def test_linear_maps_require_shared_input_and_all_rotations(self):
        x,y=leaf((1,())),leaf((2,()))
        self.assertIn('sm3_p0',roles(xor(xor(x,rotate(x,9)),rotate(x,17))))
        self.assertNotIn('sm3_p0',roles(xor(xor(x,rotate(y,9)),rotate(x,17))))
        self.assertNotIn('sm3_p1',roles(xor(xor(x,rotate(x,14)),rotate(x,23))))
        self.assertNotIn('sm3_p0',roles(xor(xor(xor(x,rotate(x,9)),rotate(x,17)),rotate(x,4))))
        # Independently XORed recurrence terms may surround a complete P1 map.
        p1=xor(xor(x,rotate(x,15)),rotate(x,23))
        self.assertIn('sm3_p1',roles(xor(p1,y)))

    def test_exact_byte_packing_and_word_width(self):
        x=truncate(leaf((1,('sbox',))),8)
        self.assertIn('sm4_key_l',roles(xor(xor(x,rotate(x,13)),rotate(x,23))))
        shifted=merge_shifts(shift(x,'left',24),truncate(leaf((2,('sbox',))),8))
        self.assertEqual(shifted[0],'bits')
        wide=leaf((3,('wide',)))
        self.assertFalse(roles(xor(xor(wide,rotate(wide,9)),rotate(wide,17))))

    def test_sm2_verify_binds_point_coordinate_and_signature_inputs(self):
        def calls(coordinate='point',digest='e'):
            return [('work','BN_mod_add',['t','r','s','n','ctx'],10),
                    ('work','EC_POINT_mul',['group','point','s','pub','t','ctx'],20),
                    ('work','EC_POINT_get_affine_coordinates',['group',coordinate,'x','y','ctx'],30),
                    ('work','BN_mod_add',['t',digest,'x','n','ctx'],40),
                    ('work','BN_cmp',['t','r'],50)]
        self.assertTrue(sm2_verify(calls()))
        self.assertFalse(sm2_verify(calls('unrelated')))
        self.assertFalse(sm2_verify(calls(digest='r')))
        self.assertFalse(sm2_verify([c for c in calls() if c[1]!='EC_POINT_get_affine_coordinates']))

    def test_development_negatives_source_and_stripped_binary(self):
        manifest=json.loads((DEV/'control-manifest.json').read_text())
        chosen=[s for s in manifest['samples'] if s['kind']=='source' or
                (s['architecture']=='x86_64' and '-O2' in s['compiler_flags'])]
        self.assertGreaterEqual(len(chosen),16)
        for s in chosen:
            with self.subTest(sample=s['id']):
                r=scan(DEV/s['path'],options=Options(windriver=False))
                self.assertEqual(r['scan_status'],'completed',r['errors'])
                self.assertFalse(predictions(r,'implementation_contains')&GUOMI)

    def test_new_known_implementations_and_actual_cross_implementation_witnesses(self):
        for project,algorithm in [('wolfsm','SM2'),('wolfsm','SM3'),('wolfsm','SM4'),('openssl','SM3'),('openssl','SM4')]:
            with self.subTest(project=project,algorithm=algorithm):
                p=DEV/'builds'/project/algorithm.lower()/'x86_64/O2/sample.so'
                r=scan(p,options=Options(windriver=False))
                self.assertEqual(r['scan_status'],'completed',r['errors'])
                self.assertEqual(predictions(r,'implementation_contains')&GUOMI,{algorithm})
                self.assertTrue(any(f['engine']=='guomi_development_signature' for f in r['findings']))
                if algorithm!='SM2':
                    self.assertTrue(any(f['engine']=='guomi_semantic' and f.get('operation_witnesses') for f in r['findings']))

    def test_renamed_edited_source_keeps_operation_evidence_without_hash_approval(self):
        p=DEV/'sources/openssl/crypto/sm4/sm4.c'
        text=p.read_text()
        names=set(re.findall(r'\b(?:SM4_\w+|ossl_sm4_\w+|CK)\b',text))
        for i,name in enumerate(sorted(names)):text=re.sub(r'\b'+re.escape(name)+r'\b','anonymous_'+str(i),text)
        with tempfile.TemporaryDirectory() as tmp:
            changed=Path(tmp)/'ordinary.c';changed.write_text(text+'\n/* modified identifiers */\n')
            r=scan(changed,options=Options(windriver=False))
            self.assertEqual(r['scan_status'],'completed',r['errors'])
            self.assertIn('SM4',predictions(r,'implementation_contains'))
            self.assertTrue(any(f['engine']=='guomi_source_semantic' for f in r['findings']))
            self.assertFalse(any(f.get('implementation_verification')=='pinned_source_sha256' for f in r['findings']))

    def test_inactive_source_and_untrusted_evidence_are_not_predictions(self):
        text=(DEV/'sources/openssl/crypto/sm4/sm4.c').read_text()
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'ordinary.c';p.write_text('#if 0\n'+text+'\n#endif\n')
            self.assertFalse(predictions(scan(p,options=Options(windriver=False)),'implementation_contains')&GUOMI)
        from qcs.model import new_report,evidence
        r=new_report(Path('ordinary.c'),'source')
        r['findings'].append(evidence('SM3','untrusted','source_operation_graph','claim',operation_witnesses=[1]))
        self.assertFalse(predictions(r,'implementation_contains'))

    def test_self_contained_compression_and_wrong_word_width(self):
        # CC0 standard SM3 compression equations, renamed helpers. No source
        # reference hash or SM3 API spelling is available to the detector.
        text='''#include <stdint.h>
static uint32_t a(uint32_t x,unsigned n){return (x<<n)|(x>>((32-n)&31));}
static uint32_t b(uint32_t x){return x^a(x,9)^a(x,17);}
static uint32_t c(uint32_t x){return x^a(x,15)^a(x,23);}
void work(uint32_t *v,uint32_t *w){uint32_t p[68],q[64];
 for(unsigned j=0;j<16;j++)p[j]=w[j];
 for(unsigned j=16;j<68;j++)p[j]=c(p[j-16]^p[j-9]^a(p[j-3],15))^a(p[j-13],7)^p[j-6];
 for(unsigned j=0;j<64;j++)q[j]=p[j]^p[j+4];
 uint32_t A=v[0],B=v[1],C=v[2],D=v[3],E=v[4],F=v[5],G=v[6],H=v[7];
 for(unsigned j=0;j<64;j++){
 uint32_t ff=(j<16)?(A^B^C):((A&B)|(A&C)|(B&C));
 uint32_t gg=(j<16)?(E^F^G):((E&F)|((~E)&G));
 uint32_t t=(j<16)?0x79cc4519:0x7a879d8a;
 uint32_t u=a(a(A,12)+E+a(t,j%32),7),z=u^a(A,12);
 uint32_t x=ff+D+z+q[j],y=gg+H+u+p[j];
 D=C;C=a(B,9);B=A;A=x;H=G;G=a(F,19);F=E;E=b(y);
 }
 v[0]^=A;v[1]^=B;v[2]^=C;v[3]^=D;v[4]^=E;v[5]^=F;v[6]^=G;v[7]^=H;
}'''
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'ordinary.c';p.write_text(text)
            r=scan(p,options=Options(windriver=False))
            self.assertIn('SM3',predictions(r,'implementation_contains'))
            p.write_text(text.replace('uint32_t','uint64_t'))
            self.assertNotIn('SM3',predictions(scan(p,options=Options(windriver=False)),'implementation_contains'))

    def test_locally_shadowed_bn_names_are_not_trusted_operations(self):
        source='''int BN_mod_add(void*t,void*r,void*s,void*n,void*c){return 0;}
extern int EC_POINT_mul(void*,void*,void*,void*,void*,void*);
extern int EC_POINT_get_affine_coordinates(void*,void*,void*,void*,void*);
extern int BN_cmp(void*,void*);
int work(void*g,void*p,void*t,void*r,void*s,void*e,void*x,void*n){
BN_mod_add(t,r,s,n,0);EC_POINT_mul(g,p,s,p,t,0);
EC_POINT_get_affine_coordinates(g,p,x,0,0);BN_mod_add(t,e,x,n,0);return BN_cmp(t,r);}'''
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'ordinary.c';p.write_text(source)
            self.assertNotIn('SM2',predictions(scan(p,options=Options(windriver=False)),'implementation_contains'))

if __name__=='__main__':unittest.main()
