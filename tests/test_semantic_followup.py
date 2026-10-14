"""Development-only regression witnesses and closely related negatives."""
import json,tempfile,unittest
from pathlib import Path
from support import WORKSPACE
from qcs.model import new_report,predictions
from qcs.guomi.binary_semantics import scan_binary_semantics
from qcs.guomi.source_semantics import scan_source_semantics
from qcs.function_signatures import scan_functions,DATABASE

class SemanticFollowupTests(unittest.TestCase):
    def operations(self,path):
        report=new_report(path,'executable');scan_binary_semantics(path,report,30)
        self.assertFalse(report['errors']);return predictions(report,'implementation_contains')

    def test_sm2_arm_aapcs_stack_and_interworking_equations(self):
        base=WORKSPACE/'samples/guomi-operations-20261012/builds'
        for arch in ['arm','thumb']:
            for opt in ['O0','O2','Os']:
                for name in ['bn-sign','bn-verify','mp_sign','sp_sign']:
                    with self.subTest(arch=arch,opt=opt,name=name):
                        self.assertEqual(self.operations(base/(name+'-'+arch+'-'+opt)/'sample.so'),{'SM2'})

    def test_sm2_similar_equations_and_wrong_modulus_remain_negative(self):
        base=WORKSPACE/'samples/guomi-operations-20261012/builds'
        for arch in ['arm','thumb']:
            for name in ['ecdsa','wrong-order','wrong-point','wrong-sign']:
                with self.subTest(arch=arch,name=name):
                    self.assertNotIn('SM2',self.operations(base/(name+'-'+arch+'-O2')/'sample.so'))

    def test_rc4_indexed_memory_on_three_isas(self):
        base=WORKSPACE/'samples/operation-development-20261013/builds'
        for arch in ['arm','thumb','aarch64','x86_64']:
            for opt in ['O2','Os']:
                for name,want in [('stream',{'RC4'}),('swap-only',set()),('wrong-index',set()),('missing-swap',set())]:
                    with self.subTest(arch=arch,opt=opt,name=name):
                        self.assertEqual(self.operations(base/('control-'+name+'-'+arch+'-'+opt)/'ordinary.so'),want)

    def test_rc4_stream_generator_without_xor_and_bad_swaps(self):
        raw=(WORKSPACE/'samples/semantic-development-20261013/sources/bcon/arcfour.c').read_text()
        # Includes are replaced with equivalent local byte type declarations;
        # no function identifier is needed by the operation recognizer.
        raw='typedef unsigned char BYTE;typedef unsigned long size_t;\n'+raw.replace('#include "arcfour.h"','')
        for text,want in [(raw,{'RC4'}),(raw.replace('state[j] = t;','state[j] = 0;'),set()),
                          (raw.replace('(state[i] + state[j]) % 256','(state[i] ^ state[j]) % 256'),set())]:
            with tempfile.TemporaryDirectory() as folder:
                p=Path(folder)/'ordinary.c';p.write_text(text);r=new_report(p,'source');scan_source_semantics(p,r)
                self.assertFalse(r['errors']);self.assertEqual(predictions(r,'implementation_contains'),want)

    def test_bound_iv_rejects_changed_sha256_initializer_data(self):
        db=json.loads(DATABASE.read_text())
        for arch in ['arm','thumb','aarch64']:
            sig=next(s for s in db['signatures'] if s['family']=='semantic-bearssl-sha2small' and s['architecture']==arch and s['role']=='initialization' and any(x['kind'] in {'arm_relative_pool','a64_adr_data'} for x in s['literals']))
            p=WORKSPACE/sig['reference']['artifact'];data=p.read_bytes()
            iv=bytes.fromhex(next(x['bytes'] for x in sig['literals'] if x['kind'] in {'arm_relative_pool','a64_adr_data'}))
            self.assertIn(iv,data)
            r=new_report(p,'executable');scan_functions(p,r,30);self.assertIn('SHA-256',predictions(r,'implementation_contains'))
            with tempfile.TemporaryDirectory() as folder:
                q=Path(folder)/'ordinary.so';q.write_bytes(data.replace(iv,bytes([iv[0]^1])+iv[1:]))
                r=new_report(q,'executable');scan_functions(q,r,30)
                self.assertFalse(r['errors']);self.assertNotIn('SHA-256',predictions(r,'implementation_contains'))

    def test_mips_hash_lifting_regression(self):
        base=WORKSPACE/'samples/semantic-development-20261013/builds'
        for arch in ['mipsel','mips_be']:
            for name,want in [('md5','MD5'),('sha1','SHA-1')]:
                self.assertIn(want,self.operations(base/('bcon-'+name+'-'+arch+'-O2')/'ordinary.so'))

if __name__=='__main__':unittest.main()
