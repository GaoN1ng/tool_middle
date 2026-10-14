from support import WORKSPACE
import json
from pathlib import Path
import tempfile
import unittest

from qcs.model import predictions
from qcs.scanner import Options, scan

BASE=WORKSPACE/'quantum-crypto-scanner/artifacts/guomi-integration-20261012'

class GuomiTests(unittest.TestCase):
    def source(self,text,suffix='.c'):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/('ordinary'+suffix);p.write_text(text)
            return scan(p,options=Options(windriver=False))

    def test_c_apis_are_calls_not_implementations(self):
        r=self.source('void f(void){sm2_sign(k,h,s,n);sm3_init(c);sm4_encrypt(k,in,out);}')
        self.assertEqual(predictions(r,'api_reference'),{'SM2','SM3','SM4'})
        self.assertFalse(predictions(r,'implementation_contains'))

    def test_c_decoys_and_generic_curve_are_not_promoted(self):
        for text in ['// sm2_sign(k,h,s,n);\nconst char *s="sm3_init(c)";',
                     'void sm4_encrypt(void) {}\nvoid sm3_init(void);',
                     'void f(void){sm2_z256_point_mul(a,b,c);encrypt(x);}',
                     '#define DIGEST(x) sm3_init(x)\n']:
            with self.subTest(text=text):
                r=self.source(text);self.assertFalse(predictions(r,'api_reference'))
                self.assertFalse(predictions(r,'implementation_contains'))

    def test_explicit_openssl_guomi_selectors(self):
        r=self.source('void f(){EVP_MD_fetch(0,"SM3",0);EVP_CIPHER_fetch(0,"SM4-CBC",0);EVP_PKEY_CTX_new_id(EVP_PKEY_SM2,0);}')
        self.assertEqual(predictions(r,'api_reference'),{'SM2','SM3','SM4'})

    def test_pinned_source_recognized_after_rename_but_modified_bytes_not_approved(self):
        for unit,expected in [('sm3.c','SM3'),('sm4.c','SM4'),('sm2_sign.c','SM2'),('sm2_enc.c','SM2')]:
            original=BASE/'upstream/gmssl/src'/unit
            with self.subTest(unit=unit),tempfile.TemporaryDirectory() as tmp:
                p=Path(tmp)/'ordinary.c';p.write_bytes(original.read_bytes())
                self.assertIn(expected,predictions(scan(p,options=Options(windriver=False)),'implementation_contains'))
                p.write_bytes(original.read_bytes()+b'\n/* edited */')
                changed=scan(p,options=Options(windriver=False))
                self.assertFalse(any(f['algorithm']==expected and f.get('implementation_verification')=='pinned_source_sha256'
                                     for f in changed['findings']))

    def test_javascript_import_aliases_and_normal_sm3_calls(self):
        snippets=[("const {sm3}=require('sm-crypto');sm3('abc');",{'SM3'}),
                  ("import {sm2 as c} from 'sm-crypto';c.doEncrypt(m,k);",{'SM2'}),
                  ("import * as gm from 'sm-crypto';const b=gm.sm4;b['encrypt'](m,k);",{'SM4'}),
                  ("const gm=require('sm-crypto');gm.sm3(m);gm.sm4.encrypt(m,k);",{'SM3','SM4'})]
        for text,expected in snippets:
            with self.subTest(text=text):
                r=self.source(text,'.mjs');self.assertEqual(r['scan_status'],'completed',r['errors'])
                self.assertEqual(predictions(r,'api_reference'),expected)
                self.assertFalse(predictions(r,'implementation_contains'))

    def test_javascript_false_positive_boundaries(self):
        for text in ["const sm4={encrypt:x=>x};sm4.encrypt(m);",
                     "const {sm4}=require('unrelated');sm4.encrypt(m);",
                     "const {sm3}=require('sm-crypto');const s='sm3(m)';const t=`sm3(m)`;const r=/sm3(m)/; //sm3(m)\n",
                     "const {sm4}=require('sm-crypto');function f(sm4){sm4.encrypt(m,k);}",
                     "const {sm3}=require('sm-crypto');{const sm3=x=>x;sm3(m);}",
                     "const {sm3}=require('sm-crypto');function f(){if(x){var sm3;}sm3(m);}",
                     "const {sm4}=require('sm-crypto');sm4.encrypt=other;sm4.encrypt(m,k);",
                     "const {sm4}=require('sm-crypto');const alias=sm4;alias.encrypt=other;sm4.encrypt(m,k);",
                     "const {sm4}=require('sm-crypto');with(other){sm4.encrypt(m,k);}",
                     "let {sm3}=require('sm-crypto');sm3=other;sm3(m);",
                     "function f(require){const {sm3}=require('sm-crypto');sm3(m);}",
                     "const {sm4}=require('sm-crypto');sm4[method](m,k);"]:
            with self.subTest(text=text):self.assertFalse(predictions(self.source(text,'.cjs'),'api_reference'))

    def test_javascript_parse_errors_are_partial(self):
        r=self.source("const {sm3}=require('sm-crypto'); sm3(m); const = ;",'.js')
        self.assertEqual(r['scan_status'],'partial')
        self.assertTrue(any(e['code']=='parse_error' for e in r['errors']))

    def test_team_js_regressions(self):
        root=BASE/'provided/js/dataset/js-guomi'
        for row in json.loads((root/'manifest.json').read_text()):
            with self.subTest(name=row['name']):
                r=scan(root/(row['name']+'.cjs'),options=Options(windriver=False))
                self.assertEqual(r['scan_status'],'completed',r['errors'])
                self.assertEqual(predictions(r,'api_reference'),set(row['expected']))

    def test_sm4_table_only_elf_stays_a_clue(self):
        for p in (BASE/'provided/elf').glob('table_only*.elf'):
            with self.subTest(path=p):
                r=scan(p);self.assertEqual(r['scan_status'],'completed',r['errors'])
                self.assertNotIn('SM4',predictions(r,'implementation_contains'))
                self.assertTrue(any('SM4' in c['candidate_algorithms'] for c in r['clues']))

    def test_stripped_relinked_operations_across_six_architectures(self):
        rows=json.loads((BASE/'verification/relinked-manifest.json').read_text())
        self.assertEqual(len(rows),108)
        self.assertEqual({r['reference']['architecture'] for r in rows},
                         {'x86_64','aarch64','arm','thumb','mipsel','mips_be'})
        for row in rows:
            with self.subTest(path=row['path']):
                r=scan(WORKSPACE/row['path'])
                self.assertEqual(r['scan_status'],'completed',r['errors'])
                self.assertEqual(predictions(r,'implementation_contains'),set(row['expected']))
                self.assertNotIn('.symtab',r['artifact']['symbol_tables'])
                self.assertTrue(any(f['engine']=='guomi_function_signature' for f in r['findings']))

    def test_required_operation_role_cannot_be_removed(self):
        for module,role,algorithm in [('sm3','finalization','SM3'),('sm4','key_schedule','SM4')]:
            p=BASE/'verification/relinked/x86_64'/('gmssl-'+module+'-O2-small0.so')
            r=scan(p)
            finding=next(f for f in r['findings'] if f['engine']=='guomi_function_signature')
            data=bytearray(p.read_bytes())
            for witness in finding['matched_functions']:
                if witness['role']==role:
                    start=witness['offset'];data[start:start+witness['length']]=bytes(witness['length'])
            with self.subTest(module=module),tempfile.TemporaryDirectory() as tmp:
                changed=Path(tmp)/'ordinary.so';changed.write_bytes(data)
                report=scan(changed)
                self.assertEqual(report['scan_status'],'completed',report['errors'])
                self.assertFalse(any(f['algorithm']==algorithm and f['engine']=='guomi_function_signature'
                                     for f in report['findings']))
                self.assertTrue(any(c['engine']=='guomi_function_signature' and algorithm in c['candidate_algorithms']
                                    for c in report['clues']))

    def test_referenced_sm4_table_bytes_must_match(self):
        p=BASE/'verification/relinked/x86_64/gmssl-sm4-O2-small0.so'
        # FK is folded into instructions in this build. CK is actual referenced
        # data and has separate literal constraints, so change CK bytes.
        raw=p.read_bytes();ck=bytes.fromhex('150e0700312a231c')
        self.assertTrue(ck in raw,'Expected referenced CK literal missing')
        with tempfile.TemporaryDirectory() as tmp:
            changed=Path(tmp)/'ordinary.so';changed.write_bytes(raw.replace(ck,bytes(8)))
            r=scan(changed)
            self.assertEqual(r['scan_status'],'completed',r['errors'])
            self.assertNotIn('SM4',predictions(r,'implementation_contains'))

    def test_constants_and_function_bytes_in_data_are_not_implementations(self):
        for name in ['standard-constants-only','known-code-as-nonexec-data']:
            with self.subTest(name=name):
                r=scan(BASE/'verification/controls'/(name+'.so'))
                self.assertEqual(r['scan_status'],'completed',r['errors'])
                self.assertFalse(predictions(r,'implementation_contains'))

    def test_javascript_invalid_encoding_is_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'ordinary.js';p.write_bytes(b'const text="\xff";')
            r=scan(p)
            self.assertEqual(r['scan_status'],'partial')
            self.assertTrue(any(e['code']=='source_encoding' for e in r['errors']))

if __name__=='__main__':unittest.main()
