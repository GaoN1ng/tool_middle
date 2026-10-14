from support import WORKSPACE
import json
import re
import tempfile
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from qcs.evaluate import metrics
from qcs.model import CORE_ALGORITHMS, evidence, new_report, predictions
from qcs.scanner import Options, scan
from qcs.source import lex_cpp, resolve_selector, split_arguments

class SourceTests(unittest.TestCase):
    def scan_text(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture.cpp"
            path.write_text(text)
            return scan(path, "source", Options(windriver=False))

    def test_multiline_call_and_line_numbers(self):
        r = self.scan_text('// AES_encrypt(0);\nvoid work() {\n AES_encrypt\n (a, b, k);\n RSA_sign(t,x,n,s,&l,r);\n}\n')
        self.assertEqual(predictions(r, "api_reference"), {"AES", "RSA"})
        self.assertEqual([x["line"] for x in r["findings"]], [3, 5])

    def test_comments_literals_raw_strings_urls_and_escaped_quotes(self):
        text = '/* RSA_sign(x); */\nconst char *url="https://host/*path*/";\nconst char *s="escaped \\\" RSA_sign(x) //";\nconst char *raw=R"end(ECDSA_sign(x) ") //)end";\n// AES_encrypt(x);\nvoid go(){ mbedtls_ecdh_compute_shared(g,z,q,d,f,p); }'
        code, visible, _ = lex_cpp(text)
        self.assertEqual(len(code), len(text))
        self.assertEqual([i for i,c in enumerate(code) if c=='\n'], [i for i,c in enumerate(text) if c=='\n'])
        r = self.scan_text(text)
        self.assertEqual(predictions(r, "api_reference"), {"ECDH"})
        self.assertEqual(r["findings"][0]["line"], 6)

    def test_declarations_definitions_macros_and_names(self):
        r = self.scan_text('#include <openssl/aes.h>\nvoid AES_encrypt(int);\nvoid RSA_sign(int x) { (void)x; }\n#define WRAP(x) ECDSA_sign(x)\nconst char *n="RSA AES";\nint AES_counter=0;')
        self.assertEqual(predictions(r, "api_reference"), set())
        self.assertEqual(predictions(r, "implementation_contains"), set())
        self.assertFalse(any(x["confidence"] == "high" for x in r["findings"]))
        self.assertTrue(any(x["identifier"] == "RSA_sign" and x["source_role"] == "definition" for x in r["clues"]))

    def test_nested_selector_arguments_keep_positions_and_lines(self):
        calls = [
            ('EVP_MD_fetch(get_context(0, 1), "SHA256", 0)', 'SHA-256'),
            ('EVP_MD_fetch(contexts[index(0, 1)], "SHA256", 0)', 'SHA-256'),
            ('EVP_MD_fetch((Context){1, 2}, "SHA256", 0)', 'SHA-256'),
            ('EVP_MD_fetch([](int a, int b){return 0;}(0, 1), "SHA256", 0)', 'SHA-256'),
            ('EVP_CIPHER_fetch(get_context(0, 1), "AES-256-GCM", "provider,a")', 'AES'),
            ('mbedtls_gcm_setkey(get_context(0, 1), MBEDTLS_CIPHER_ID_AES, k, n)', 'AES'),
            ('mbedtls_sha256(input(a, b), length(a, b), output(a, b), 0)', 'SHA-256'),
        ]
        for call, algorithm in calls:
            with self.subTest(call=call):
                text = '// header\nvoid work(){\n ' + call + ';\n}\n'
                report = self.scan_text(text)
                self.assertEqual(predictions(report, 'api_reference'), {algorithm})
                finding = report['findings'][0]
                self.assertEqual(finding['line'], 3)
                self.assertEqual(finding['offset'], text.index(call))

    def test_literal_delimiters_and_comments_do_not_split_arguments(self):
        calls = [
            'EVP_MD_fetch(make_context("a,b)[{", \'x\'), "SHA256", 0)',
            'EVP_MD_fetch(make_context(R"tag(a,b)[{)tag", \'x\'), "SHA256", 0)',
            'EVP_MD_fetch(make_context("a,\\\"b", \'\\\'\'), "SHA256", 0)',
            'EVP_MD_fetch(get_context(0, /* ), ] } , */ 1), /* , */ "SHA256", 0)',
            'EVP_MD_fetch(\n get_context(0, 1),\n "SHA256",\n 0)',
        ]
        for call in calls:
            with self.subTest(call=call):
                report = self.scan_text('void work(){' + call + ';}\n')
                self.assertEqual(predictions(report, 'api_reference'), {'SHA-256'})

    def test_unresolved_selectors_and_malformed_arguments_stay_clues(self):
        calls = [
            'EVP_MD_fetch(get_context(0, 1), selector, 0)',
            'EVP_MD_fetch(0, choose("SHA256", "MD5"), 0)',
            'EVP_MD_fetch(0, "SHA" "256", 0)',
            'EVP_MD_fetch(0, R"(SHA256)", 0)',
            'EVP_MD_fetch(0, "SHA256,MD5", 0)',
            'mbedtls_sha256(input(a, b), n, o, choose(0, 1))',
        ]
        for call in calls:
            with self.subTest(call=call):
                report = self.scan_text('void work(){' + call + ';}\n')
                self.assertEqual(predictions(report, 'api_reference'), set())
        for args in ('get_context(0, 1], "SHA256", 0', '0, "SHA256",', '0,,"SHA256"', '(0, "SHA256", 0'):
            with self.subTest(args=args):
                self.assertIsNone(split_arguments(args))
                self.assertIsNone(resolve_selector('EVP_MD_fetch', args))

    def test_empty_and_fake_named_definitions_are_not_implementations(self):
        definitions = [
            'void SHA256_Update(void) {}',
            'void SHA256_Update(void) { /* real SHA256? */ }',
            'int RSA_sign(void) { return 0; }',
            'int AES_encrypt(int x) { return x + 1; }',
            'void tc_sha256_final(void) { int x = 0; for (; x < 64; x++) {} }',
        ]
        for definition in definitions:
            with self.subTest(definition=definition):
                report = self.scan_text(definition)
                self.assertEqual(report['scan_status'], 'completed')
                self.assertFalse(report['findings'])
                self.assertFalse(report['algorithm_assets'])
                self.assertEqual(predictions(report, 'implementation_contains'), set())
                self.assertTrue(any(x.get('source_role') == 'definition' and x['candidate_algorithms'] for x in report['clues']))

    def test_wrapper_only_proves_api_reference(self):
        report = self.scan_text('void SHA256_Update(void) { SHA256(data, length, output); }')
        self.assertEqual(predictions(report, 'api_reference'), {'SHA-256'})
        self.assertEqual(predictions(report, 'implementation_contains'), set())
        self.assertTrue(all(x['source_role'] == 'call' for x in report['findings']))

    def test_legacy_definition_evidence_is_not_implementation_prediction(self):
        report = new_report(Path('empty.c'), 'source')
        report['findings'].append(evidence('SHA-256', 'source', 'source_api', 'SHA256_Update', source_role='definition'))
        self.assertEqual(predictions(report, 'implementation_contains'), set())
        report['findings'][0].update(evidence_type='source_implementation', implementation_verification='pinned_source_sha256')
        self.assertEqual(predictions(report, 'implementation_contains'), set())

    def test_pinned_real_source_matches_without_using_path(self):
        reference = WORKSPACE/'samples/public-benchmark/sources/esp-idf/components/bt/common/tinycrypt/src/sha256.c'
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'renamed.c'
            path.write_bytes(reference.read_bytes())
            report = scan(path, 'source', Options(windriver=False))
            self.assertEqual(predictions(report, 'implementation_contains'), {'SHA-256'})
            verified = [x for x in report['findings'] if x['evidence_type'] == 'source_implementation']
            self.assertTrue(verified)
            self.assertTrue(all(x['source_sha256'] == report['artifact']['sha256'] == x['reference_source']['sha256'] for x in verified))
            self.assertTrue(all(x['reference_source']['commit'] and x['reference_source']['license'] for x in verified))

    def test_modified_reference_and_same_path_stub_require_new_verification(self):
        reference = WORKSPACE/'samples/public-benchmark/sources/esp-idf/components/bt/common/tinycrypt/src/sha256.c'
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'sha256.c'
            raw = reference.read_bytes()
            self.assertIn(b'0x6a09e667', raw.lower())
            path.write_bytes(re.sub(b'0x6a09e667', b'0x6a09e666', raw, flags=re.I))
            report = scan(path, 'source', Options(windriver=False))
            self.assertEqual(predictions(report, 'implementation_contains'), set())
            self.assertFalse(any(x['evidence_type'] == 'source_implementation' for x in report['findings']))
            path.write_text('void tc_sha256_final(void) {}')
            self.assertFalse(scan(path, 'source', Options(windriver=False))['algorithm_assets'])

    def test_pinned_source_with_conditional_initializer_braces(self):
        reference = WORKSPACE/'samples/public-benchmark/sources/tasmota/lib/lib_ssl/bearssl-esp8266/src/symcipher/chacha20_ct.c'
        report = scan(reference, 'source', Options(windriver=False))
        self.assertEqual(predictions(report, 'implementation_contains'), {'ChaCha20'})
        self.assertTrue(any(x['identifier'] == 'br_chacha20_ct_run' and x['evidence_type'] == 'source_implementation' for x in report['findings']))

    def test_missing_source_reference_database_is_an_explicit_failure(self):
        with patch('qcs.source.DATABASE', Path('/qcs-missing-source-reference.json')):
            report = self.scan_text('void SHA256_Update(void) {}')
        # The new independent Guomi source channel can complete, but cannot
        # conceal the core source engine failure or turn the stub into proof.
        self.assertEqual(report['scan_status'], 'partial')
        self.assertEqual(report['engine_status']['source']['status'], 'failed')
        self.assertTrue(report['errors'])
        self.assertFalse(report['algorithm_assets'])
        with patch('qcs.source.DATABASE', Path('/qcs-missing-source-reference.json')), \
             patch('qcs.guomi.SOURCE_PATH', Path('/qcs-missing-guomi-reference.json')):
            report = self.scan_text('void SHA256_Update(void) {}')
            # The independent Guomi engines can complete while the general
            # reference engine fails. Aggregate status must retain that failure.
            self.assertEqual(report['scan_status'], 'partial')
        self.assertFalse(report['algorithm_assets'])

    def test_generic_ec_evp_bn_and_variable_selector(self):
        r = self.scan_text('void x(){ EC_KEY_generate_key(k); mbedtls_ecp_gen_key(g,k,f,p); BN_new(); EVP_EncryptInit_ex(c,a,0,k,i); EVP_CIPHER_fetch(0, name, 0); EVP_PKEY_CTX_new_id(EVP_PKEY_EC,0); }')
        self.assertEqual(predictions(r, "api_reference"), set())
        self.assertTrue(any(x.get("clue_category") == "elliptic_curve_generic" for x in r["clues"]))

    def test_explicit_selectors_and_sha224_ambiguity(self):
        r = self.scan_text('void x(){ EVP_CIPHER_fetch(0,"AES-256-GCM",0); EVP_MD_fetch(0,"SHA256",0); EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,0); mbedtls_sha256(x,n,o,0); }')
        self.assertEqual(predictions(r, "api_reference"), {"AES", "SHA-256", "RSA"})
        r = self.scan_text('void x(){ mbedtls_sha256(x,n,o,flag); mbedtls_sha256_starts(ctx,1); }')
        self.assertFalse(r["findings"])

    def test_mbedtls_explicit_modes_and_generic_ec_type(self):
        r=self.scan_text('void x(){mbedtls_gcm_setkey(c,MBEDTLS_CIPHER_ID_AES,k,n);mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);}')
        self.assertEqual(predictions(r,'api_reference'),{'AES','SHA-256'})

    def test_all_core_apis(self):
        r = self.scan_text('void x(){ AES_encrypt(a,b,k); DES_ecb_encrypt(a,b,k,1); RC4(k,n,a,b); EVP_chacha20(); RSA_sign(t,a,n,b,&l,r); ECDSA_sign(t,a,n,b,&l,k); ECDH_compute_key(a,n,p,k,f); MD5(a,n,b); SHA1(a,n,b); SHA256(a,n,b); }')
        self.assertEqual(predictions(r,"api_reference"), set(CORE_ALGORITHMS))

    def test_terminal_apis_keep_generic_ec_and_names_unresolved(self):
        r = self.scan_text('void x(){br_aes_ct_cbcenc_run(c,v,d,n);tc_sha256_final(o,c);uECC_shared_secret(q,d,z,c);gxecdsa_sign(k,d,s);ecc_verify(s,h,k,r);uECC_make_key(q,d,c);br_ec_keygen(r,i,k,o);br_aes_fake_encrypt(x);}\n')
        self.assertEqual(predictions(r, 'api_reference'), {'AES', 'SHA-256', 'ECDH', 'ECDSA'})
        self.assertFalse(any(x['identifier'] == 'br_aes_fake_encrypt' for x in r['findings']))
        self.assertTrue(any(x.get('clue_category') == 'elliptic_curve_generic' for x in r['clues']))
        negative = self.scan_text('void tc_aes_encrypt(int); // gxecdsa_sign(x);\nconst char *s="br_rsa_i15_public(x)";\nvoid x(){uECC_make_key(q,d,c);br_ec_keygen(r,i,k,o);}\n')
        self.assertFalse(negative['findings'])

    def test_combined_digest_is_two_explicit_algorithms(self):
        r = self.scan_text('void x(){EVP_md5_sha1();br_md5sha1_init(c);}\n')
        self.assertEqual(predictions(r, 'api_reference'), {'MD5', 'SHA-1'})
        self.assertEqual(len(r['findings']), 4)

    def test_cp1252_source_both_engines_preserve_line_numbers(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'legacy.c'
            path.write_bytes(b'// Windows comment \x96 AES_encrypt(x);\nvoid x(){tc_sha256_final(o,c);}\n')
            r = scan(path, 'source')
            self.assertEqual(r['scan_status'], 'completed')
            self.assertEqual(r['artifact']['source_encoding'], 'cp1252_fallback')
            self.assertEqual(predictions(r, 'api_reference'), {'SHA-256'})
            self.assertEqual(r['findings'][0]['line'], 2)

class EngineTests(unittest.TestCase):
    def test_pe_combined_digest_selector(self):
        sys.path.insert(0, str(WORKSPACE/'quantum-crypto-scanner/tools'))
        from pe_fixture import named_import_pe
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'digest.exe'
            path.write_bytes(named_import_pe(('EVP_md5_sha1',)))
            r = scan(path, 'executable')
            self.assertEqual(predictions(r, 'api_reference'), {'MD5', 'SHA-1'})
            self.assertEqual(len(r['findings']), 2)

    def test_pe_named_imports_and_generic_negative(self):
        import sys
        sys.path.insert(0,str(WORKSPACE / 'quantum-crypto-scanner/tools'))
        from pe_fixture import named_import_pe
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'fixture.exe';p.write_bytes(named_import_pe())
            r=scan(p,'executable')
            self.assertEqual(r['scan_status'],'completed')
            self.assertEqual(predictions(r,'api_reference'),{'RSA','ECDSA','ECDH'})
            self.assertTrue(all(x['symbol_table']=='PE.imports' for x in r['findings']))
            p.write_bytes(named_import_pe(('EC_KEY_generate_key','EVP_EncryptInit_ex','BN_new')))
            r=scan(p,'executable')
            self.assertEqual(predictions(r,'api_reference'),set())
            self.assertTrue(r['dependencies'])

    def test_existing_yara_sha1_end_to_end(self):
        path = WORKSPACE / 'third_party/crypto-detection/example/sha1/sha1test.out'
        r = scan(path, 'executable')
        self.assertEqual(r['scan_status'], 'completed')
        self.assertIn('SHA-1', predictions(r,'implementation_contains'))
        self.assertEqual([x['algorithm'] for x in r['algorithm_assets']], ['SHA-1'])
        self.assertGreaterEqual(r['algorithm_assets'][0]['evidence_count'], 2)

    def test_shared_iv_base64_and_chacha_are_not_definite(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'data.bin'
            p.write_bytes(bytes.fromhex('67E6096A85AE67BB72F36E3C3AF54FA57F520E518C68059BABD9831F19CDE05B') + b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' + b'expand 32-byte k')
            r=scan(p,'executable')
            self.assertEqual(predictions(r,'implementation_contains'),set())
            ids={x['identifier'] for x in r['clues']}
            self.assertTrue({'SHA2_BLAKE2_IVs','BASE64_table','Chacha_256_constant'} <= ids)
            self.assertEqual(r['scan_status'],'partial')  # raw format lacks symbol channel

    def test_aes_rules_deduplicate_and_keep_offsets(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'tables.bin'
            p.write_bytes(bytes.fromhex('637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0') + bytes.fromhex('8d01020408102040801b36'))
            r=scan(p,'executable')
            self.assertEqual([x['algorithm'] for x in r['algorithm_assets']],['AES'])
            self.assertGreaterEqual(r['algorithm_assets'][0]['evidence_count'],2)
            self.assertTrue(all(x['matches'] for x in r['findings']))

    def test_unknown_bin_not_firmware_or_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'unknown.bin';p.write_bytes(b'\x00\x01ordinary data')
            r=scan(p)
            self.assertEqual(r['scan_status'],'unsupported')
            self.assertEqual(r['input_kind'],'unknown')

    def test_plain_text_names_remain_weak(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'config.txt';p.write_text('AES_encrypt(0); RSA enabled\n')
            r=scan(p)
            self.assertEqual(r['scan_status'],'completed')
            self.assertFalse(r['findings'])
            self.assertTrue(r['clues'])

    def test_missing_input_and_malformed_elf(self):
        self.assertEqual(scan('/missing-qcs-file')['scan_status'],'failed')
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'bad.elf';p.write_bytes(b'\x7fELFbroken')
            r=scan(p)
            self.assertEqual(r['scan_status'],'partial')
            self.assertTrue(any(e['engine']=='symbol' for e in r['errors']))

    def test_rule_compile_error_is_json_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'invalid.yar';p.write_text('rule bad { condition: syntax_error }')
            target=WORKSPACE/'third_party/crypto-detection/example/sha1/sha1test.out'
            r=scan(target,'executable',Options(rules=p))
            self.assertEqual(r['scan_status'],'partial')
            self.assertTrue(any(e['engine']=='yara' for e in r['errors']))

    def test_missing_dependency_is_distinct(self):
        with patch('qcs.symbols.scan_symbols',side_effect=ModuleNotFoundError('pyelftools')):
            r=scan(WORKSPACE/'third_party/crypto-detection/example/sha1/sha1test.out','executable')
        self.assertTrue(any(e['code']=='missing_dependency' for e in r['errors']))

    def test_file_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(3): (Path(tmp)/f'{i}.c').write_text('int x;')
            r=scan(tmp,'source',Options(max_files=1,windriver=False))
            self.assertEqual(r['scan_status'],'partial')
            self.assertEqual(len(r['components']),1)

class EvaluationTests(unittest.TestCase):
    def test_project_architecture_groups_keep_failed_objects(self):
        import hashlib
        from qcs.evaluate import evaluate
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root/'source.c'
            source.write_text('void x(){tc_aes_encrypt(o,i,k);}\n')
            sample = {'id': 'grouped', 'path': 'source.c', 'kind': 'source', 'split': 'acceptance',
                'source': 'authored test', 'license': 'CC0-1.0', 'build': 'literal source',
                'truth_basis': 'literal AES call', 'truth': {'api_reference': ['AES'], 'implementation_contains': None},
                'architecture': 'test-architecture', 'compiler_flags': [], 'symbol_state': 'not_applicable',
                'sha256': hashlib.sha256(source.read_bytes()).hexdigest(), 'terminal_business_type': None,
                'project': 'test-project', 'family': 'test-family'}
            manifest = root/'manifest.json'
            manifest.write_text(json.dumps({'algorithms': ['AES'], 'samples': [sample]}))
            result = evaluate(manifest, root/'reports', Options(windriver=False))
            self.assertEqual(result['metrics']['api_reference']['project:test-project']['micro']['TP'], 1)
            self.assertEqual(result['metrics']['api_reference']['architecture:test-architecture']['sample_count'], 1)
            source.write_text('void changed(){}\n')
            result = evaluate(manifest, root/'failed', Options(windriver=False))
            group = result['metrics']['api_reference']['project:test-project']
            self.assertFalse(result['evaluation_complete'])
            self.assertEqual(group['sample_count'], 1)
            self.assertEqual(group['micro']['FN'], 1)
            self.assertEqual(group['scan_completion_rate'], 0)

    def test_multilabel_counts_and_failure_not_exact_match(self):
        rows=[{'truth':['AES','RSA'],'predicted':['AES'],'scan_status':'completed'},
              {'truth':[],'predicted':['RSA'],'scan_status':'completed'},
              {'truth':[],'predicted':[],'scan_status':'failed'}]
        m=metrics(rows,['AES','RSA'])
        self.assertEqual(m['per_algorithm']['RSA']['FN'],1)
        self.assertEqual(m['per_algorithm']['RSA']['FP'],1)
        self.assertEqual(m['per_algorithm']['RSA']['TN'],1)
        self.assertEqual(m['file_exact_match_rate'],0)
        self.assertEqual(m['scan_completion_rate'],2/3)

@unittest.skipUnless((WORKSPACE/'quantum-crypto-scanner/fixtures/manifest.json').exists(), 'Build labelled fixtures first')
class BuiltArtifactTests(unittest.TestCase):
    root=WORKSPACE/'quantum-crypto-scanner/fixtures'

    def test_mixed_libc_and_defined_asymmetric_symbols(self):
        r=scan(self.root/'binary/mixed-holdout.so','executable')
        self.assertEqual(r['scan_status'],'completed')
        self.assertTrue({'RSA','ECDSA','ECDH','AES'} <= predictions(r,'implementation_contains'))
        self.assertTrue(any(d['name'].startswith('libc') for d in r['dependencies']))
        self.assertTrue({'.symtab','.dynsym'} <= set(r['artifact']['symbol_tables']))
        self.assertTrue(any(x.get('symbol_status')=='defined' and '.symtab' in x.get('symbol_tables',[]) for x in r['findings']))
        rsa=next(x for x in r['findings'] if x['identifier']=='mbedtls_rsa_public')
        self.assertEqual(rsa['symbol_tables'],['.symtab'])

    def test_dynamic_asymmetric_and_library_only_negative(self):
        r=scan(self.root/'binary/imports.so','executable')
        self.assertEqual(predictions(r,'api_reference'),{'RSA','ECDSA','ECDH'})
        for name in ['library-only.so','generic-import.so']:
            r=scan(self.root/'binary'/name,'executable')
            self.assertTrue(r['dependencies'])
            self.assertFalse(r['algorithm_assets'])

    def test_actual_stripped_aes_and_known_rsa_signature(self):
        r=scan(self.root/'binary/aes-stripped.so','executable')
        self.assertIn('AES',predictions(r,'implementation_contains'))
        self.assertNotIn('.symtab',r['artifact']['symbol_tables'])
        r=scan(self.root/'binary/rsa-stripped.so','executable')
        self.assertIn('RSA',predictions(r,'implementation_contains'))
        self.assertTrue(any(x['engine']=='function_signature' and x['algorithm']=='RSA' for x in r['findings']))
        self.assertTrue(any('asymmetric' in n for n in r['coverage_notes']))

    def test_arm_and_big_endian_only_constant_evidence(self):
        for name in ['aes-arm.o','aes-ppc-be.o']:
            r=scan(self.root/'binary'/name,'executable')
            self.assertIn('AES',predictions(r,'implementation_contains'))
            self.assertFalse(any(x['evidence_type']=='binary_instruction' for x in r['findings']))
        self.assertEqual(r['artifact']['bits'],32)
        self.assertEqual(r['artifact']['endianness'],'big')

    def test_firmware_trace_and_asymmetric_symmetric_channels(self):
        r=scan(self.root/'firmware.squashfs','firmware')
        self.assertEqual(r['scan_status'],'completed')
        self.assertTrue({'AES','RSA','ECDSA','ECDH','SHA-1'} <= predictions(r,'implementation_contains'))
        self.assertTrue({'AES','RSA','ECDSA','ECDH','SHA-1'} <= {a['algorithm'] for a in r['algorithm_assets']})
        for c in r['components']:
            self.assertEqual(c['artifact']['firmware_sha256'],r['artifact']['sha256'])
            self.assertTrue(c['artifact']['firmware_relative_path'])
            self.assertTrue(c['artifact']['sha256'])
            self.assertTrue(c['extraction_chain'])
            self.assertNotIn('/tmp/qcs-firmware-',json.dumps(c))

    def test_extraction_error_and_limits(self):
        r=scan(self.root/'broken-firmware.img','firmware')
        self.assertIn(r['scan_status'],{'unsupported','failed'})
        self.assertTrue(r['errors'])
        r=scan(self.root/'firmware.squashfs','firmware',Options(max_files=2))
        self.assertEqual(r['scan_status'],'partial')
        self.assertTrue(r['errors'])

    def test_recursive_firmware_depth_limit(self):
        import shutil
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'root';root.mkdir()
            shutil.copyfile(self.root/'firmware.squashfs',root/'nested.squashfs')
            image=Path(tmp)/'nested.squashfs'
            subprocess.run(['mksquashfs',str(root),str(image),'-noappend','-processors','1','-no-xattrs'],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            r=scan(image,'firmware',Options(max_depth=1))
            self.assertEqual(r['scan_status'],'partial')
            self.assertEqual(r['components'][0]['errors'][0]['code'],'max_depth')
            r=scan(image,'firmware')
            self.assertEqual(r['scan_status'],'completed')
            child=r['components'][0]['components'][0]
            self.assertEqual(child['artifact']['firmware_sha256'],r['artifact']['sha256'])
            self.assertEqual(len(child['extraction_chain']),2)

class ProcessTests(unittest.TestCase):
    def test_timeout_stops_extractor_process(self):
        from qcs.process import bounded_run
        r=bounded_run([sys.executable,'-c','import time; time.sleep(5)'],timeout=.1)
        self.assertEqual(r['limit'],'timeout')
        self.assertLess(r['duration_seconds'],2)

if __name__=='__main__': unittest.main()
