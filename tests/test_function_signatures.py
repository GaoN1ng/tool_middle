from support import WORKSPACE
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from qcs.model import predictions
from qcs.scanner import scan


class FunctionSignatureTests(unittest.TestCase):
    root = WORKSPACE/'samples/stripped-repair'
    public = WORKSPACE/'samples/public-benchmark/binaries/rebuilt-tinycrypt'

    def test_real_hidden_asymmetric_and_sha_across_architectures(self):
        for arch, target in [('x86_64','x86_64-linux-musl'), ('aarch64','aarch64-linux-musl'), ('arm','arm-linux-musleabihf')]:
            for name, expected in [('rsa', {'RSA'}), ('ecdh', {'ECDH'}), ('ecdsa', {'ECDSA','SHA-256'}), ('sha256', {'SHA-256'}), ('micro-ecc', {'ECDH','ECDSA'})]:
                with self.subTest(arch=arch, name=name):
                    r = scan(self.root/'binaries'/arch/(name+'-O2.so'), 'executable')
                    self.assertEqual(r['scan_status'], 'completed')
                    self.assertEqual(predictions(r,'implementation_contains'), expected)
                    self.assertNotIn('.symtab', r['artifact']['symbol_tables'])
                    self.assertTrue(any(x['engine']=='function_signature' for x in r['findings']))
                    self.assertFalse(predictions(r,'api_reference') & {'RSA','ECDSA','ECDH','SHA-256'})
            r = scan(self.public/target/'ecdsa-stripped.so', 'executable')
            self.assertEqual(predictions(r,'implementation_contains'), {'ECDSA','SHA-256'})

    def test_sha224_blake2_inert_tables_and_generic_math_negatives(self):
        for arch in ['x86_64','aarch64','arm']:
            for name in ['sha224-only','tiny-sha224-decoy','blake2s','generic-ec','generic-bignum','inert-constants','code-as-data']:
                with self.subTest(arch=arch, name=name):
                    r = scan(self.root/'binaries'/arch/(name+'-O2.so'), 'executable')
                    self.assertEqual(r['scan_status'],'completed')
                    self.assertEqual(predictions(r,'implementation_contains'),set())

    def test_referenced_iv_change_does_not_become_sha256(self):
        for target in ['x86_64-linux-musl','aarch64-linux-musl']:
            original = self.public/target/'sha256-stripped.so'
            data = original.read_bytes()
            iv = bytes.fromhex('67e6096a85ae67bb72f36e3c3af54fa5')
            self.assertIn(iv,data)
            with tempfile.TemporaryDirectory() as tmp:
                changed = Path(tmp)/'image.so'
                changed.write_bytes(data.replace(iv, bytes.fromhex('d89e05c107d57c3617dd703039590ef7')))
                r = scan(changed,'executable')
                self.assertNotIn('SHA-256',predictions(r,'implementation_contains'))
                self.assertTrue(any(x['engine']=='function_signature' and not x['algorithm'] for x in r['clues']))

    def test_whole_function_computation_change_breaks_witness(self):
        original = self.root/'binaries/x86_64/sha256-O2.so'
        r = scan(original,'executable')
        f = next(x for x in r['findings'] if x['engine']=='function_signature')
        initializer = next(x for x in f['matched_functions'] if x['role']=='initialization')
        with tempfile.TemporaryDirectory() as tmp:
            changed = Path(tmp)/'changed.so'
            data = bytearray(original.read_bytes())
            # Alter the real initializer's null-check instruction, outside any
            # relocation. This keeps the ELF valid but changes whole code.
            data[initializer['offset']] ^= 1
            changed.write_bytes(data)
            r = scan(changed,'executable')
            self.assertFalse(any(x['engine']=='function_signature' and x['algorithm']=='SHA-256' for x in r['findings']))
            # The null check is outside the digest computation. A recovered
            # standard operation witness may still recognize the algorithm.
            for x in r['findings']:
                if x['algorithm']=='SHA-256':
                    self.assertEqual(x['engine'],'operation_binary')
                    self.assertTrue(x['operation_witnesses'])

    def test_name_and_path_do_not_drive_matching(self):
        original = self.root/'binaries/aarch64/ecdh-O2.so'
        with tempfile.TemporaryDirectory() as tmp:
            renamed = Path(tmp)/'ordinary-temperature-reader'
            shutil.copyfile(original,renamed)
            r = scan(renamed)
            self.assertIn('ECDH',predictions(r,'implementation_contains'))
            self.assertTrue(all(x['runtime_usage']=='unknown' for x in r['findings']))

    def test_missing_database_marks_partial_instead_of_empty_success(self):
        with patch('qcs.function_signatures.DATABASE',Path('/nonexistent-qcs-signature-database.json')):
            r = scan(self.root/'binaries/x86_64/rsa-O2.so','executable')
        self.assertEqual(r['scan_status'],'partial')
        self.assertTrue(any(x['engine']=='function_signature' for x in r['errors']))

    def test_real_pe_and_unsupported_architectures_keep_existing_channels(self):
        import sys
        sys.path.insert(0,str(WORKSPACE/'quantum-crypto-scanner/tools'))
        from pe_fixture import named_import_pe
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'imports.exe'
            p.write_bytes(named_import_pe())
            r=scan(p,'executable')
            self.assertEqual(r['scan_status'],'completed')
            self.assertEqual(r['engine_status']['function_signature']['status'],'completed')
            self.assertEqual(predictions(r,'api_reference'),{'RSA','ECDSA','ECDH'})
        r=scan(WORKSPACE/'quantum-crypto-scanner/fixtures/binary/aes-ppc-be.o','executable')
        self.assertEqual(r['engine_status']['function_signature']['status'],'disabled')
        self.assertIn('AES',predictions(r,'implementation_contains'))


if __name__=='__main__':unittest.main()
