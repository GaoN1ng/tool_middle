from support import WORKSPACE
import json
from pathlib import Path
import tempfile
import unittest

from qcs.function_signatures import function_regions
from qcs.guomi import SIGNATURE_PATH
from qcs.model import predictions
from qcs.scanner import Options, scan

BASE = WORKSPACE/'quantum-crypto-scanner/artifacts/guomi-sm2-fix-20261012'
ORIGINAL = WORKSPACE/'quantum-crypto-scanner/artifacts/guomi-integration-20261012/provided/elf'


class GuomiSM2PortabilityTests(unittest.TestCase):
    def changed_report(self, raw):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'ordinary-temperature-reader'
            path.write_bytes(raw)
            report=scan(path,options=Options(windriver=False))
            self.assertEqual(report['scan_status'],'completed',report['errors'])
            return report

    def witnesses(self, path):
        report=scan(path,options=Options(windriver=False))
        self.assertEqual(report['scan_status'],'completed',report['errors'])
        self.assertEqual(predictions(report,'implementation_contains'),{'SM2'})
        database=json.loads(SIGNATURE_PATH.read_text())
        signatures={s['id']:s for s in database['signatures']}
        return [(w,signatures[w['signature_id']]) for f in report['findings']
                if f['engine']=='guomi_function_signature' for w in f['matched_functions']]

    def test_two_original_stripped_sm2_regressions(self):
        for name in ['sm2_O0_stripped.elf','sm2_O2_stripped.elf']:
            with self.subTest(name=name):
                path=ORIGINAL/name
                self.assertTrue(self.witnesses(path))
                renamed=self.changed_report(path.read_bytes())
                self.assertEqual(predictions(renamed,'implementation_contains'),{'SM2'})
                self.assertFalse(renamed['artifact']['symbol_tables'])
                self.assertFalse(predictions(renamed,'api_reference'))

    def test_source_path_link_mode_and_optimization_variants(self):
        manifest=json.loads((BASE/'portability-manifest.json').read_text())
        self.assertEqual(len(manifest['samples']),25)
        for row in manifest['samples']:
            with self.subTest(path=row['path']):
                report=scan(WORKSPACE/row['path'],options=Options(windriver=False))
                self.assertEqual(report['scan_status'],'completed',report['errors'])
                # Generic SM2-curve arithmetic has no actual SM2 operation.
                self.assertEqual(predictions(report,'implementation_contains') & {'SM2','SM3','SM4'},
                                 set(row['expected']))
                self.assertNotIn('.symtab',report['artifact']['symbol_tables'])

    def test_diagnostic_path_format_and_function_name_data_do_not_identify_sm2(self):
        path=BASE/'portability/sm2_sign-shared-windows-O2/ordinary.elf'
        raw=path.read_bytes()
        self.assertIn(b'Z:/portable/reference-C',raw)
        for literal in [b'Z:/portable/reference-C',b'%s:%d:%s():\n',b'sm2_do_sign\0',b'sm2_do_verify\0']:
            self.assertIn(literal,raw)
            raw=raw.replace(literal,b'X'*len(literal))
        self.assertEqual(predictions(self.changed_report(raw),'implementation_contains'),{'SM2'})

    def test_stdio_pointer_initial_values_do_not_identify_sm2(self):
        path=BASE/'portability/sm2_sign-shared-windows-O2/ordinary.elf'
        witnesses=self.witnesses(path)
        regions,_=function_regions(path)
        raw=bytearray(path.read_bytes())
        modified=set()
        for witness,sig in witnesses:
            for variant in sig['linker_variants']:
                offset=witness['offset']+variant['displacement_offset']
                target=witness['address']+variant['next_instruction']+int.from_bytes(raw[offset:offset+4],'little',signed=True)
                region=next(r for r in regions if r[0]<=target and target+8<=r[0]+len(r[2]))
                file_offset=region[1]+target-region[0]
                raw[file_offset:file_offset+8]=b'\xa5'*8
                modified.add(file_offset)
        self.assertTrue(modified)
        self.assertEqual(predictions(self.changed_report(raw),'implementation_contains'),{'SM2'})

    def test_only_audited_mov_lea_pair_is_accepted(self):
        path=ORIGINAL/'sm2_O2_stripped.elf'
        witnesses=self.witnesses(path)
        self.assertGreaterEqual(len(witnesses),2)
        for opcode in [0x89,0x8f]:
            with self.subTest(opcode=opcode):
                raw=bytearray(path.read_bytes())
                for witness,sig in witnesses:
                    variant=sig['linker_variants'][0]
                    at=variant['opcode_offset']
                    mask=bytes.fromhex(sig['mask'])
                    # These bytes pass the nibble/bit mask, so rejecting them
                    # specifically exercises the audited alternative check.
                    self.assertEqual((raw[witness['offset']+at]^opcode)&mask[at],0)
                    raw[witness['offset']+at]=opcode
                self.assertNotIn('SM2',predictions(self.changed_report(raw),'implementation_contains'))

    def test_unmapped_stdio_reference_is_rejected(self):
        path=ORIGINAL/'sm2_O2_stripped.elf'
        raw=bytearray(path.read_bytes())
        for witness,sig in self.witnesses(path):
            variant=sig['linker_variants'][0]
            at=witness['offset']+variant['displacement_offset']
            raw[at:at+4]=(0x70000000).to_bytes(4,'little',signed=True)
        self.assertNotIn('SM2',predictions(self.changed_report(raw),'implementation_contains'))

    def test_changed_operation_code_is_rejected(self):
        path=ORIGINAL/'sm2_O2_stripped.elf'
        raw=bytearray(path.read_bytes())
        for witness,sig in self.witnesses(path):
            self.assertEqual(bytes.fromhex(sig['mask'])[0],0xff)
            raw[witness['offset']]^=1
        self.assertNotIn('SM2',predictions(self.changed_report(raw),'implementation_contains'))

    def test_ecdsa_generic_curve_and_bignum_are_not_sm2(self):
        root=WORKSPACE/'samples/stripped-repair/binaries'
        for arch in ['x86_64','aarch64','arm']:
            for name in ['ecdsa','generic-ec','generic-bignum','inert-constants','code-as-data']:
                with self.subTest(arch=arch,name=name):
                    report=scan(root/arch/(name+'-O2.so'),options=Options(windriver=False))
                    self.assertEqual(report['scan_status'],'completed',report['errors'])
                    self.assertNotIn('SM2',predictions(report,'implementation_contains'))

    def test_sm3_sm4_algorithm_data_constraints_are_preserved(self):
        before=json.loads((BASE/'before-function-signatures.json').read_text())
        current=json.loads(SIGNATURE_PATH.read_text())
        old={s['id']:s for s in before['signatures'] if s['algorithm'] in {'SM3','SM4'}}
        new={s['id']:s for s in current['signatures'] if s['algorithm'] in {'SM3','SM4'}}
        self.assertEqual(old,new)

    def test_preserved_constant_and_code_payloads_in_nonexecuting_data(self):
        from elftools.elf.elffile import ELFFile
        folder=BASE/'verification-final/controls'
        sbox=bytes.fromhex('d690e9fecce13db716b614c228fb2c05')
        for name in ['standard-constants-only','known-code-as-nonexec-data']:
            with self.subTest(name=name):
                path=folder/(name+'.so')
                with path.open('rb') as f:
                    elf=ELFFile(f)
                    data=[s.data() for s in elf.iter_sections() if s['sh_flags'] & 2
                          and not s['sh_flags'] & 4 and s['sh_type']!='SHT_NOBITS']
                    self.assertTrue(any(len(d)>64 for d in data),'Payload was discarded')
                    if name=='standard-constants-only':
                        self.assertTrue(any(sbox in d for d in data))
                    else:
                        ref=WORKSPACE/'quantum-crypto-scanner/artifacts/guomi-integration-20261012/references/x86_64/gmssl-sm2-sign-O2-small0/reference.so'
                        with ref.open('rb') as reference:
                            body=ELFFile(reference).get_section_by_name('.text').data()
                        self.assertTrue(any(body in d for d in data),'Whole code payload missing')
                report=scan(path,options=Options(windriver=False))
                self.assertEqual(report['scan_status'],'completed',report['errors'])
                self.assertFalse(predictions(report,'implementation_contains'))


if __name__=='__main__':
    unittest.main()
