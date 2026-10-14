"""Semantic guards and header context: positives plus invalid relations."""
import tempfile
import unittest
from pathlib import Path
from qcs.guomi.binary_semantics import Lift,decode,disassembler,scan_binary_semantics
from qcs.guomi.source_semantics import scan_source_semantics
from qcs.model import new_report,predictions
from support import WORKSPACE
from qcs.guomi.linear import canonical,bits,leaf,rotate,shift,merge_shifts,xor,roles,truncate,role_tags

DEV=WORKSPACE/'samples/operation-development-20261013'

class ResearchOperationsTests(unittest.TestCase):
    def test_reference_requires_ecdh_operation_body_not_forwarder(self):
        from qcs.function_signatures import scan_functions
        for name,expected in [('ecdh',{'ECDH'}),('ecdsa',{'ECDSA'})]:
            p=DEV/'builds'/('mbedtls-'+name+'-arm-O0')/'ordinary.so'
            report=new_report(p,'executable');scan_functions(p,report,30)
            self.assertFalse(report['errors'])
            self.assertEqual(predictions(report,'implementation_contains'),expected)
    def test_role_tags_bind_only_the_matching_input(self):
        x=leaf((1,()));unrelated=leaf((2,('add','sbox')))
        p0=xor(xor(x,rotate(x,9)),rotate(x,17))
        value=xor(p0,unrelated)
        self.assertIn('sm3_p0',roles(value))
        self.assertEqual(role_tags(value,'sm3_p0'),())
        used=leaf((3,('add',)))
        self.assertEqual(role_tags(xor(xor(used,rotate(used,9)),rotate(used,17)),'sm3_p0'),('add',))

    def test_different_inputs_real_arm_negatives(self):
        for opt in ('O2','Os'):
            p=WORKSPACE/'samples/guomi-development-20261012/builds/controls/different-input-rotations/arm'/opt/'sample.so'
            report=new_report(p,'executable');scan_binary_semantics(p,report,30)
            self.assertFalse(report['errors']);self.assertFalse(predictions(report,'implementation_contains'))

    def test_full_width_bit_equivalence_and_partial_negatives(self):
        x=leaf((1,()));y=leaf((2,()))
        split=merge_shifts(shift(('bits',bits(x)),'left',7),shift(('bits',bits(x)),'right',25))
        self.assertEqual(split,rotate(x,7))
        self.assertEqual(canonical(('bits',bits(xor(rotate(x,9),y)))),xor(rotate(x,9),y))
        self.assertEqual(canonical(truncate(x,8))[0],'bits')
        words=[leaf((i,())) for i in range(10,14)]
        schedule=rotate(xor(xor(words[0],words[1]),xor(words[2],words[3])),1)
        self.assertIn('sha1_schedule',roles(('bits',bits(schedule))))
        bad=list(bits(schedule));bad[31]=frozenset()
        self.assertNotIn('sha1_schedule',roles(('bits',tuple(bad))))
    def guard(self,raw):
        base=0x1000
        raw+=b'\x90'*32
        lift=Lift('x86_64',[],[(base,0,raw,1)])
        ins=next(decode(disassembler('x86_64'),raw,base))
        return lift.guard_successor(ins)

    def test_guard_requires_terminal_trap_without_side_effects(self):
        self.assertEqual(self.guard(bytes.fromhex('75020f0b89c0909090')),0x1004)
        # A write before the trap cannot be ignored or merged into success.
        self.assertIsNone(self.guard(bytes.fromhex('750689070f0b9090909090')))
        self.assertIsNone(self.guard(bytes.fromhex('750290909090909090')))
        self.assertIsNone(self.guard(bytes.fromhex('7502ffd0909090909090')))

    def test_real_compiler_guard_and_arm_forms(self):
        for arch,opt in [('x86_64','O0'),('aarch64','O0'),('arm','O2'),('thumb','O2'),('thumb','O0')]:
            for name,want in [('quarter',{'ChaCha20'}),('wrong-rotate',set()),('disconnected-arx',set())]:
                p=DEV/'builds'/('control-'+name+'-'+arch+'-'+opt)/'ordinary.so'
                with self.subTest(arch=arch,name=name):
                    self.assertTrue(p.exists())
                    report=new_report(p,'executable');scan_binary_semantics(p,report,30)
                    self.assertFalse(report['errors'])
                    self.assertEqual(predictions(report,'implementation_contains'),want)

    def scan_context(self,header,body):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);(base/'local.h').write_text(header)
            p=base/'ordinary.c';p.write_text('#include "local.h"\n'+body)
            report=new_report(p,'source');scan_source_semantics(p,report)
            self.assertFalse(report['errors'])
            return predictions(report,'implementation_contains'),report

    def test_header_scalar_helper_actual_equation(self):
        raw=(DEV/'sources/controls/quarter.c').read_text()
        body=raw.replace('#define R(x,n) (((x)<<(n))|((x)>>(32-(n))))','')
        header='static unsigned R(unsigned x,int n){return (x<<n)|(x>>((-n)&31));}\n'
        detected,report=self.scan_context(header,body)
        self.assertEqual(detected,{'ChaCha20'})
        self.assertEqual(len(report['source_operation_context']['files']),1)
        bad=header.replace('((-n)&31)','((-(n+1))&31)')
        self.assertFalse(self.scan_context(bad,body)[0])

    def test_header_only_unused_algorithm_is_not_inherited(self):
        raw=(DEV/'sources/controls/quarter.c').read_text()
        self.assertFalse(self.scan_context(raw,'unsigned f(unsigned x){return x+1;}')[0])
        # A disabled include must not supply a missing helper.
        body=raw.replace('#define R(x,n) (((x)<<(n))|((x)>>(32-(n))))','')
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);(base/'local.h').write_text('static unsigned R(unsigned x,int n){return (x<<n)|(x>>(32-n));}')
            p=base/'ordinary.c';p.write_text('#if 0\n#include "local.h"\n#endif\n'+body)
            report=new_report(p,'source');scan_source_semantics(p,report)
            self.assertFalse(predictions(report,'implementation_contains'))

    def test_local_shadowing_and_builtin_width(self):
        raw=(DEV/'sources/controls/quarter.c').read_text()
        header='#define R(x,n) (((x)<<(n))|((x)>>(32-(n))))\n'
        body=raw.replace('#define R(x,n) (((x)<<(n))|((x)>>(32-(n))))','#define R(x,n) ((x)^(n))')
        self.assertFalse(self.scan_context(header,body)[0])
        builtin=raw.replace('(((x)<<(n))|((x)>>(32-(n))))','__builtin_rotateleft32(x,n)')
        self.assertEqual(self.scan_context('',builtin)[0],{'ChaCha20'})
        self.assertFalse(self.scan_context('',builtin.replace('uint32_t','uint64_t'))[0])

if __name__=='__main__':unittest.main()
