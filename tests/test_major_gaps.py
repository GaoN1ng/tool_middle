"""Operation relation regressions for the high-miss development families."""
import time
import unittest
from pathlib import Path
from qcs.guomi.source_semantics import Analysis
from qcs.guomi.binary_semantics import decode,disassembler
from qcs.guomi.binary_bignum import PointerLift
from qcs.copy_semantics import arm_copy
from qcs.binary_decode import control_instructions

ROOT=Path(__file__).resolve().parents[1]

class MajorGapTests(unittest.TestCase):
    def test_verified_functions_skip_only_their_executable_byte_intervals(self):
        from qcs.analysis_regions import additional_regions
        regions=[(100,0,b'0123456789',1),(100,0,b'0123456789',0)]
        finding={'engine':'guomi_function_signature','algorithm':'SM3',
                 'matched_functions':[{'address':102,'length':4},{'address':104,'length':3}]}
        result,skipped=additional_regions(regions,{'findings':[finding]})
        self.assertEqual(skipped,5)
        self.assertEqual(result,[(100,0,b'01',1),(107,7,b'789',1),regions[1]])
        for changed in (dict(finding,engine='yara'),dict(finding,algorithm='AES')):
            self.assertEqual(additional_regions(regions,{'findings':[changed]}),(regions,0))

    def test_macro_array_swap_requires_both_feedback_indices_and_keystream(self):
        raw='''#define SWAP(a,b) tmp=(a);(a)=(b);(b)=tmp
void ordinary(unsigned char *state,unsigned char *data,int n,unsigned i,unsigned j){
unsigned tmp;for(int c=0;c<n;c++){i++;i&=255;j+=state[i];j&=255;
SWAP(state[i],state[j]);data[c]^=state[(state[i]+tmp)&255];}}'''
        for code,want in ((raw,True),(raw.replace('i++','i+=2'),False),
                          (raw.replace('j+=state[i]','j+=data[i]'),False),
                          (raw.replace('(b)=tmp','(b)=0'),False),
                          (raw.replace('state[(state[i]+tmp)&255]','state[i]'),False),
                          (raw.replace('SWAP(state[i],state[j]);','SWAP(state[i],state[j]);unknown(state);'),False)):
            a=Analysis(code.encode(),False);a.run();a.findings()
            self.assertEqual(any(m[0]=='RC4' for m in a.general_findings()),want,code)

    def test_macro_expansion_does_not_double_apply_post_increment(self):
        for expression,want in (('x++',3),('++x',4)):
            code='unsigned ordinary(){unsigned x=3;return '+expression+';}'
            a=Analysis(code.encode(),False);a.root='ordinary'
            value=a.statements(a.functions['ordinary'][1],{},0)
            self.assertEqual(value,('constant',want))

    def test_thumb_unwind_entry_recovers_start_hidden_by_literal_pool(self):
        # Literal-like 32-bit Thumb instruction at 0x1000 overlaps a real
        # independent function entry at 0x1002: movs r0,#1; bx lr.
        raw=bytes.fromhex('00f001207047')
        initial={i.address for i in decode(disassembler('thumb'),raw,0x1000)}
        self.assertNotIn(0x1002,initial)
        recovered={i.address:i for i in control_instructions(disassembler('thumb'),raw,0x1000,domain='thumb',entries=[0x1002])}
        self.assertEqual(recovered[0x1002].mnemonic,'movs')
        self.assertNotIn(0x2000,recovered)

    def test_arm_neon_copy_checks_every_byte_and_rejects_wrong_store(self):
        # vld1.8 {d16,d17},[r1]!; vst1.8 {d16,d17},[r0]!;
        # subs r2,r2,#16; bne start; bx lr.
        raw=bytes.fromhex('0d0a61f40d0a40f4102052e2fbffff1a1eff2fe1')
        for code,length,want in ((raw,32,True),(raw,31,False),
                                 (raw.replace(bytes.fromhex('0d0a40f4'),bytes.fromhex('0d0a41f4')),32,False),
                                 (raw[:-4],32,False)):
            self.assertEqual(arm_copy(list(decode(disassembler('arm'),code,0x1000)),length),want)

    def test_imported_copy_only_invalidates_its_destination(self):
        # call [rip+0x1000] uses relocation slot at 0x2006.
        ins=next(decode(disassembler('x86_64'),bytes.fromhex('ff1500100000'),0x1000))
        for destination,want in (('other',True),('encoded',False)):
            lift=PointerLift('x86_64',[],{0x2006:'memcpy'})
            lift.equations.exchange.serialized['encoded']=({},1)
            lift.regs.update(rdi=destination,rsi='input',rdx='32',rcx='encoded')
            lift.step(ins)
            self.assertEqual('encoded' in lift.equations.exchange.serialized,want)

    def test_uncompressed_point_export_is_read_only_except_output(self):
        from qcs.curve_exchange import Exchange
        for output,want in (('bytes',True),('P',False)):
            ex=Exchange();ex.points['P']={'peer':None}
            ex.feed('sm2_z256_point_to_uncompressed_octets',['P',output],1)
            self.assertEqual('P' in ex.points,want)

if __name__=='__main__':unittest.main()
