"""Cross-file table/state binding and close non-equivalent source controls."""
import tempfile
import unittest
from pathlib import Path

from qcs.guomi.source_semantics import scan_source_semantics, Analysis
from qcs.guomi.binary_semantics import Lift, decode, disassembler
from qcs.copy_semantics import mips_copy
from qcs.model import new_report, predictions
from qcs.operation_tables import SHA256_K, SHA256_IV

ROOT = Path(__file__).resolve().parents[1]


class SourceLinkageTests(unittest.TestCase):
    def fixture(self, change=None):
        header = '#define DEF(T,N,P) T N P\n'
        header += 'static const unsigned values[64]={' + ','.join(map(str, SHA256_K)) + '};\n'
        header += 'static const unsigned initial[8]={' + ','.join(map(str, SHA256_IV)) + '};\n'
        header += '''void copy(unsigned*d,const unsigned*s){
d[0]=s[0];d[1]=s[1];d[2]=s[2];d[3]=s[3];d[4]=s[4];d[5]=s[5];d[6]=s[6];d[7]=s[7];}
void begin(unsigned*s){copy(s,initial);}
void update(unsigned*s,unsigned*w){compress(s,w,values);}
'''
        caller = 'void owner(void){method.first=begin;method.second=update;}'
        code = '''#include "defs.h"
#define R(x,n) (((x)>>(n))|((x)<<(32-(n))))
DEF(void,compress,(unsigned*s,unsigned*w,const unsigned*k)){
unsigned a=s[0],b=s[1],c=s[2],d=s[3],e=s[4],f=s[5],g=s[6],h=s[7];
for(unsigned j=0;j<64;j++){
unsigned u=h+(R(e,6)^R(e,11)^R(e,25))+((e&f)^(~e&g))+w[j]+(k)[j];
unsigned v=(R(a,2)^R(a,13)^R(a,22))+((a&b)^(a&c)^(b&c));
h=g;g=f;f=e;e=d+u;d=c;c=b;b=a;a=u+v;}s[0]+=a;s[4]+=e;}
'''
        if change:
            header, caller, code = change(header, caller, code)
        with tempfile.TemporaryDirectory(dir=ROOT/'build/tmp') as folder:
            root = Path(folder); (root/'LICENSE').write_text('fixture')
            (root/'defs.h').write_text('#define DEF(T,N,P) T N P\n')
            (root/'parameters.h').write_text(header)
            (root/'owner.c').write_text(caller)
            path = root/'ordinary.c'; path.write_text(code)
            report = new_report(path, 'source'); scan_source_semantics(path, report)
            self.assertFalse(report['errors'])
            return predictions(report, 'implementation_contains'), report

    def test_real_reverse_call_and_same_descriptor_bind_initializer(self):
        found, report = self.fixture()
        self.assertIn('SHA-256', found)
        plans = report['source_parameter_linkage']['bindings']
        self.assertTrue(plans)
        self.assertTrue(plans[0]['descriptor_iv'])

    def test_missing_or_wrong_parameter_initializer_and_descriptor_decline(self):
        changes = [
            lambda h,c,s:(h,c.replace('method.second','other.second'),s),
            lambda h,c,s:(h.replace('s[7];','s[0];'),c,s),
            lambda h,c,s:(h.replace(str(SHA256_IV[0]),str(SHA256_IV[0]^1)),c,s),
            lambda h,c,s:(h.replace('compress(s,w,values)','compress(s,w,other)'),c,s),
            lambda h,c,s:(h.replace('compress(s,w,values)','compress(other,w,values)'),c,s),
            lambda h,c,s:(h,c,s.replace('j<64','j<65')),
        ]
        for change in changes:
            found,_ = self.fixture(change)
            self.assertNotIn('SHA-256', found)

    def test_declaration_export_variants_preserve_identifier_binding(self):
        header = b'''#define CC __cdecl
#define DEF(T,N,P) __declspec(dllexport) T CC N P
#define DEF(T,N,P) extern T CC N P
'''
        a = Analysis(b'DEF(const unsigned*,ordinary,(void)){return 0;}',False,
                     declaration_contexts=[header])
        self.assertIn('ordinary', a.functions)

    def test_static_copy_requires_every_matching_source_byte(self):
        # Renamed/static MIPS byte-copy loop; the return delay slot executes.
        raw = bytes.fromhex('1500c010000000000000a190ffffc22410004010000081a0f8ffbd270400bfaf0000beaf25f0a0030100a324010085240000619001006324ffff42240000a1a0fbff40140100a52425e8c0030400bf8f0000be8f0800bd270800e00325108000')
        for order in ('mipsel', 'mips_be'):
            data = raw if order=='mipsel' else b''.join(raw[i:i+4][::-1] for i in range(0,len(raw),4))
            instructions = list(decode(disassembler(order),data,0x1000))
            self.assertTrue(mips_copy(instructions,32))
            changed = data.replace(bytes.fromhex('0000a1a0') if order=='mipsel' else bytes.fromhex('a0a10000'),
                                   bytes.fromhex('0000a0a0') if order=='mipsel' else bytes.fromhex('a0a00000'))
            self.assertFalse(mips_copy(list(decode(disassembler(order),changed,0x1000)),32))

    def test_frame_pointer_spill_and_overwrite_use_actual_stack_offset(self):
        # Thumb push {r7,lr}; mov r7,sp; sub sp,#16; add r0,sp,#8;
        # str r0,[sp]; ldr r1,[sp]. An immediate overwrite kills the pointer.
        raw = bytes.fromhex('80b56f4684b002a800900099')
        lift = Lift('thumb',[],[(0x1000,0,raw,1)])
        instructions = list(decode(disassembler('thumb'),raw,0x1000))
        for ins in instructions:lift.step(ins)
        self.assertEqual(lift.stack_offsets['r1'],-16)
        self.assertEqual(lift.stack_offsets['sp'],-24)
        for ins in decode(disassembler('thumb'),bytes.fromhex('002000900099'),0x1010):lift.step(ins)
        self.assertNotIn('r1',lift.stack_offsets)


if __name__ == '__main__':
    unittest.main()
