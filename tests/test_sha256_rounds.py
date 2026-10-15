"""SHA-256 complete round equations and close non-equivalent controls."""
from pathlib import Path
import tempfile
import unittest

from qcs.guomi.source_semantics import scan_source_semantics
from qcs.guomi.source_semantics import Analysis, walk
from qcs.model import new_report, predictions
from qcs.operation_tables import SHA256_K, SHA256_IV
from qcs.guomi.binary_semantics import Lift, decode, disassembler
from qcs.operations import Arithmetic
from qcs.guomi.linear import leaf


class SHA256RoundTests(unittest.TestCase):
    def source(self, choice, majority, change=None):
        code = '#include <stdint.h>\n#define R(x,n) (((x)>>(n))|((x)<<(32-(n))))\n'
        code += 'static const uint32_t k[64]={' + ','.join(map(str, SHA256_K)) + '};\n'
        code += 'void init(uint32_t*s){' + ''.join('s[%d]=%du;' % (i,x) for i,x in enumerate(SHA256_IV)) + '}\n'
        code += '''void f(uint32_t*s,const uint32_t*w){
uint32_t a=s[0],b=s[1],c=s[2],d=s[3],e=s[4],g=s[6],h=s[7],v=s[5];
for(unsigned j=0;j<64;j++){
uint32_t t1=h+(R(e,6)^R(e,11)^R(e,25))+(''' + choice + ''')+k[j]+w[j];
uint32_t t2=(R(a,2)^R(a,13)^R(a,22))+(''' + majority + ''');
h=g;g=v;v=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
}s[0]+=a;s[4]+=e;}
'''
        if change:code=change(code)
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'ordinary.c';p.write_text(code)
            r=new_report(p,'source');scan_source_semantics(p,r)
            self.assertFalse(r['errors'])
            return predictions(r,'implementation_contains'),r

    def test_complete_round_without_local_message_expansion(self):
        for choice in ('(e&v)^(~e&g)', '(e&v)|(~e&g)', 'g^(e&(v^g))'):
            for majority in ('(a&b)^(a&c)^(b&c)', '(a&b)|(a&c)|(b&c)', '(a&b)^(c&(a^b))'):
                found,r=self.source(choice,majority)
                self.assertIn('SHA-256',found,(choice,majority,r.get('operation_diagnostics')))
                self.assertGreater(r['operation_diagnostics']['source']['event_counts'].get('sha256_round',0),0)

    def test_wrong_input_maps_and_variant_stay_negative(self):
        good_ch='(e&v)^(~e&g)';good_maj='(a&b)^(a&c)^(b&c)'
        cases=[('(a&v)^(~a&g)',good_maj,None),
               (good_ch,'(a&b)^(a&c)^(b&g)',None),
               (good_ch,good_maj,lambda s:s.replace('R(a,13)','R(a,12)')),
               (good_ch,good_maj,lambda s:s.replace('a=t1+t2','a=t1')),
               (good_ch,good_maj,lambda s:s.replace(str(SHA256_IV[0])+'u',str(SHA256_IV[0]^1)+'u'))]
        for ch,maj,change in cases:
            found,_=self.source(ch,maj,change)
            self.assertNotIn('SHA-256',found)

    def test_identity_masks_do_not_replace_boolean_producers(self):
        arithmetic=Arithmetic();x=leaf((1,()));y=leaf((2,()));out=leaf((3,()))
        arithmetic.rounds.remember('and',[x,y],out)
        expected=arithmetic.rounds.polynomial(out)
        arithmetic.rounds.remember('and',[out,('constant',0xffffffff)],out)
        self.assertEqual(arithmetic.rounds.polynomial(out),expected)

    def test_all_ones_xor_is_boolean_complement_in_source_and_binary(self):
        good_maj='(a&b)^(a&c)^(b&c)'
        for mask,want in (('0xffffffffu',True),('0xfffffffeu',False)):
            found,_=self.source('(e&v)^((e^'+mask+')&g)',good_maj)
            self.assertEqual('SHA-256' in found,want,mask)
        x=leaf((1000,()))
        for raw,want in ((bytes.fromhex('83f0ff'),True),(bytes.fromhex('83f0fe'),False)):
            lift=Lift('x86_64',[],[(0x1000,0,raw,1)]);lift.regs['rax']=x
            for ins in decode(disassembler('x86_64'),raw,0x1000):lift.step(ins)
            poly=lift.arithmetic.rounds.polynomial(lift.regs['rax'])
            self.assertEqual(poly==frozenset({frozenset(),frozenset({(1000,())})}),want)

    def test_macro_arguments_do_not_cascade_and_typedef_casts_are_real(self):
        for template in ('#define F(a,b) ((a)^(b))',
                         '#define X_x(a,b) ((a)^(b))\n#define F(a,b) X_##x(a,b)'):
            a=Analysis((template+'\nunsigned ordinary(unsigned b,unsigned c){return F(b,c);}').encode(),False)
            a.root='ordinary'
            call=next(n for n in walk(a.functions['ordinary'][1]) if n.type=='call_expression')
            self.assertEqual(a.expr(call,{'b':('constant',7),'c':('constant',3)}),('constant',4))
        for definition,want in [('typedef uint32_t word;',True),
                                ('typedef uint64_t word;',False),('',False)]:
            for body in ('#define R(x,n) ((((word)(x))>>(n))|(((word)(x))<<(32-(n))))',
                         '#define Q(x,n,T) ((((T)(x))>>(n))|(((T)(x))<<(32-(n))))\n#define R(x,n) Q(x,n,word)'):
                code=definition+'\n'+body+'\nunsigned f(unsigned e){return R(e,6);}'
                a=Analysis(code.encode(),False);a.run()
                self.assertEqual(any(r=='rotate' for _,r,_,_ in a.events),want)

    def test_algorithm_like_macro_names_do_not_supply_missing_operations(self):
        ch='(e&v)^(~e&g)';maj='(a&b)^(a&c)^(b&c)'
        def broken(code):
            code=code.replace(ch,'CH(e,v,g)').replace(maj,'MAJ(a,b,c)')
            return '#define CH(x,y,z) ((x)+(y)+(z))\n#define MAJ(x,y,z) ((x)^(y)^(z))\n'+code
        found,_=self.source(ch,maj,broken)
        self.assertNotIn('SHA-256',found)

    def test_aarch64_halfword_constant_initialization(self):
        # mov w8,#0xe667; movk w8,#0x6a09,lsl#16; str w8,[x0]
        raw=bytes.fromhex('e8cc9c522841ad72080000b9')
        lift=Lift('aarch64',[],[(0x1000,0,raw,1)])
        for ins in decode(disassembler('aarch64'),raw,0x1000):lift.step(ins)
        self.assertIn((0x1008,'iv_store',SHA256_IV[0]),lift.events)
        # A different upper half is a different constant, not a SHA IV.
        changed=raw[:4]+bytes.fromhex('4841ad72')+raw[8:]
        lift=Lift('aarch64',[],[(0x1000,0,changed,1)])
        for ins in decode(disassembler('aarch64'),changed,0x1000):lift.step(ins)
        self.assertFalse(any(r=='iv_store' for _,r,_ in lift.events))


if __name__=='__main__':unittest.main()
