"""Real development witnesses, altered equations and conservative CFG joins."""
import tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
from qcs.model import new_report,predictions
from support import WORKSPACE
from qcs.guomi.binary_semantics import Lift,decode,disassembler,scan_binary_semantics
from qcs.guomi.source_semantics import Analysis,scan_source_semantics
from qcs.controlflow import analyze,intersect,snapshot
from qcs.static_primitives import source_equations

POWER='''unsigned long f(unsigned long b,unsigned long e,unsigned long m){unsigned long r=1;
while(e){if(e&1)r=(r*b)%m;b=(b*b)%m;e>>=1;}return r;}
unsigned long g(unsigned long c,unsigned long dp,unsigned long dq,unsigned long p,unsigned long q,unsigned long qi){
unsigned long a=f(c,dp,p);unsigned long b=f(c,dq,q);unsigned long h=((a-b)*qi)%p;unsigned long o=b+q*h;return o;}
'''


class ControlflowPrimitivesTests(unittest.TestCase):
    def test_cfg_o0_rc4_positive_and_mutations(self):
        base=WORKSPACE/'samples/operation-development-20261013/builds'
        for name,want in [('stream',{'RC4'}),('missing-swap',set()),('wrong-index',set()),('swap-only',set())]:
            p=base/('control-'+name+'-x86_64-O0')/'ordinary.so';r=new_report(p,'executable')
            scan_binary_semantics(p,r,30)
            self.assertFalse(r['errors']);self.assertEqual(predictions(r,'implementation_contains'),want)
            self.assertTrue(r['controlflow_analysis'])

    def test_join_discards_conflicting_values_and_loops_terminate(self):
        lift=Lift('x86_64',[],[]);a=snapshot(lift);b=snapshot(lift)
        a['regs']['rax']=('constant',1);b['regs']['rax']=('constant',2)
        a['memory'][('frame',-8)]=('constant',3);b['memory'][('frame',-8)]=('constant',3)
        joined=intersect(a,b);self.assertNotIn('rax',joined['regs']);self.assertEqual(joined['memory'][('frame',-8)],('constant',3))
        raw=bytes.fromhex('b801000000ffc085c075fac3')
        records=analyze(Lift('x86_64',[],[(4096,0,raw,1)]),list(decode(disassembler('x86_64'),raw,4096)),time.monotonic()+10)
        self.assertLess(records['steps'],100);self.assertGreater(records['loop_edges'],0)

    def test_static_power_and_crt_require_every_recurrence(self):
        for code,want in [(POWER,{'RSA'}),(POWER.replace('r=(r*b)%m','r=(r+b)%m'),set()),
                          (POWER.replace('f(c,dq,q)','f(qi,dq,q)'),set()),
                          (POWER.replace('o=b+q*h','o=b-q*h'),set()),
                          (POWER.replace('e>>=1','e>>=2'),set())]:
            result=source_equations(Analysis(code.encode(),False))[0]
            self.assertEqual({m[0] for m in result},want)

    def test_function_budget_retains_later_functions(self):
        raw='unsigned heavy(unsigned x){'+''.join('x=x+1;' for _ in range(80))+'return x;}\n'+POWER
        a=Analysis(raw.encode(),False)
        with patch('qcs.guomi.source_semantics.MAX_NODES',150):a.run()
        self.assertIn('heavy',a.function_limits);self.assertIn('g',a.function_visits)
        self.assertLess(a.function_visits['g'],150)

    def test_sm4_intrinsics_require_both_families_and_no_shadowing(self):
        code='typedef unsigned vec; vec ordinary(vec x,vec k){k=vsm4ekeyq_u32(k,x);return vsm4eq_u32(x,k);}'
        def scan(raw):
            with tempfile.TemporaryDirectory() as folder:
                p=Path(folder)/'ordinary.c';p.write_text(raw);r=new_report(p,'source');scan_source_semantics(p,r)
                return predictions(r,'implementation_contains')
        self.assertIn('SM4',scan(code))
        self.assertNotIn('SM4',scan(code.replace('k=vsm4ekeyq_u32(k,x);','')))
        self.assertNotIn('SM4',scan('unsigned vsm4eq_u32(unsigned a,unsigned b){return a+b;}'+code))

    def test_real_static_math_and_mutated_equations(self):
        base=WORKSPACE/'samples/controlflow-development-20261014/builds'
        from qcs.guomi.binary_bignum import binary_equations
        from qcs.function_signatures import function_regions
        for name,want in [('sm2',{'SM2'}),('rsa',{'RSA'}),('sm2-wrong-denominator',set()),
                          ('sm2-wrong-product',set()),('rsa-wrong-base',set()),('rsa-wrong-recombination',set())]:
            p=base/('static-controls-'+name+'-x86_64-O2')/'ordinary.so';regions,_=function_regions(p)
            result=binary_equations(p,regions,'x86_64',time.monotonic()+60)
            self.assertEqual({m.get('algorithm','SM2') for m in result},want)


if __name__=='__main__':unittest.main()
