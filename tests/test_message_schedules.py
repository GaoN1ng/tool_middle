"""Ring recurrence and projective protocol relations with semantic mutations."""
import unittest
from qcs.guomi.source_semantics import Analysis
from qcs.operation_bignum import ConventionalEquations
from qcs.static_primitives import source_equations

RING='''unsigned r(unsigned x,unsigned n){return (x<<n)|(x>>(32-n));}
void ordinary(unsigned *w,unsigned end){unsigned i;for(i=16;i<end;i++){
unsigned a=w[(i-15)&15],b=w[(i-2)&15];
w[i&15]=w[(i-16)&15]+w[(i-7)&15]+(r(a,25)^r(a,14)^(a>>3))+(r(b,15)^r(b,13)^(b>>10));}}
'''

class MessageScheduleTests(unittest.TestCase):
 def test_sha256_ring_read_write_recurrence_and_mutations(self):
  for raw,want in [(RING,True),(RING.replace('(i-7)&15','(i-8)&15'),False),
                   (RING.replace('a>>3','a>>4'),False),
                   (RING.replace('w[i&15]=','w[(i+1)&15]='),False)]:
   a=Analysis(raw.encode(),False);a.run();events=[e for e in a.events if e[1]=='sha256_schedule'];self.assertEqual(bool(events),want)
 def test_sha1_and_sm3_exact_ring_equations(self):
  prefix='unsigned r(unsigned x,unsigned n){return (x<<n)|(x>>(32-n));}\nvoid ordinary(unsigned *w,unsigned n){for(unsigned i=16;i<n;i++)'
  cases=[('w[i&15]=r(w[(i-3)&15]^w[(i-8)&15]^w[(i-14)&15]^w[(i-16)&15],1);','sha1_bound_schedule'),
         ('{unsigned a=w[(i-16)&15]^w[(i-9)&15]^r(w[(i-3)&15],15);w[i&15]=a^r(a,15)^r(a,23)^r(w[(i-13)&15],7)^w[(i-6)&15];}','sm3_bound_schedule')]
  for raw,role in cases:
   a=Analysis((prefix+raw+'}').encode(),False);a.run();self.assertTrue(any(e[1]==role for e in a.events),a.events)
   a=Analysis((prefix+raw.replace('(i-16)&15','(i-15)&15')+'}').encode(),False);a.run();self.assertFalse(any(e[1]==role for e in a.events))
 def test_projective_ecdh_requires_peer_normalization_and_x_output(self):
  calls=[('prj_pt_import_from_aff_buf',['q','input','length','curve']),('prj_pt_mul',['q','d','q']),
         ('prj_pt_unique',['q','q']),('fp_export_to_buf',['out','length','q.X'])]
  for skipped in [None,0,1,2]:
   eq=ConventionalEquations()
   for site,(name,args) in enumerate(calls):
    if site!=skipped:eq.feed(name,args,site)
   self.assertEqual({m['algorithm'] for m in eq.general_matches},{'ECDH'} if skipped is None else set())
  eq=ConventionalEquations()
  for site,(name,args) in enumerate(calls):eq.feed(name,[a.replace('q.X','q.Y') for a in args],site)
  self.assertFalse(eq.general_matches)
 def test_unsigned_power_summary_declines_preloop_mutation(self):
  power='unsigned f(unsigned b,unsigned e,unsigned m){unsigned r=1;b=0;while(e){if(e&1)r=(r*b)%m;b=(b*b)%m;e>>=1;}return r;}'
  a=Analysis(power.encode(),False);result,summaries,_=source_equations(a);self.assertFalse(summaries)

if __name__=='__main__':unittest.main()
