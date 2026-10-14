"""Standard equations, mutation negatives and real development regressions."""
import unittest
from pathlib import Path
from qcs.guomi.linear import leaf,rotate,shift,xor,roles
from qcs.guomi.source_semantics import Analysis
from qcs.operation_bignum import ConventionalEquations
from qcs.operation_tables import numeric_tables
from support import WORKSPACE
from qcs.model import new_report,predictions
from qcs.guomi.binary_semantics import scan_binary_semantics
from qcs.source import lex_cpp

DEV=WORKSPACE/'samples/operation-development-20261013'

def source(raw):
 a=Analysis(lex_cpp(raw)[0].encode(),False);a.run();a.findings();return {x[0] for x in a.general_findings()}

class OperationsTests(unittest.TestCase):
 def test_sigma_has_exact_logical_shift(self):
  x=leaf((1,()));y=leaf((2,()))
  good=xor(xor(rotate(x,-7),rotate(x,-18)),shift(x,'right',3))
  self.assertIn('sha256_small0',roles(good))
  self.assertNotIn('sha256_small0',roles(xor(xor(rotate(x,-7),rotate(x,-18)),shift(y,'right',3))))
  self.assertNotIn('sha256_small0',roles(xor(xor(rotate(x,-7),rotate(x,-18)),rotate(x,-3))))
  self.assertNotIn('sha256_small0',roles(xor(good,rotate(x,-1))))

 def test_quarter_round_requires_all_dependencies(self):
  text=(DEV/'sources/controls/quarter.c').read_text()
  self.assertEqual(source(text),{'ChaCha20'})
  self.assertFalse(source(text.replace('R(b,7)','R(b,6)')))
  self.assertFalse(source(text.replace('c+=d;b^=c;b=R(b,7)','c+=d;b^=a;b=R(b,7)')))
  self.assertFalse(source(text.replace('uint32_t','uint64_t')))

 def test_rc4_requires_recurrence_swap_and_output(self):
  text=(DEV/'sources/controls/stream.c').read_text()
  self.assertEqual(source(text),{'RC4'})
  for name in ('swap-only','wrong-index','missing-swap'):
   with self.subTest(name=name):self.assertFalse(source((DEV/'sources/controls'/(name+'.c')).read_text()))

 def test_macro_round_definitions_are_lexical(self):
  p=WORKSPACE/'third_party/mbedtls/library/sha1.c'
  self.assertIn('SHA-1',source(p.read_text()))
  # Shared-IV HAS-160 and RIPEMD round constants cannot supply SHA-1's
  # schedule relation; similarly an inert S box is never a DES operation.
  data=next(values for kind,values in numeric_tables() if kind=='des_sp')
  text='const unsigned t[64]={'+','.join(map(str,data))+'};unsigned f(unsigned x){return x^0x5a827999;}'
  self.assertFalse(source(text))

 def test_neutral_binary_and_mutations(self):
  for name,expected in [('quarter',{'ChaCha20'}),('stream',{'RC4'}),('wrong-rotate',set()),('disconnected-arx',set()),('swap-only',set()),('wrong-index',set()),('missing-swap',set())]:
   p=DEV/'builds'/('control-'+name+'-x86_64-O2')/'ordinary.so'
   with self.subTest(name=name):
    r=new_report(p,'executable');scan_binary_semantics(p,r,30)
    self.assertFalse(r['errors']);self.assertEqual(predictions(r,'implementation_contains'),expected)

 def test_ecdsa_equation_requires_nonce_point_coordinate_and_order(self):
  calls=[('EC_POINT_mul',['g','P','k','NULL','NULL','ctx']),
   ('EC_POINT_get_affine_coordinates',['g','P','x','y','ctx']),
   ('BN_nnmod',['r','x','n','ctx']),('BN_mod_mul',['u','r','d','n','ctx']),
   ('BN_mod_add',['u','e','u','n','ctx']),('BN_mod_inverse',['den','k','n','ctx']),
   ('BN_mod_mul',['s','u','den','n','ctx'])]
  def eq(cs,shadowed=()):
   e=ConventionalEquations(shadowed)
   for i,(n,a) in enumerate(cs):e.feed(n,a,10*i+1)
   return e
  self.assertTrue(eq(calls).general_matches)
  self.assertFalse(eq(calls[2:]).general_matches)
  for index,position,replacement in [(1,1,'other_point'),(5,1,'other_nonce'),(6,3,'other_order')]:
   bad=[(n,list(a)) for n,a in calls];bad[index][1][position]=replacement
   self.assertFalse(eq(bad).general_matches)
  self.assertFalse(eq(calls,['BN_mod_inverse']).general_matches)

 def test_rsa_crt_requires_shared_base_reduction_and_recombination(self):
  calls=[('BN_mod_exp',['a','c','dp','p','ctx']),('BN_mod_exp',['b','c','dq','q','ctx']),
   ('BN_sub',['h','a','b']),('BN_mul',['h','h','coefficient','ctx']),
   ('BN_nnmod',['h','h','p','ctx']),('BN_mul',['u','h','q','ctx']),('BN_add',['m','b','u'])]
  def matches(cs):
   e=ConventionalEquations()
   for i,(n,a) in enumerate(cs):e.feed(n,a,i+1)
   return {m['algorithm'] for m in e.general_matches}
  self.assertEqual(matches(calls),{'RSA'})
  self.assertFalse(matches(calls[:4]+calls[5:]))
  for index,position,replacement in [(1,1,'different_input'),(4,2,'q'),(5,2,'p')]:
   bad=[(n,list(a)) for n,a in calls];bad[index][1][position]=replacement
   self.assertFalse(matches(bad))

 def test_ecdh_requires_peer_point_and_related_coordinate_output(self):
  calls=[('mbedtls_ecp_mul_restartable',['g','P','d','peer','rng','state','restart']),
   ('mbedtls_mpi_copy',['out','P.X'])]
  def matches(cs):
   e=ConventionalEquations()
   for i,(n,a) in enumerate(cs):e.feed(n,a,i+1)
   return {m['algorithm'] for m in e.general_matches}
  self.assertEqual(matches(calls),{'ECDH'})
  self.assertFalse(matches([calls[0],('mbedtls_mpi_copy',['out','other.X'])]))
  self.assertFalse(matches([('mbedtls_ecp_mul_restartable',['g','P','d','g->G']),calls[1]]))

 def test_shared_sha1_constants_remain_clues_without_operations(self):
  from qcs.operations import reconcile_shared_sha1
  from qcs.model import evidence
  r=new_report(Path('ordinary.so'),'executable')
  r['findings']=[evidence('SHA-1','yara','binary_constant','SHA1_Constants')]
  reconcile_shared_sha1(r)
  self.assertFalse(predictions(r,'implementation_contains'));self.assertEqual(len(r['clues']),1)
  r['findings']=[evidence('SHA-1','yara','binary_constant','SHA1_Constants'),
   evidence('SHA-1','operation_binary','binary_instruction','standard_operation_graph')]
  reconcile_shared_sha1(r);self.assertEqual(len(r['findings']),2)

if __name__=='__main__':unittest.main()
