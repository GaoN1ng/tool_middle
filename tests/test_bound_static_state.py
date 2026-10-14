"""Bound static callee integrity and real-author source equations."""
import json,tempfile,time,unittest
from pathlib import Path
from support import WORKSPACE
from qcs.model import new_report,predictions
from qcs.guomi.source_semantics import Analysis,scan_source_semantics
from qcs.guomi.binary_bignum import binary_equations
from qcs.guomi.binary_semantics import decode,disassembler
from qcs.function_signatures import function_regions
from qcs.static_primitives import summaries

DEV=WORKSPACE/'samples/controlflow-development-20261014'

class BoundStaticStateTests(unittest.TestCase):
 def test_complete_static_ecdh_and_negative_relations(self):
  files=[('builds/static-ec-ecdh-x86_64-O2/ordinary.so',{'ECDH'}),
         ('builds/static-ec-wrong-coordinate-x86_64-O2/ordinary.so',set()),
         ('builds/static-ec-missing-affine-x86_64-O2/ordinary.so',set()),
         ('builds/static-ec-missing-multiply-x86_64-O2/ordinary.so',set()),
         ('ecc-primitive-builds/x86_64-O2/ordinary.so',set())]
  for file,want in files:
   p=DEV/file;regions,_=function_regions(p)
   result=binary_equations(p,regions,'x86_64',time.monotonic()+60)
   self.assertEqual({m.get('algorithm','SM2') for m in result},want)
 def test_replacing_a_masked_call_target_invalidates_static_primitive(self):
  from elftools.elf.elffile import ELFFile
  p=DEV/'builds/static-controls-sm2-x86_64-O2/ordinary.so'
  with p.with_name('inspection.so').open('rb') as f:
   elf=ELFFile(f);symbols={s.name:s['st_value'] for s in elf.get_section_by_name('.symtab').iter_symbols() if s['st_shndx']!='SHN_UNDEF'}
  bank=json.loads((WORKSPACE/'quantum-crypto-scanner/qcs/rules/static_primitives.json').read_text())
  sig=next(s for s in bank['signatures'] if s.get('semantic')=='mp_submod' and s['family']=='static-math-x86_64-O2')
  call=next(c for c in sig['calls'] if 'signature' in c)
  address=symbols['mp_submod']+call['offset'];regions,_=function_regions(p)
  base,offset,data,_=next(r for r in regions if r[3]&1 and r[0]<=address<r[0]+len(r[2]));ins=next(decode(disassembler('x86_64'),data[address-base:address-base+16],address))
  self.assertEqual(ins.mnemonic,'call');destination=symbols['mp_add'] if ins.operands[-1].imm!=symbols['mp_add'] else symbols['mp_mul']
  raw=bytearray(p.read_bytes());at=offset+address-base+ins.imm_offset
  raw[at:at+ins.imm_size]=(destination-address-ins.size).to_bytes(ins.imm_size,'little',signed=True)
  with tempfile.TemporaryDirectory() as folder:
   q=Path(folder)/'ordinary.so';q.write_bytes(raw);regions,_=function_regions(q)
   result=binary_equations(q,regions,'x86_64',time.monotonic()+60)
   self.assertNotIn('SM2',{m.get('algorithm','SM2') for m in result})
 def test_new_author_and_blinded_curve_source_equations(self):
  for file,want in [('sources/nettle/rsa-sign.c','RSA'),('sources/libecc/src/sig/ecdsa_common.c','ECDSA'),('sources/libecc/src/sig/sm2.c','SM2')]:
   p=DEV/file;r=new_report(p,'source');scan_source_semantics(p,r);self.assertFalse(r['errors']);self.assertIn(want,predictions(r,'implementation_contains'))
 def test_conditional_duplicate_functions_are_retained_but_not_inlined(self):
  code='#ifdef FEATURE\nunsigned f(unsigned x){return (x<<9)|(x>>23);}\n#else\nunsigned f(unsigned x){return x+1;}\n#endif\nunsigned g(unsigned x){return f(x);}'
  a=Analysis(code.encode(),False);a.run();self.assertIn('f',a.ambiguous_functions)
  self.assertEqual(sum(name=='f' or name.startswith('f@') for name in a.functions),2)
  self.assertFalse(any(root=='g' and role=='rotate' for root,role,value,site in a.events))
 def test_extended_euclid_needs_both_recurrences(self):
  code='long f(long a,long n){long t=0,nt=1,r=n,nr=a;while(nr){long q=r/nr;long z=t-q*nt;t=nt;nt=z;z=r-q*nr;r=nr;nr=z;}if(t<0)t+=n;return t;}'
  for raw,want in [(code,True),(code.replace('z=r-q*nr','z=r+q*nr'),False),(code.replace('t+=n','t-=n'),False)]:
   found,_=summaries(Analysis(raw.encode(),False));self.assertEqual(bool(found),want)

if __name__=='__main__':unittest.main()
