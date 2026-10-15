"""Loop prefixes, real declaration macros and dependent curve equations."""
import tempfile
import time
import unittest
from pathlib import Path

from qcs.controlflow import analyze
from qcs.guomi.binary_semantics import Lift,decode,disassembler
from qcs.guomi.binary_bignum import PointerLift
from qcs.guomi.source_semantics import Analysis
from qcs.guomi.source_context import available_code,load_context
from qcs.operation_bignum import ConventionalEquations
from qcs.curve_exchange import Exchange

ROOT=Path(__file__).resolve().parents[1]


class SemanticPathTests(unittest.TestCase):
    def test_aarch64_stub_never_uses_import_name_as_address(self):
        # ADRP x16; LDR x16,[x16]; LDR x17,[x16,#8]; BR x17.
        # The first load resolves a name; the second has no concrete base.
        raw=bytes.fromhex('10000090100240f9110640f920021fd6')
        lift=PointerLift('aarch64',[(0x1000,0,raw,1)],{0x1000:'BN_mod_exp'})
        self.assertIsNone(lift.resolve_stub(0x1000))
        valid=bytes.fromhex('10000090110240f920021fd6')
        lift=PointerLift('aarch64',[(0x1000,0,valid,1)],{0x1000:'BN_mod_exp'})
        self.assertEqual(lift.resolve_stub(0x1000),'BN_mod_exp')

    def test_actual_definition_macro_preserves_body_offsets(self):
        raw=b'#define DEFINE(T,N,P) T N P\nDEFINE(unsigned, ordinary, (unsigned x))\n{return x+1;}'
        analysis=Analysis(raw,False)
        self.assertIn('ordinary',analysis.functions)
        self.assertEqual(analysis.functions['ordinary'][1].start_byte,raw.index(b'{'))
        self.assertEqual(len(analysis.raw),len(raw))
        self.assertEqual(analysis.raw.count(b'\n'),raw.count(b'\n'))
        analysis=Analysis(raw.replace(b'T N P',b'T other P'),False)
        self.assertIn('other',analysis.functions)
        self.assertNotIn('ordinary',analysis.functions)

    def test_missing_or_conflicting_declaration_definitions_are_declined(self):
        for header in (b'',b'#define DECL(T,N,P) T N P\n#define DECL(T,N,P) T other P\n'):
            analysis=Analysis(header+b'DECL(unsigned, ordinary, (unsigned x)){return x;}',False)
            self.assertNotIn('ordinary',analysis.functions)
        header=b'#define DECL(T,N,P) T N P\n'
        analysis=Analysis(b'DECL(unsigned, ordinary, (unsigned x)){return x;}',False,declaration_contexts=[header])
        self.assertIn('ordinary',analysis.functions)

    def test_include_suffix_is_unambiguous_and_stays_local(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build/tmp') as directory:
            root=Path(directory);(root/'LICENSE').write_text('fixture')
            for name in ('src','custom/include'): (root/name).mkdir(parents=True)
            path=root/'src/ordinary.c';path.write_text('#include "local.h"\n')
            (root/'custom/include/local.h').write_text('#define DECL(T,N,P) T N P\n')
            _,record=load_context(path,path.read_text());self.assertEqual(len(record['files']),1)
            (root/'src/other').mkdir();(root/'src/other/local.h').write_text('#define DECL(T,N,P) T wrong P\n')
            _,record=load_context(path,path.read_text());self.assertEqual(record['files'],[])

    def test_natural_loop_entry_keeps_pointer_without_exporting_exit_state(self):
        raw=bytes.fromhex('48bb0080000000000000b9020000008b034883c304ffc975f6b867e6096a8907c3')
        instructions=list(decode(disassembler('x86_64'),raw,0x1000))
        tables=[{'address':0x8000,'length':256,'kind':'sha256_k'}]
        lift=Lift('x86_64',tables,[(0x1000,0,raw,1)]);outputs={}
        analyze(lift,instructions,time.monotonic()+10,block_outputs=outputs)
        prefix=Lift('x86_64',tables,[(0x1000,0,raw,1)])
        info=analyze(prefix,instructions,time.monotonic()+10,initial_iteration=True,entry_outputs=outputs)
        self.assertIn((0x100f,'table_read','sha256_k'),prefix.events)
        self.assertFalse(any(role=='iv_store' for _,role,_ in prefix.events))
        self.assertEqual(info['status'],'completed')

    def test_arm_pc_and_neon_alignment_are_addresses_not_displacements(self):
        # Thumb ADR at 0x1030a resolves 0x10340. VLD's :128 is alignment.
        path=ROOT/'Samples/test_set/elf_samples/aa/aa923f7e5d6ec8c6/ordinary.so'
        from qcs.function_signatures import function_regions,read_virtual
        regions,_=function_regions(path)
        tables=[{'address':0x10340,'length':32,'kind':'sha256_iv'}]
        lift=Lift('thumb',tables,regions)
        raw=read_virtual(regions,0x1030a,0x14)
        for ins in decode(disassembler('thumb'),raw,0x1030a):lift.step(ins)
        reads=[e for e in lift.events if e[1]=='table_read']
        self.assertEqual(len(reads),2)
        lift=Lift('thumb',[{'address':0x103c0,'length':32,'kind':'sha256_iv'}],regions)
        for ins in decode(disassembler('thumb'),raw,0x1030a):lift.step(ins)
        self.assertFalse(any(e[1]=='table_read' for e in lift.events))

    def test_ladder_needs_all_bound_equations_inverse_and_output(self):
        path=ROOT/'build/datasets/development-source-context/samples/controlflow-development-20261014/sources/tinyssh/crypto_scalarmult_curve25519.c'
        original=available_code(path.read_text())
        variants=[(original,True),
            (original.replace('fe25519_sub(z2, z3, z2)','fe25519_add(z2, z3, z2)'),False),
            (original.replace('fe25519_mul(x2, tmp1, tmp0)','fe25519_mul(x2, tmp1, x1)'),False),
            (original.replace('fe25519_inv(z2, z2);',''),False),
            (original.replace('fe25519_tobytes(q, x2)','fe25519_tobytes(q, x1)'),False),
            (original.replace('fe25519_inv(z2, z2);','fe25519_inv(z2, z2); unknown(z2);'),False),
            (original.replace('fe25519_inv(z2, z2);','fe25519_inv(z2, z2); fe25519_add(z2,x1,x1);'),False),
            ('void fe25519_mul(void *a,void *b,void *c){}\n'+original,False)]
        for code,want in variants:
            analysis=Analysis(code.encode(),False);analysis.run();analysis.findings()
            self.assertEqual(any(m[0]=='ECDH' for m in analysis.general_findings()),want)

    def test_curve_signing_needs_scalar_inverse_and_same_coordinate(self):
        for wrong in (None,'inverse','coordinate','sum'):
            eq=ConventionalEquations()
            calls=[('prj_pt_mul',['R','k','P']),('prj_pt_unique',['R','R']),
                   ('nn_mod',['r','R.X.fp_val' if wrong!='coordinate' else 'other','n']),
                   ('nn_mod_mul',['v','r','d','n']),
                   ('nn_mod_add',['v','v','e','n']),
                   ('nn_modinv',['inv','k' if wrong!='inverse' else 'other','n']),
                   ('nn_mod_mul' if wrong!='sum' else 'nn_mod_add',['s','inv','v','n'])]
            for site,(name,args) in enumerate(calls):eq.feed(name,args,site)
            self.assertEqual(any(m['algorithm']=='ECDSA' for m in eq.general_matches),wrong is None)

    def test_key_agreement_needs_real_xhat_and_correct_peer_scalar(self):
        for mutation in (None,'unbound','wrong_point','wrong_scalar','no_kdf'):
            ex=Exchange();ex.xhat('xl','RL',1,'fixture proven formula')
            if mutation!='unbound':ex.xhat('xp','RP',2,'fixture proven formula')
            calls=[('sm2_z256_modn_mul',['t','xl','rl']),('sm2_z256_modn_add',['t','t','d']),
                   ('sm2_z256_point_mul',['Q','xp','RP' if mutation!='wrong_point' else 'other']),
                   ('sm2_z256_point_add',['Q','PP','Q']),
                   ('sm2_z256_point_mul',['Q','t' if mutation!='wrong_scalar' else 'd','Q']),
                   ('sm2_z256_point_to_bytes',['Q','input'])]
            if mutation!='no_kdf':calls.append(('sm2_kdf',['input','128','len','out']))
            for site,(name,args) in enumerate(calls,3):ex.feed(name,args,site)
            self.assertEqual(bool(ex.matches),mutation is None)

    def test_binary_xhat_requires_both_high_zero_limbs(self):
        # mov [rdi],rax; mov [rdi+8],rbx; mov [rdi+16],rcx;
        # mov [rdi+24],rcx. Only complete stores establish the x-hat.
        raw=bytes.fromhex('48890748895f0848894f1048894f18')
        for high,want in (('0',True),('1',False)):
            lift=PointerLift('x86_64',[],{})
            lift.regs.update(rdi='input:0:rdi',rax='coordinate-low',rbx='coordinate-high',rcx=high)
            lift.coordinate_words['coordinate-low']=('P',0)
            lift.high_bit_words['coordinate-high']=('P',1)
            for ins in decode(disassembler('x86_64'),raw,0x1000):lift.step(ins)
            self.assertEqual('input:0:rdi[0]' in lift.equations.exchange.xhats,want)

    def test_source_xhat_requires_untouched_affine_coordinate_and_all_stores(self):
        from qcs.curve_exchange import source_xhat_helpers
        code='''int local(void*P,unsigned long*out){unsigned long x[4];
if(sm2_z256_point_get_xy(P,x,0)!=1)return -1;
out[0]=x[0];out[1]=(x[1]&0x7fffffffffffffff)|0x8000000000000000;
out[2]=0;out[3]=0;return 1;}'''
        for variant,want in ((code,True),(code.replace('out[0]=x[0];','x[0]=0;out[0]=x[0];'),False),
                             (code.replace('out[3]=0;','if(flag){out[3]=0;}'),False)):
            a=Analysis(variant.encode(),False)
            self.assertEqual(bool(source_xhat_helpers(a)),want)


if __name__=='__main__':unittest.main()
