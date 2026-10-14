"""Equation binding, cross-call witnesses and ISA coverage development checks."""
import unittest
from pathlib import Path
from qcs.guomi.bignum import Equations
from qcs.guomi.binary_semantics import Lift,decode,disassembler,witnesses
from qcs.guomi.linear import leaf,roles,rotate
from qcs.guomi.source_semantics import Analysis
from qcs.model import new_report


def signature(prefix='mp_',wrong=False,modulus='n'):
    return [(prefix+'addmod',['x','e','n','r']),
            (prefix+'mulmod',['r','d','n','u']),
            (prefix+'add_d',['d','1','den']),
            (prefix+'mulmod',['den','b',modulus,'den']),
            (prefix+'invmod',['den',modulus,'den']),
            (prefix+'mulmod',['k','den','n','v']),
            (prefix+'mulmod',['u','den','n','u']),
            (prefix+('addmod' if wrong else 'submod'),['v','u','n','s']),
            (prefix+'mulmod',['s','b','n','s'])]


def equations(calls,shadowed=()):
    e=Equations(shadowed)
    for i,(n,a) in enumerate(calls):e.feed(n,a,i*10+1)
    return e


class GuomiOperationTests(unittest.TestCase):
    def test_blinding_and_api_argument_conventions(self):
        for prefix in ('mp_','sp_'):
            self.assertTrue(equations(signature(prefix)).matches)
            self.assertFalse(equations(signature(prefix,wrong=True)).matches)
            self.assertFalse(equations(signature(prefix,modulus='other_order')).matches)
            self.assertFalse(equations(signature(prefix),[prefix+'invmod']).matches)
            modified=signature(prefix)
            modified.insert(2,('opaque_mutation',['u']))
            self.assertFalse(equations(modified).matches)
        bn=[('BN_mod_add',['r','e','x','n','ctx']),('BN_mod_mul',['u','r','d','n','ctx']),
            ('BN_copy',['den','d']),('BN_add_word',['den','1']),
            ('BN_mod_inverse',['den','den','n','ctx']),
            ('BN_mod_sub',['u','k','u','n','ctx']),('BN_mod_mul',['s','u','den','n','ctx'])]
        self.assertTrue(equations(bn).matches)
        # ECDSA s=k^-1*(e+r*d) uses the same primitive APIs but a different relation.
        ecdsa=[('BN_mod_mul',['u','r','d','n','ctx']),('BN_mod_add',['u','e','u','n','ctx']),
               ('BN_mod_inverse',['den','k','n','ctx']),('BN_mod_mul',['s','u','den','n','ctx'])]
        self.assertFalse(equations(ecdsa).matches)

    def test_mpi_separate_reduction_and_coordinate_binding(self):
        mpi=[('mbedtls_mpi_add_mpi',['r','e','x']),('mbedtls_mpi_mod_mpi',['r','r','n']),
             ('mbedtls_mpi_mul_mpi',['u','r','d']),('mbedtls_mpi_add_int',['den','d','1']),
             ('mbedtls_mpi_inv_mod',['den','den','n']),('mbedtls_mpi_sub_mpi',['u','k','u']),
             ('mbedtls_mpi_mul_mpi',['s','u','den']),('mbedtls_mpi_mod_mpi',['s','s','n'])]
        # Reduction after the add must be remembered as the r equation.
        self.assertTrue(equations(mpi).matches)
        calls=[('BN_mod_add',['t','r','s','n','ctx']),('EC_POINT_mul',['g','P','s','pub','t','ctx']),
               ('EC_POINT_get_affine_coordinates',['g','P','x','y','ctx']),
               ('BN_mod_add',['t','e','x','n','ctx']),('BN_cmp',['t','r'])]
        self.assertTrue(equations(calls).matches)
        calls[2]=('EC_POINT_get_affine_coordinates',['g','other_point','x','y','ctx'])
        self.assertFalse(equations(calls).matches)

    def test_montgomery_scale_and_group_order_are_bound(self):
        e=Equations();e.group_orders['group']='n';e.mont_groups['mont']='group'
        calls=[('BN_mod_add',['r','e','x','n','ctx']),('BN_add',['s','d','BN_value_one()']),
               ('ossl_ec_group_do_inverse_ord',['group','s','s','ctx']),
               ('bn_to_mont_fixed_top',['u','r','mont','ctx']),
               ('bn_mul_mont_fixed_top',['u','u','d','mont','ctx']),
               ('bn_mod_sub_fixed_top',['u','k','u','n']),
               ('bn_to_mont_fixed_top',['u','u','mont','ctx']),
               ('BN_mod_mul_montgomery',['s','u','s','mont','ctx'])]
        for i,(n,a) in enumerate(calls):e.feed(n,a,i+1)
        self.assertTrue(e.matches)
        bad=Equations();bad.group_orders.update(group='n',other='other_n');bad.mont_groups['mont']='other'
        for i,(n,a) in enumerate(calls):bad.feed(n,a,i+1)
        self.assertFalse(bad.matches)

    def test_aarch64_local_calls_and_dynamic_rotate(self):
        # neg w8,w1; ror w0,w0,w8; ret, emitted by the actual development compiler.
        raw=bytes.fromhex('e803014b002cc81ac0035fd6')
        ins=list(decode(disassembler('aarch64'),raw,0x200))
        lift=Lift('aarch64',[],[]);x=leaf((99,()))
        lift.regs={'x0':x,'x1':('constant',13)}
        for op in ins[:-1]:lift.step(op)
        self.assertEqual(lift.regs['x0'],rotate(x,13))

    def test_name_independent_local_rotate_helper(self):
        # SysV uint32 helper(x,n): mov eax,edi; mov ecx,esi; rol eax,cl; ret
        body=bytes.fromhex('89f889f1d3c0c3')
        call=next(disassembler('x86_64').disasm(bytes.fromhex('e8fb000000'),0x100))
        lift=Lift('x86_64',[],[(0x200,0,body,1)])
        x=leaf((99,()))
        lift.regs={'rdi':x,'rsi':('constant',13),'rbx':x}
        self.assertTrue(lift.local_call(call))
        self.assertEqual(lift.regs['rax'],rotate(x,13))
        self.assertEqual(lift.regs['rbx'],x)
        self.assertNotIn('rdi',lift.regs)
        # A conditional branch with two possible returns is not a scalar summary.
        bad=bytes.fromhex('85ff740389f8c331c0c3')
        lift=Lift('x86_64',[],[(0x200,0,bad,1)])
        self.assertFalse(lift.local_call(call))

    def test_ud1_operand_bytes_do_not_become_instructions(self):
        raw=bytes.fromhex('670fb9401489f8c3')
        ins=list(decode(disassembler('x86_64'),raw,0x100))
        self.assertEqual([(i.address,i.mnemonic) for i in ins],[(0x100,'ud1'),(0x105,'mov'),(0x107,'ret')])

    def test_crypto_instructions_require_operation_families(self):
        sm4=[(1,'crypto_instruction','sm4e'),(2,'crypto_instruction','sm4ekey')]
        self.assertEqual({x[0] for x in witnesses(sm4,[])},{'SM4'})
        self.assertFalse(witnesses(sm4[:1],[]))
        sm3=[(i,'crypto_instruction',op) for i,op in enumerate(
            ['sm3ss1','sm3tt1a','sm3tt1b','sm3tt2a','sm3tt2b','sm3partw1','sm3partw2'])]
        self.assertEqual({x[0] for x in witnesses(sm3,[])},{'SM3'})
        self.assertFalse(witnesses(sm3[:-1],[]))

    def test_actual_upstream_signer_without_algorithm_names_or_hashes(self):
        from support import WORKSPACE
        src=(WORKSPACE/'samples/guomi-development-20261012/sources/wolfsm/sm2.c').read_bytes()
        # Isolate the authentic signature-equation helper, rename its identifier.
        start=src.index(b'static int _ecc_sm2_calc_r_s')
        end=src.index(b'\n#endif',start)
        src=src[start:end].replace(b'_ecc_sm2_calc_r_s',b'ordinary')
        a=Analysis(src,False);a.run()
        self.assertIn('SM2',{f[0] for f in a.findings()})
        a=Analysis(src.replace(b'mp_submod_ct',b'mp_addmod_ct'),False);a.run()
        self.assertNotIn('SM2',{f[0] for f in a.findings()})


if __name__=='__main__':unittest.main()
