"""Classic MIPS32 delay slots, converged joins and stripped PIC entries."""
import time
import unittest

from qcs.controlflow import analyze
from qcs.guomi.binary_semantics import Lift, decode, disassembler
from qcs.guomi.linear import leaf, rotate


def imm(op, target, source, value):
    return (op << 26) | (source << 21) | (target << 16) | (value & 0xffff)


class MIPSControlflowTests(unittest.TestCase):
    def run_words(self, words, domain='mipsel', **kwargs):
        raw=b''.join(w.to_bytes(4,'little' if domain=='mipsel' else 'big') for w in words)
        lift=Lift(domain,[{'address':0x8000,'length':256,'kind':'sha256_k'}],[(0x1000,0,raw,1)],**kwargs)
        info=analyze(lift,list(decode(disassembler(domain),raw,0x1000)),time.monotonic()+10)
        return lift,info

    def test_branch_slot_reads_real_table_in_both_endians(self):
        # ori s0,zero,0x8000; beq a0,a1,+2; lw v0,0(s0);
        # nop; jr ra; nop. The load executes on both branch edges.
        words=[imm(13,16,0,0x8000),imm(4,5,4,2),imm(35,2,16,0),0,0x03e00008,0]
        for domain in ('mipsel','mips_be'):
            lift,info=self.run_words(words,domain)
            self.assertEqual(info['status'],'completed')
            self.assertIn((0x1008,'table_read','sha256_k'),lift.events)
        words[1]=imm(20,5,4,2)  # beql: slot is conditional, currently declined.
        lift,info=self.run_words(words)
        self.assertEqual(info['status'],'limited')
        self.assertFalse(any(r=='table_read' for _,r,_ in lift.events))

    def test_conflicting_join_does_not_keep_provisional_table_reads(self):
        # Conditional paths assign s0 different addresses before the join.
        words=[imm(4,5,4,4),0,imm(13,16,0,0x8000),imm(4,0,0,3),0,
               imm(13,16,0,0x9000),0,imm(35,2,16,0),0x03e00008,0]
        lift,info=self.run_words(words)
        self.assertEqual(info['status'],'completed')
        self.assertGreater(info['joins'],0)
        self.assertFalse(any(r=='table_read' for _,r,_ in lift.events))

    def test_call_slot_precedes_callee_clobber(self):
        # jal external; ori t0,zero,0x8000 (slot); lw v0,0(t0).
        # A callee may overwrite t0, so the last load is not a known table read.
        words=[(3<<26)|(0x2000>>2),imm(13,8,0,0x8000),imm(35,2,8,0),0x03e00008,0]
        lift,info=self.run_words(words)
        self.assertFalse(any(r=='table_read' for _,r,_ in lift.events))
        # s0 is callee-preserved and keeps the slot's actual address.
        words[1]=imm(13,16,0,0x8000);words[2]=imm(35,2,16,0)
        lift,info=self.run_words(words)
        self.assertIn((0x1008,'table_read','sha256_k'),lift.events)

    def test_pic_address_survives_a_loop_edge(self):
        # lui v0,0; addiu v0,v0,0x7000; addu s2,v0,t9.
        # gp is exactly entry+offset; no symbol information is supplied.
        words=[imm(15,2,0,0),imm(9,2,2,0x7000),(2<<21)|(25<<16)|(18<<11)|33,
               imm(4,5,4,1),0,imm(35,3,18,0),imm(5,0,4,-2),0,0x03e00008,0]
        lift,info=self.run_words(words,mips_gp=0x8000)
        self.assertEqual(info['status'],'completed')
        self.assertGreater(info['loop_edges'],0)
        self.assertTrue(any(r=='table_read' for _,r,_ in lift.events))
        lift,_=self.run_words(words,mips_gp=0x8004)
        self.assertFalse(any(r=='table_read' for _,r,_ in lift.events))

    def test_imported_copy_binds_got_slot_and_actual_delay_slot_length(self):
        # ori a1,zero,0x8000; ori t0,zero,0x9000; lw t9,0(t0);
        # jalr t9; addiu a2,zero,32 (delay slot); jr ra; nop.
        for domain in ('mipsel','mips_be'):
            for length,api,tail,want in ((32,'memcpy',False,True),
                                         (32,'memmove',True,True),
                                         (31,'memcpy',False,False),
                                         (32,'ordinary',False,False)):
                words=[imm(13,5,0,0x8000),imm(13,8,0,0x9000),imm(35,25,8,0),
                       (25<<21)|8 if tail else (25<<21)|(31<<11)|9,
                       imm(9,6,0,length),0x03e00008,0]
                raw=b''.join(w.to_bytes(4,'little' if domain=='mipsel' else 'big') for w in words)
                tables=[{'address':0x8000,'length':32,'kind':'sha256_iv'}]
                lift=Lift(domain,tables,[(0x1000,0,raw,1)],import_slots={0x9000:api})
                analyze(lift,list(decode(disassembler(domain),raw,0x1000)),time.monotonic()+10)
                self.assertEqual((0x100c,'table_read','sha256_iv') in lift.events,want,
                                 (domain,length,api,tail,lift.events))

    def test_mips_dynamic_tags_resolve_real_development_import(self):
        from pathlib import Path
        from elftools.elf.elffile import ELFFile
        from qcs.guomi.binary_bignum import import_slots
        root=Path(__file__).resolve().parents[1]
        path=root/'Samples/test_set/elf_samples/9d/9d543abbeb4e1f19/ordinary.so'
        with path.open('rb') as stream:
            elf=ELFFile(stream)
            tags={t.entry.d_tag:t.entry.d_val for s in elf.iter_segments()
                  if s['p_type']=='PT_DYNAMIC' for t in s.iter_tags()}
            slot=tags['DT_PLTGOT']+tags['DT_MIPS_LOCAL_GOTNO']*(elf.elfclass//8)
        self.assertEqual(import_slots(path).get(slot),'mutils_memcpy')

    def test_scalar_helper_uses_variable_shifts_and_return_delay_slot(self):
        # sllv at,a0,a1; addiu v0,zero,32; subu v0,v0,a1;
        # srlv v0,a0,v0; jr ra; or v0,v0,at (return slot).
        for domain in ('mipsel','mips_be'):
            for complement,want in ((32,True),(31,False)):
                words=[(5<<21)|(4<<16)|(1<<11)|4,imm(9,2,0,complement),
                       (2<<21)|(5<<16)|(2<<11)|35,(2<<21)|(4<<16)|(2<<11)|6,
                       0x03e00008,(2<<21)|(1<<16)|(2<<11)|37]
                endian='little' if domain=='mipsel' else 'big'
                raw=b''.join(w.to_bytes(4,endian) for w in words)
                caller=((3<<26)|(0x1100>>2)).to_bytes(4,endian)
                ins=next(decode(disassembler(domain),caller,0x1000))
                lift=Lift(domain,[],[(0x1100,0,raw,1)])
                x=leaf((1,('sbox',)));lift.regs.update(a0=x,a1=('constant',2))
                self.assertTrue(lift.local_call(ins))
                self.assertEqual(lift.regs['v0']==rotate(x,2),want)

    def test_aarch64_flag_setting_subtract_recovers_complementary_shift(self):
        raw=bytes.fromhex('ff4300d1e00f00b9e10b00b9e80f40b9e90b40b90821c91ae90f40b9eb0b40b90a0480524a010b6b2925ca1a0001092aff430091c0035fd6')
        x=leaf((1,('sbox',)))
        for changed,want in ((raw,True),(raw.replace(bytes.fromhex('4a010b6b'),bytes.fromhex('4a010b2b')),False)):
            lift=Lift('aarch64',[],[(0x1000,0,changed,1)])
            lift.regs.update(x0=x,x1=('constant',2))
            instructions=list(decode(disassembler('aarch64'),changed,0x1000))
            for ins in instructions[:-1]:lift.step(ins)
            self.assertEqual(lift.regs['x0']==rotate(x,2),want)

    def test_unstable_runtime_loop_does_not_erase_an_independent_function(self):
        # A six-register loop loses one fact per revisit. The descending
        # intersection now converges without erasing invariant frame facts.
        raw=bytes.fromhex('b801000000bb01000000b901000000ba01000000be01000000bf01000000'
                          '89d889cb89d189f289feffc7ebf2c3b867e6096a8907c3')
        lift=Lift('x86_64',[],[(0x1000,0,raw,1)])
        info=analyze(lift,list(decode(disassembler('x86_64'),raw,0x1000)),time.monotonic()+10)
        self.assertEqual(info['status'],'completed')
        self.assertEqual(info['widened_blocks'],0)
        self.assertGreater(info['replayed_blocks'],0)
        self.assertTrue(any(r=='iv_store' and v==0x6a09e667 for _,r,v in lift.events))
        lift=Lift('x86_64',[],[(0x1000,0,raw,1)])
        info=analyze(lift,list(decode(disassembler('x86_64'),raw,0x1000)),
                     time.monotonic()+10,max_steps=10)
        self.assertGreater(info['limited_components'],0)
        self.assertTrue(any(r=='iv_store' and v==0x6a09e667 for _,r,v in lift.events))


if __name__=='__main__':unittest.main()
