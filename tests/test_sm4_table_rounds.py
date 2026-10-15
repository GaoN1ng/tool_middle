"""SM4 lookup dataflow positives and mutation negatives, independent of names."""
from pathlib import Path
import tempfile
import unittest

from qcs.guomi.binary_semantics import DATA, table_patterns, locate_tables, Lift, decode, disassembler
from qcs.guomi.linear import leaf, truncate, shift, xor
from qcs.guomi.source_semantics import scan_source_semantics
from qcs.model import new_report, predictions
from qcs.sm4_tables import TableRounds


class SM4TableRoundTests(unittest.TestCase):
    def test_exact_four_bytes_and_negative_relations(self):
        x, y = leaf((1, ())), leaf((2, ()))
        def build(change=None):
            rounds = TableRounds(); out = leaf((99, ()))
            for i, position in enumerate((0, 8, 16, 24)):
                source = y if change == 'different-input' and i == 2 else x
                index = truncate(shift(source, 'right', position), 8) if position else truncate(source, 8)
                value = leaf((10 + i, ('block_table',)))
                rounds.remember(value, index, {'kind': 'block_table',
                    'byte_position': (position + 8) % 32 if change == 'wrong-byte' and i == 2 else position})
                if not (change == 'missing-byte' and i == 2):
                    out = xor(out, value)
            return rounds.witness(out)
        self.assertTrue(build())
        for change in ('different-input', 'wrong-byte', 'missing-byte'):
            self.assertIsNone(build(change), change)

    def test_four_table_maps_keep_exact_positions(self):
        for i, (kind, raw) in enumerate(table_patterns()):
            if kind != 'block_table':
                continue
            found = locate_tables([(0x4000, 0, raw, 4)])
            target = next(t for t in found if t['kind'] == kind)
            self.assertEqual(target['byte_position'], (i - 2) % 9 % 4 * 8)
            changed = raw[:13] + bytes([raw[13] ^ 1]) + raw[14:]
            self.assertFalse(locate_tables([(0x4000, 0, changed, 4)]))

    def test_source_preexpanded_rounds_and_inert_table(self):
        patterns = [(i, raw) for i, (kind, raw) in enumerate(table_patterns()) if kind == 'block_table'][:4]
        declarations = '\n'.join('const unsigned t%d[256]={%s};' % (i,
            ','.join(str(int.from_bytes(raw[j:j+4], 'little')) for j in range(0, len(raw), 4)))
            for i, (_, raw) in enumerate(patterns))
        # Maps for positions 0,8,16,24, using pre-expanded keys.
        word = 't0[x&255]^t1[(x>>8)&255]^t2[(x>>16)&255]^t3[x>>24]'
        body = 'unsigned f(unsigned x,unsigned y){unsigned z=' + word + ';x=y^z;return ' + word + ';}'
        cases = [(body, True), (body.replace('t2[(x>>16)&255]', 't2[(y>>16)&255]'), False),
                 ('unsigned f(unsigned x,unsigned y){unsigned z=' + word + ';x=y;return z^(' + word + ');}', False),
                 ('unsigned f(unsigned x){return t0[x&255];}', False),
                 ('unsigned f(unsigned x){return x+1;}', False)]
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / 'ordinary.c'
            for source, want in cases:
                p.write_text(declarations + source)
                report = new_report(p, 'source'); scan_source_semantics(p, report)
                self.assertFalse(report['errors'])
                self.assertEqual('SM4' in predictions(report, 'implementation_contains'), want)

    def test_pointer_spill_restores_only_pointer_width(self):
        # str x0,[sp,#16]; ldr x1,[sp,#16]; str w2,[sp,#16]; ldr x3,[sp,#16]
        raw = bytes.fromhex('e00b00f9e10b40f9e21300b9e30b40f9')
        lift = Lift('aarch64', [], [(0x1000, 0, raw, 1)])
        lift.addresses['x0'] = 0x8000
        instructions = list(decode(disassembler('aarch64'), raw, 0x1000))
        lift.step(instructions[0]); lift.step(instructions[1])
        self.assertEqual(lift.addresses.get('x1'), 0x8000)
        lift.step(instructions[2]); lift.step(instructions[3])
        self.assertNotIn('x3', lift.addresses)

    def test_decoded_byte_load_matches_the_cached_array_cell(self):
        # ldrb w10,[x9,w8,uxtw]: ARM64 has no operand.size metadata.
        raw=bytes.fromhex('2a496838')
        lift=Lift('aarch64',[],[(0x1000,0,raw,1)])
        lift.step(next(decode(disassembler('aarch64'),raw,0x1000)))
        value=lift.regs['x10']
        self.assertIn(value,lift.arrays.loads)
        self.assertIsNotNone(lift.arrays.byte_value(value))


if __name__ == '__main__':
    unittest.main()
