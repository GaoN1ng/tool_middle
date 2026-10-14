import copy
import tempfile
import unittest
from pathlib import Path
from features import source_functions, binary_body, link_context
from curate import annotate


class FeatureContract(unittest.TestCase):
    def test_renamed_source_keeps_operations_and_local_calls(self):
        a = 'unsigned helper(unsigned x){return (x<<7)^(x>>25);}\nunsigned caller(unsigned *p){for(int i=0;i<16;i++)p[i]=helper(p[i])+1;return p[0];}'
        b = a.replace('helper', 'different_name').replace('caller', 'outer').replace('p[', 'state[').replace('*p)', '*state)')
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'first.c'; q = Path(d) / 'unrelated.c'
            p.write_text(a); q.write_text(b)
            af, _ = source_functions(p); bf, _ = source_functions(q)
            self.assertEqual([f['features'] for f in af], [f['features'] for f in bf])
            self.assertTrue(af[1]['features']['context:neighbors_log'] > 0)

    def test_binary_relocation_excludes_absolute_addresses(self):
        # mov/add/xor/rotate + local backwards branch + ret
        raw = bytes.fromhex('b81000000083c00131c9c1c80775f9c3')
        a, _ = binary_body(raw, 0x1000, 'x86_64')
        b, _ = binary_body(raw, 0x12345000, 'x86_64')
        self.assertEqual(a, b)
        self.assertGreater(a['structure:back_edges'], 0)

    def test_context_is_order_independent_and_cycle_bounded(self):
        fs = [{'offset': 10, 'calls': [20], 'features': {'stat:op_add': .5}},
              {'offset': 20, 'calls': [10], 'features': {'stat:op_xor': .8}}]
        a = copy.deepcopy(fs); b = list(reversed(copy.deepcopy(fs)))
        link_context(a); link_context(b)
        self.assertEqual({f['offset']: f['features'] for f in a}, {f['offset']: f['features'] for f in b})

    def test_positive_file_does_not_label_every_helper(self):
        row = {'family': 'unknown-aes', 'truth': {'implementation_contains': ['AES']}}
        self.assertEqual(annotate('allocate', row, [], {} )[:2], ([], None))
        row = {'family': 'library-sha512', 'truth': {'implementation_contains': []}}
        self.assertEqual(annotate('sha512_transform', row, [], {})[:2], ([], 1))
        self.assertEqual(annotate('allocate', row, [], {})[:2], ([], None))


if __name__ == '__main__': unittest.main()
