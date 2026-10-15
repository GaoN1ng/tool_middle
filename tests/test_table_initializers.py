"""Complete generated-table acceptance and consumer/failure boundaries."""
import unittest
from qcs.guomi.source_semantics import Analysis
from qcs.operation_tables import numeric_tables
from qcs.table_initializers import recover


class GeneratedTableTests(unittest.TestCase):
    def analyze(self,tail='',consumer=False):
        box=next(values for kind,values in numeric_tables() if kind=='aes_sbox')
        raw=('static unsigned char input[256]={'+','.join(map(str,box))+'};\n'
             'static unsigned char output[256];\n'
             'void build(void){int i;for(i=0;i<256;i++)output[i]=input[i];'+tail+'}\n')
        if consumer:
            raw+='unsigned int transform(unsigned int x){return output[x&255]^output[(x>>8)&255]^output[(x>>16)&255]^output[(x>>24)&255]^x;}'
        analysis=Analysis(raw.encode(),False);tables=recover(analysis);analysis.run();analysis.findings()
        return tables,{item[0] for item in analysis.general_findings()}

    def test_complete_map_needs_actual_operation_consumers(self):
        tables,algorithms=self.analyze()
        self.assertTrue(any(row['table']=='output' for row in tables))
        self.assertNotIn('AES',algorithms)
        _,algorithms=self.analyze(consumer=True)
        self.assertIn('AES',algorithms)

    def test_mutated_unknown_and_out_of_bounds_constructors_decline(self):
        for tail in ('output[7]^=1;','unknown(output);','output[256]=1;',
                     'for(i=0;i<256;i--)output[0]=0;'):
            with self.subTest(tail=tail):
                tables,algorithms=self.analyze(tail,consumer=True)
                self.assertFalse(any(row['table']=='output' for row in tables))
                self.assertNotIn('AES',algorithms)

    def test_renamed_functions_and_arrays_preserve_behavior(self):
        box=next(values for kind,values in numeric_tables() if kind=='aes_sbox')
        raw=('typedef unsigned char octet;static octet source[256]={'+','.join(map(str,box))+'};'
             'static octet target[256];void unusual(void){int j;for(j=0;j<256;++j)target[j]=(octet)source[j];}')
        rows=recover(Analysis(raw.encode(),False))
        self.assertEqual([(r['table'],r['kind']) for r in rows],[('target','aes_sbox')])

    def test_multidimensional_storage_is_bounded_before_allocation(self):
        raw=b'static unsigned char enormous[4096][4096][4096];void build(void){enormous[0][0][0]=1;}'
        self.assertEqual(recover(Analysis(raw,False)),[])

if __name__=='__main__':unittest.main()
