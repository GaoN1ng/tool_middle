"""Verified constant arrays reached through bounded local source pointers."""
import unittest

from qcs.guomi.source_semantics import Analysis
from qcs.operation_tables import SHA256_K


class SourcePointerTests(unittest.TestCase):
    def reads(self, body, values=SHA256_K):
        code=('static const unsigned data[64]={'+','.join(map(str,values))+'};\n'
              'unsigned ordinary(unsigned count,unsigned *unknown){'+body+'}')
        analysis=Analysis(code.encode(),False);analysis.run()
        return [v for _,r,v,_ in analysis.events if r=='table_read']

    def test_aliases_and_offsets_read_actual_verified_array(self):
        for body in ('const unsigned *p=data;return p[3];',
                     'const unsigned *p=data+4;return p[3];',
                     'const unsigned *p=data;p++;return p[3];',
                     'const unsigned *p=data;const unsigned *q=p+8;return q[3];'):
            self.assertIn('sha256_k',self.reads(body),body)
        self.assertNotIn('sha256_k',self.reads('const unsigned *p=data;return p[3];',
                                              (SHA256_K[0]^1,)+SHA256_K[1:]))

    def test_proved_loop_pointer_range_survives_induction_widening(self):
        body='unsigned i,s=0;const unsigned *p;for(i=0,p=data;i<16;i+=8,p+=8){s+=p[7];}return s;'
        self.assertIn('sha256_k',self.reads(body))
        for changed in (body.replace('i<16','i<count'),
                        body.replace('i<16','i<72'),
                        body.replace('s+=p[7]','p=unknown;s+=p[7]'),
                        body.replace('s+=p[7]','i+=8;s+=p[7]'),
                        body.replace('s+=p[7]','escape(&p);s+=p[7]')):
            self.assertNotIn('sha256_k',self.reads(changed),changed)

    def test_invalidated_or_out_of_bounds_alias_is_not_a_table(self):
        for body in ('const unsigned *p=data;p=unknown;return p[0];',
                     'const unsigned *p=data+64;return p[0];',
                     'const unsigned *p=data-1;return p[0];',
                     'const unsigned *p=data;return p[count];',
                     'const unsigned *p=data;escape(&p);return p[0];',
                     'unsigned *data=unknown;return data[0];',
                     'const unsigned *p=data;if(count){p=unknown;}return p[0];'):
            self.assertNotIn('sha256_k',self.reads(body),body)
        code=('static const unsigned data[64]={'+','.join(map(str,SHA256_K))+'};\n'
              'unsigned ordinary(const unsigned *data){return data[0];}')
        analysis=Analysis(code.encode(),False);analysis.run()
        self.assertFalse(any(r=='table_read' for _,r,_,_ in analysis.events))


if __name__=='__main__':unittest.main()
