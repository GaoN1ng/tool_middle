"""Compression reference known answers and finite state-feedback controls."""
import hashlib
import time
import unittest
from qcs.compression_probes import compress,probe,vectors
from qcs.semantic_probes import ARENA
from test_semantic_probes import Memory

class Candidate:
    endian='little'
    def __init__(self,algorithm,corrupt=False,constant=False):
        self.machine=Memory();self.algorithm=algorithm;self.model_calls=[];self.corrupt=corrupt;self.constant=constant
    def reset(self):self.machine.bytes.clear()
    def invoke(self,address,args,**kw):
        state,block,_=args;count=8 if self.algorithm=='SM3' else 5
        statewords=[int.from_bytes(self.machine.mem_read(state+4*i,4),'little') for i in range(count)]
        result=compress(self.algorithm,statewords,self.machine.mem_read(block,64))
        if self.constant:result=vectors(self.algorithm)[0][2]
        if self.corrupt:result[-1]^=1
        self.machine.mem_write(state,b''.join(v.to_bytes(4,'little') for v in result))

class CompressionTests(unittest.TestCase):
    def test_complete_compression_matches_standard_abc_digests(self):
        block=b'abc\x80'+bytes(52)+(24).to_bytes(8,'big')
        for name,state,expected in (
            ('SHA-1',[0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0],hashlib.sha1(b'abc').hexdigest()),
            ('SM3',[0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e],
             '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')):
            self.assertEqual(''.join(f'{v:08x}' for v in compress(name,state,block)),expected)

    def test_all_states_and_every_feedback_word_required(self):
        for algorithm in ('SM3','SHA-1'):
            self.assertEqual(len(probe(Candidate(algorithm),[1],algorithm,time.monotonic()+2)),1)
            self.assertFalse(probe(Candidate(algorithm,corrupt=True),[1],algorithm,time.monotonic()+2))
            self.assertFalse(probe(Candidate(algorithm,constant=True),[1],algorithm,time.monotonic()+2))
            self.assertFalse(probe(Candidate(algorithm),[1],algorithm,time.monotonic()-1))

if __name__=='__main__':unittest.main()
