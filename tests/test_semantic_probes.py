"""Bounded emulator failure controls and independent vector acceptance."""
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from qcs.semantic_probes import Machine,Declined,ARENA,probe_curve,probe_block,probe_stream,curve_vectors,rc4_stream,des_boundary
from qcs.function_signatures import function_regions
from qcs.model import new_report

ROOT=Path(__file__).resolve().parents[1]

class Memory:
    def __init__(self):self.bytes={}
    def mem_write(self,address,data):
        for i,v in enumerate(data):self.bytes[address+i]=v
    def mem_read(self,address,n):return bytes(self.bytes.get(address+i,0) for i in range(n))

class FakeMachine:
    def __init__(self,kind,corrupt=False):
        self.machine=Memory();self.kind=kind;self.corrupt=corrupt;self.initial_writable=[];self.model_calls=[]
    def reset(self):self.machine.bytes.clear()
    def invoke(self,address,args,**kwargs):
        from qcs.semantic_probes import BLOCK_VECTORS
        if self.kind=='curve':
            out,key,point=args
            # Deliberately implements only the first probe input. A constant
            # answer must fail even when the first vector happens to match.
            self.machine.mem_write(out,curve_vectors()[0][2]);return
        if address==1:
            state,key,length=args[:3];self.key=self.machine.mem_read(key,length)
            self.machine.mem_write(state,self.key);return
        if address!=2:raise Declined('No entry')
        state,block=args[:2];plain=self.machine.mem_read(block,16 if self.kind=='AES' else 8)
        self.key=self.machine.mem_read(state,16 if self.kind=='AES' else 8)
        for k,p,out in BLOCK_VECTORS[self.kind]:
            if self.key==bytes.fromhex(k) and plain==bytes.fromhex(p):
                data=bytearray.fromhex(out)
                if self.corrupt and k.startswith('0000'):data[0]^=1
                self.machine.mem_write(block,data);return
        raise Declined('No implementation')

class VectorTests(unittest.TestCase):
    def test_des_boundary_is_an_explicit_involutive_encoding(self):
        for raw in (bytes.fromhex('0123456789abcdef'),bytes(range(8)),bytes(8)):
            self.assertEqual(des_boundary(des_boundary(raw)),raw)
        self.assertNotEqual(des_boundary(bytes(range(8))),bytes(range(8)))
    def test_rc4_reference_matches_rfc6229_first_block(self):
        self.assertEqual(rc4_stream(bytes.fromhex('0102030405'),bytes(16)).hex(),'b2396305f03dc027ccc3524a0a1118a8')

    def test_montgomery_reference_matches_rfc7748(self):
        from qcs.semantic_probes import montgomery
        scalar=bytearray.fromhex('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4')
        scalar[0]&=248;scalar[31]=(scalar[31]&127)|64
        point=bytes.fromhex('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c')
        self.assertEqual(montgomery(bytes(scalar),point).hex(),'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552')

    def test_one_matching_curve_vector_does_not_accept(self):
        self.assertFalse(probe_curve(FakeMachine('curve'),[1],time.monotonic()+2))

    def test_all_block_vectors_required_and_expired_budget_declines(self):
        for algorithm in ('AES','DES'):
            self.assertEqual(len(probe_block(FakeMachine(algorithm),[1,2],algorithm,time.monotonic()+2)),1)
            self.assertFalse(probe_block(FakeMachine(algorithm,True),[1,2],algorithm,time.monotonic()+2))
            self.assertFalse(probe_block(FakeMachine(algorithm),[1,2],algorithm,time.monotonic()-1))

class IsolationTests(unittest.TestCase):
    def test_preparation_deadline_is_checked_during_instruction_decoding(self):
        from types import SimpleNamespace
        from qcs.semantic_probes import scan_probes
        report=new_report(self.path,'executable')
        clock=[0]
        def instructions(*args):
            clock[0]=10
            yield SimpleNamespace(id=1,operands=[])
        with patch('qcs.semantic_probes.time.monotonic',side_effect=lambda:clock[0]), \
             patch('qcs.function_signatures.function_regions',return_value=([(0x1000,0,b'\0'*128,1)],['x86_64'])), \
             patch('qcs.operation_tables.locate',return_value=[]), \
             patch('qcs.guomi.binary_bignum.import_slots',return_value={}), \
             patch('qcs.guomi.binary_semantics.decode',side_effect=instructions), \
             patch('qcs.process.bounded_run',side_effect=AssertionError('No time for worker')):
            scan_probes(self.path,report,3)
        self.assertEqual(report['engine_status']['semantic_probes']['status'],'budget_unavailable')
        self.assertFalse(report['findings'])

    def test_large_unrolled_function_keeps_its_real_entry(self):
        from qcs.semantic_probes import candidate_functions
        with patch('qcs.pointer_paths.unwind_ranges',return_value=[(0x11000,100000),(0x31000,600000)]):
            functions,_=candidate_functions(self.path,[],'x86_64')
        self.assertEqual(functions,[0x11000])

    def test_sm3_split_immediates_only_select_a_worker(self):
        from types import SimpleNamespace
        from qcs.semantic_probes import scan_probes
        constants=(0x4519,0x79cc,0x9d8a,0x7a87)
        instructions=[SimpleNamespace(id=1,operands=[SimpleNamespace(type=2,imm=x)]) for x in constants]
        report=new_report(self.path,'executable')
        with patch('qcs.function_signatures.function_regions',return_value=([(0x1000,0,b'\0'*128,1)],['aarch64'])), \
             patch('qcs.operation_tables.locate',return_value=[]), \
             patch('qcs.guomi.binary_bignum.import_slots',return_value={}), \
             patch('qcs.guomi.binary_semantics.decode',return_value=instructions), \
             patch('qcs.process.bounded_run',return_value={'returncode':0,'limit':None,'output':'[]'}) as run:
            scan_probes(self.path,report,3)
        self.assertEqual(report['findings'],[])
        self.assertEqual(report['engine_status']['semantic_probes']['candidate_algorithms'],['SM3'])
        self.assertTrue(run.called)

    @classmethod
    def setUpClass(cls):
        # A tiny valid ELF fixture assembled from fixed x86-64 instructions;
        # tests need no host compiler and never run the target natively.
        import struct
        cls.temp=tempfile.TemporaryDirectory(dir=ROOT/'build/tmp');cls.directory=Path(cls.temp.name)
        cls.path=cls.directory/'ordinary.so';raw=bytearray(0x3600)
        ident=b'\x7fELF'+bytes([2,1,1])+bytes(9)
        raw[:64]=struct.pack('<16sHHIQQQIHHHHHH',ident,3,62,1,0x11000,64,0x3400,0,64,56,2,64,5,4)
        raw[64:120]=struct.pack('<IIQQQQQQ',1,5,0,0x10000,0x10000,0x2000,0x2000,0x1000)
        raw[120:176]=struct.pack('<IIQQQQQQ',1,6,0x2000,0x12000,0x12000,0x1000,0x1000,0x1000)
        cls.entries={};offset=0x1000
        codes={'ordinary':bytes.fromhex('c60707c3'),'systemcall':bytes.fromhex('0f05c60707c3'),
               'invalid':bytes.fromhex('0f0bc60707c3'),'endless':bytes.fromhex('ebfe')}
        for name,code in codes.items():
            cls.entries[name]=0x10000+offset;raw[offset:offset+len(code)]=code;offset+=32
        for name,opcode,slot in (('forbidden',b'\xff\x15',0x12000),('copy',b'\xff\x25',0x12008)):
            address=0x10000+offset;cls.entries[name]=address
            code=opcode+struct.pack('<i',slot-address-6)+(bytes.fromhex('c60707c3') if name=='forbidden' else b'')
            raw[offset:offset+len(code)]=code;offset+=32
        strings=b'\0forbidden_api\0memcpy\0';raw[0x3000:0x3000+len(strings)]=strings
        symbols=bytes(24)+struct.pack('<IBBHQQ',1,0x12,0,0,0,0)+struct.pack('<IBBHQQ',15,0x12,0,0,0,0)
        raw[0x3100:0x3100+len(symbols)]=symbols
        relocations=struct.pack('<QQq',0x12000,(1<<32)|1,0)+struct.pack('<QQq',0x12008,(2<<32)|1,0)
        raw[0x3200:0x3200+len(relocations)]=relocations
        sections=[(0,0,0,0,0,0,0,0,0,0),(0,3,0,0,0x3000,len(strings),0,0,1,0),
                  (0,11,0,0,0x3100,len(symbols),1,1,8,24),(0,4,0,0,0x3200,len(relocations),2,0,8,24),
                  (0,3,0,0,0x3300,1,0,0,1,0)]
        for i,section in enumerate(sections):raw[0x3400+64*i:0x3440+64*i]=struct.pack('<IIQQQQIIQQ',*section)
        cls.path.write_bytes(raw)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def test_private_memory_copy_and_permission_fault(self):
        m=Machine(self.path,'x86_64');m.reset();m.machine.mem_write(ARENA+100,b'abc')
        m.invoke(self.entries['copy'],[ARENA,ARENA+100,3]);self.assertEqual(bytes(m.machine.mem_read(ARENA,3)),b'abc')
        with self.assertRaises(Declined):m.invoke(self.entries['copy'],[self.entries['ordinary'],ARENA+100,3])
        with self.assertRaises(Declined):m.invoke(self.entries['copy'],[ARENA,0x12345000,3])

    def test_unknown_import_syscall_instruction_fault_and_budget_fail_closed(self):
        for name in ('forbidden','systemcall','invalid','endless'):
            m=Machine(self.path,'x86_64');m.reset()
            with self.assertRaises(Declined,msg=name):m.invoke(self.entries[name],[ARENA],instructions=1000,milliseconds=5)
            self.assertEqual(bytes(m.machine.mem_read(ARENA,1)),b'\0',name)
        m=Machine(self.path,'x86_64');m.reset()
        with self.assertRaises(Declined):m.invoke(self.entries['ordinary'],[0x12345000])

    def test_aborted_backend_is_replaced_before_next_candidate(self):
        m=Machine(self.path,'x86_64');m.reset();original=m.machine
        with self.assertRaises(Declined):m.invoke(self.entries['ordinary'],[0x12345000])
        self.assertTrue(m.poisoned)
        with self.assertRaisesRegex(Declined,'fresh candidate reset'):
            m.invoke(self.entries['ordinary'],[ARENA])
        m.reset()
        self.assertIsNot(m.machine,original)
        self.assertFalse(m.poisoned)
        m.invoke(self.entries['ordinary'],[ARENA])
        self.assertEqual(bytes(m.machine.mem_read(ARENA,1)),b'\x07')

    def test_real_isolated_worker_runs_with_address_space_limit(self):
        from qcs.process import bounded_run
        import os
        env=dict(os.environ,PYTHONPATH=os.pathsep.join(str(p) for p in sys.path if p))
        result=bounded_run([sys.executable,'-m','qcs.semantic_probes','--worker',str(self.path),'x86_64','AES','.2'],
                           timeout=3,env=env)
        self.assertEqual(result['returncode'],0,result)
        self.assertEqual(result['output'].strip(),'[]')

    def test_failed_worker_never_emits_a_witness(self):
        from qcs.semantic_probes import scan_probes
        from qcs.operation_tables import DES_S
        report=new_report(self.path,'executable')
        with patch('qcs.function_signatures.function_regions',return_value=([(0x1000,0,b'\0'*512,0)],['mips_be'])), \
             patch('qcs.operation_tables.locate',return_value=[{'kind':'des_s'}]), \
             patch('qcs.guomi.binary_bignum.import_slots',return_value={}), \
             patch('qcs.process.bounded_run',return_value={'returncode':-11,'limit':None,'output':'[{"algorithm":"DES"}]'}):
            scan_probes(self.path,report,3)
        self.assertEqual(report['findings'],[])
        self.assertEqual(report['engine_status']['semantic_probes']['status'],'backend_declined')
        self.assertEqual(report['scan_status'],'partial')

    def test_optional_budget_abstention_is_distinct_from_backend_crash(self):
        from qcs.semantic_probes import scan_probes
        report=new_report(self.path,'executable')
        with patch('qcs.function_signatures.function_regions',return_value=([(0x1000,0,b'\0'*512,0)],['mips_be'])), \
             patch('qcs.operation_tables.locate',return_value=[{'kind':'des_s'}]), \
             patch('qcs.guomi.binary_bignum.import_slots',return_value={}), \
             patch('qcs.process.bounded_run',return_value={'returncode':-9,'limit':'timeout','output':'[{"algorithm":"DES"}]'}):
            scan_probes(self.path,report,3)
        self.assertEqual(report['findings'],[])
        self.assertEqual(report['engine_status']['semantic_probes']['status'],'budget_exhausted')
        self.assertEqual(len(report['engine_status']['semantic_probes']['budget_declined']),1)
        self.assertEqual(report['scan_status'],'completed')
        self.assertFalse(report['errors'])

    def test_no_optional_time_skips_all_elf_preparation(self):
        from qcs.semantic_probes import scan_probes
        report=new_report(self.path,'executable')
        with patch('qcs.function_signatures.function_regions',side_effect=AssertionError('No time for preparation')):
            scan_probes(self.path,report,.001)
        self.assertEqual(report['findings'],[])
        self.assertEqual(report['engine_status']['semantic_probes']['status'],'budget_unavailable')

if __name__=='__main__':unittest.main()
