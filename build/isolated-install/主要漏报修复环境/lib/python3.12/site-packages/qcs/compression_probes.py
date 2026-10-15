"""Independent SM3/SHA-1 single-block reference and finite ABI probes.

Arbitrary chaining states distinguish the complete compression mapping from
constant output or a shared IV. Three distinct state/block inputs are required.
No algorithm identification is based on a candidate spelling or its file path.
"""
import hashlib
import time

MASK=(1<<32)-1

def rol(v,n):
    n%=32
    return ((v<<n)|(v>>(32-n)))&MASK

def compress(algorithm,state,block):
    w=[int.from_bytes(block[i:i+4],'big') for i in range(0,64,4)]
    if algorithm=='SHA-1':
        for i in range(16,80):w.append(rol(w[i-3]^w[i-8]^w[i-14]^w[i-16],1))
        a,b,c,d,e=state
        for i in range(80):
            f=((b&c)|((~b)&d)) if i<20 else (b^c^d) if i<40 or i>=60 else ((b&c)|(b&d)|(c&d))
            t=(rol(a,5)+f+e+w[i]+(0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xca62c1d6)[i//20])&MASK
            a,b,c,d,e=t,a,rol(b,30),c,d
        return [(x+y)&MASK for x,y in zip(state,(a,b,c,d,e))]
    if algorithm!='SM3':raise ValueError('Unsupported compression reference')
    def p1(x):return x^rol(x,15)^rol(x,23)
    for i in range(16,68):w.append(p1(w[i-16]^w[i-9]^rol(w[i-3],15))^rol(w[i-13],7)^w[i-6])
    a,b,c,d,e,f,g,h=state
    for i in range(64):
        ss1=rol((rol(a,12)+e+rol(0x79cc4519 if i<16 else 0x7a879d8a,i))&MASK,7);ss2=ss1^rol(a,12)
        ff=(a^b^c) if i<16 else ((a&b)|(a&c)|(b&c))
        gg=(e^f^g) if i<16 else ((e&f)|((~e)&g))
        tt1=(ff+d+ss2+(w[i]^w[i+4]))&MASK;tt2=(gg+h+ss1+w[i])&MASK
        a,b,c,d,e,f,g,h=tt1,a,rol(b,9),c,tt2^rol(tt2,9)^rol(tt2,17),e,rol(f,19),g
    return [x^y for x,y in zip(state,(a,b,c,d,e,f,g,h))]

def vectors(algorithm):
    words=8 if algorithm=='SM3' else 5;result=[]
    for index in range(3):
        raw=hashlib.sha256(('qcs-compression-state-'+str(index)).encode()).digest()
        state=[int.from_bytes(raw[i:i+4],'big') for i in range(0,words*4,4)]
        block=hashlib.sha512(('qcs-compression-block-'+str(index)).encode()).digest()
        result.append((state,block,compress(algorithm,state,block)))
    return result

def probe(machine,functions,algorithm,deadline):
    from .semantic_probes import Declined,ARENA
    cases=vectors(algorithm);statebuf,blockbuf=ARENA+0x4000,ARENA+0x1000
    for address in functions:
        if time.monotonic()>deadline:break
        # Contexts commonly put a byte counter before the chaining words.
        # Offsets select call hypotheses only. Every word must match on all
        # inputs; unrelated context words are not accepted as output.
        for offset in (0,8,16):
            if time.monotonic()>deadline:break
            try:
                for state,block,expected in cases:
                    machine.reset()
                    machine.machine.mem_write(statebuf+offset,b''.join(x.to_bytes(4,machine.endian) for x in state))
                    machine.machine.mem_write(blockbuf,block)
                    machine.invoke(address,[statebuf,blockbuf,1],instructions=3000000,milliseconds=120)
                    output=bytes(machine.machine.mem_read(statebuf+offset,len(expected)*4))
                    if output!=b''.join(x.to_bytes(4,machine.endian) for x in expected):raise Declined('Compression output mismatch')
                    if bytes(machine.machine.mem_read(blockbuf,64))!=block:raise Declined('Compression changed const block')
                return [{'algorithm':algorithm,'address':address,'vectors':3,'state_offset':offset,
                    'relation':'Complete compression mapping on three distinct arbitrary chaining states and 64-byte messages, including state feedback and unchanged input',
                    'modeled_imports':sorted(set(machine.model_calls))}]
            except Declined:continue
    return []
