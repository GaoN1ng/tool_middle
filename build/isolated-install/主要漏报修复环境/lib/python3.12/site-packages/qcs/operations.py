"""Shared bounded operation witnesses for conventional cryptography.

These classify related operations and actual constant-table accesses, never
function names, source hashes or a global opcode histogram. Source definitions
and bounded binary neighbourhoods retain an explicit, reviewable witness.
"""
from collections import Counter
from bisect import bisect_left,bisect_right
from .operation_tables import MD5_K,SHA1_K,SHA256_K,SHA256_IV
from .guomi.linear import xor,rotate
from .model import evidence


class Arithmetic:
    """Remember exact addition inputs behind linear-expression leaves.

    Keeping non-linear additions as separate leaves preserves XOR algebra.
    The bounded DAG lets us check the complete ChaCha quarter round rather
    than merely looking for four frequently used rotation counts.
    """
    def __init__(self):
        self.sums={}
        self.index_forms={}
        from .sha256_rounds import RoundEquations
        self.rounds=RoundEquations(self)
    def add(self,a,b,out):
        self.index_operation('add',a,b,out)
        if out[0]=='lin' and len(out[1])==1:
            identity,r=next(iter(out[1]))
            if not r:
                if len(self.sums)>=16000:self.sums.clear()
                self.sums[identity]=(a,b)
    def index(self,value,depth=0):
        if depth>8:return None
        if value[0]=='constant':return ((),value[1])
        if value[0]!='lin' or len(value[1])!=1:return None
        identity,r=next(iter(value[1]))
        if r:return None
        return self.index_forms.get(identity,(((identity,1),),0))
    def index_operation(self,op,a,b,out):
        if out in (a,b) or out[0]!='lin' or len(out[1])!=1:return
        identity,r=next(iter(out[1]))
        if r:return
        x,y=self.index(a),self.index(b)
        if x is None or y is None:return
        if op in {'add','sub'}:
            terms=dict(x[0]);sign=-1 if op=='sub' else 1
            for key,n in y[0]:terms[key]=terms.get(key,0)+sign*n
            terms={k:n for k,n in terms.items() if n}
            constant=x[1]+sign*y[1]
        elif op=='mul' and not y[0] and abs(y[1])<=16:
            terms={k:n*y[1] for k,n in x[0]};constant=x[1]*y[1]
        else:return
        if len(terms)>4 or any(abs(n)>64 for n in terms.values()) or abs(constant)>65536:return
        if len(self.index_forms)>=16000:self.index_forms.clear()
        self.index_forms[identity]=(tuple(sorted(terms.items(),key=lambda kv:repr(kv[0]))),constant)
    def split_rotation(self,value,n):
        unrot=rotate(value,-n)
        if unrot[0]!='lin':return []
        result=[]
        for identity,r in unrot[1]:
            if r==0 and identity in self.sums:
                atom=('lin',frozenset({(identity,0)}))
                result.append((atom,self.sums[identity],xor(unrot,atom)))
        return result
    def quarter(self,value):
        if value[0]!='lin' or any('wide' in identity[1] for identity,_ in value[1]):return False
        # b'=ROL7(b1 XOR (c1+d1)), d1=ROL8(d0 XOR (a0+b1)),
        # b1=ROL12(b0 XOR (c0+d0)), d0=ROL16(d XOR (a+b)).
        for _,(c1,d1),b1 in self.split_rotation(value,7):
            for C,D in [(c1,d1),(d1,c1)]:
                for _,(aa,bb),d0 in self.split_rotation(D,8):
                    if b1 not in (aa,bb):continue
                    a1=bb if aa==b1 else aa
                    for c_atom,(cc,dd),b0 in self.split_rotation(b1,12):
                        if C!=c_atom or d0 not in (cc,dd):continue
                        for initial_add,(a0,b),original_d in self.split_rotation(d0,16):
                            if b0 not in (a0,b):continue
                            if a1==initial_add:return True
        return False


def recognize(events,*,sha256_variant=False):
    """One source definition or bounded binary neighbourhood, no names."""
    count=Counter(r for _,r,_ in events)
    rotations={v for _,r,v in events if r=='rotate'}
    constants={v&0xffffffff for _,r,v in events if r in {'immediate','constant'} and isinstance(v,int)}
    reads=Counter(v for _,r,v in events if r=='table_read')
    isa={v for _,r,v in events if r=='crypto_instruction'}
    result=[]
    def matched(algorithm,reason,roles):
        relevant=[e for e in events if e[1] in roles]
        result.append((algorithm,min((e[0] for e in relevant),default=0),relevant[:128],reason))
    if count['chacha_quarter']:
        matched('ChaCha20','Exact dependent add/XOR/rotate quarter round (16,12,8,7)',{'chacha_quarter'})
    if count['rc4_prga']:
        matched('RC4','Byte-bounded index recurrence, dependent state swap and state-sum lookup used as keystream or XORed with input',{'rc4_prga'})
    sha_sigma={'sha256_big0','sha256_big1','sha256_small0','sha256_small1'}
    sha_schedule=(sha_sigma<=set(count) or count['sha256_round'] or
                  ({'sha256_big0','sha256_big1'}<=set(count) and count['sha256_schedule']))
    if (sha256_variant and sha_schedule and count['add']>=8 and count['and']>=2
            and (reads['sha256_k'] or len(constants&set(SHA256_K))>=8)):
        matched('SHA-256','SHA-256 sigma/schedule or bound T1+T2 Ch/Maj equation, used K values and SHA-256 IV',sha_sigma|{'sha256_round','sha256_schedule','table_read','constant','immediate'})
    if (count['add']>=16 and count['and']>=2 and len(rotations&{7,12,17,22,5,9,14,20,4,11,16,23,6,10,15,21})>=8
            and (reads['md5_k'] or len(constants&set(MD5_K))>=16)):
        matched('MD5','MD5 sine-derived round constants used with addition, Boolean operations and rotation schedule',{'rotate','table_read','constant','immediate'})
    if ({5,30}<=rotations and count['sha1_schedule'] and count['add']>=8 and count['xor']>=8
            and count['and']>=2 and (len(constants&set(SHA1_K))>=3 or reads['sha1_k'])):
        matched('SHA-1','Four-word XOR/ROL1 message recurrence, round rotations 5/30 and three distinct round constants',{'sha1_schedule','rotate','constant','immediate'})
    if ((reads['aes_t']>=4 or reads['aes_sbox']>=4) and count['xor']>=4 and
        (count['and']>=2 or (reads['aes_sbox']>=8 and count['xor']>=8))):
        matched('AES','Complete standard AES substitution or T tables actually read by masked XOR round operations',{'table_read','xor','and'})
    if ((reads['des_sp']>=4 or reads['des_s']>=4) and count['xor']>=4 and count['and']>=4):
        matched('DES','Complete standard DES substitution/permutation tables read by six-bit indexed XOR round operations',{'table_read','xor','and'})
    if ({'aesenc','aesenclast'}<=isa or {'aesdec','aesdeclast'}<=isa or {'aese','aesmc'}<=isa or {'aesd','aesimc'}<=isa):
        matched('AES','Decoded AES round and final/mix operation families',{'crypto_instruction'})
    if sha256_variant and ({'sha256rnds2','sha256msg1','sha256msg2'}<=isa or {'sha256h','sha256h2','sha256su0','sha256su1'}<=isa):
        matched('SHA-256','Decoded SHA-256 round and schedule instruction families with SHA-256 IV',{'crypto_instruction'})
    if {'sha1c','sha1p','sha1m','sha1h','sha1su0','sha1su1'}<=isa:
        matched('SHA-1','Decoded SHA-1 schedule and all round instruction families',{'crypto_instruction'})
    return result


def binary_findings(events,tables):
    # One bounded code region around an algorithm-specific event. Identical
    # anchors are bucketed; unrelated far-away functions are never combined.
    events=sorted(set((a,r,tuple(v) if isinstance(v,list) else v) for a,r,v in events),key=lambda e:e[0])
    positions=[e[0] for e in events];found={};examined=set()
    reads={v for _,r,v in events if r=='table_read'}
    iv=('sha256_iv' in reads or {'sha256_iv_0','sha256_iv_1'}<=reads or
        set(SHA256_IV)<={v for _,r,v in events if r=='iv_store'})
    anchors={'sha256_big0','sha256_big1','sha1_schedule','chacha_quarter','rc4_prga','table_read','crypto_instruction'}
    for address,role,value in events:
        if role not in anchors and not (role in {'immediate','constant'} and value in MD5_K):continue
        bucket=address//4096
        if bucket in examined:continue
        examined.add(bucket);start=max(0,address-32768)
        nearby=events[bisect_left(positions,start):bisect_right(positions,address+65536)]
        for item in recognize(nearby,sha256_variant=iv):found.setdefault(item[0],item)
    return list(found.values())


def emit(report,matches,engine,*,source=False,code=None,domain=None,regions=()):
    seen=set()
    for algorithm,offset,events,reason in matches:
        if algorithm in seen:continue
        seen.add(algorithm)
        details=[{'offset' if source else 'address':a,'role':r,'detail':v} for a,r,v in events]
        extra={'offset':offset,'operation_witnesses':details,'implementation_verification':'bounded_standard_operation_graph'}
        if source:extra.update(line=code[:offset].count(b'\n')+1,source_role='definition',offset_basis='lexed_utf8_source')
        else:
            extra.update(virtual_address=offset,architecture=domain,offset=next((off+offset-base for base,off,data,flags in regions if flags&1 and base<=offset<base+len(data)),None))
        report['findings'].append(evidence(algorithm,engine,'source_operation_graph' if source else 'binary_instruction',
            'standard_operation_graph',confidence='medium',confidence_reason=reason,**extra))
    return seen


def reconcile_shared_sha1(report):
    """A SHA-1 IV is shared with other hashes; retain it as a clue alone."""
    supported=any(f['algorithm']=='SHA-1' and
        not (f['engine']=='yara' and f['identifier']=='SHA1_Constants')
        for f in report['findings'])
    if supported:return
    retained=[]
    for item in report['findings']:
        if item['engine']=='yara' and item['identifier']=='SHA1_Constants':
            item.update(algorithm=None,algorithm_category='unknown',candidate_algorithms=['SHA-1','RIPEMD-160','HAS-160'],
                confidence='low',confidence_reason='Shared IV/round constants lack SHA-1-specific computation evidence')
            report['clues'].append(item)
        else:retained.append(item)
    report['findings']=retained
