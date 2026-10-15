"""Bounded, name-independent 32-bit XOR/rotate expressions.

These are local data-flow witnesses, not a general symbolic executor. Unknown
operations create new values; no values are propagated across control-flow joins.
"""
from collections import defaultdict

MASK = 0xffffffff
PATTERNS = {'sm3_p0': (0, 9, 17), 'sm3_p1': (0, 15, 23),
            'sm4_l': (0, 2, 10, 18, 24), 'sm4_key_l': (0, 13, 23),
            'sha256_big0': (30, 19, 10), 'sha256_big1': (26, 21, 7)}


def leaf(identity):
    return ('lin', frozenset({(identity, 0)}))


@__import__('functools').lru_cache(maxsize=512)
def canonical(value):
    """Recover a rotate/XOR polynomial only when all 32 bit equations agree.

    Split shifts, SHLD and bitwise masks can produce the same full-width value
    as ROL. Partial words and logical shifts must remain bit expressions.
    """
    if value[0]!='bits':return value
    if any(len(atoms)>64 for atoms in value[1]):return value
    terms=frozenset((identity,(-bit)%32) for identity,bit in value[1][0])
    if all(atoms==frozenset((identity,(out-rotation)%32) for identity,rotation in terms)
           for out,atoms in enumerate(value[1])):
        return ('lin',terms)
    return value


def rotate(value, count):
    if value[0]=='bits':
        return canonical(('bits',tuple(value[1][(i-count)%32] for i in range(32))))
    if value[0] != 'lin':
        return ('rot', value, count % 32)
    return ('lin', frozenset((v, (r + count) % 32) for v, r in value[1]))


def xor(a, b):
    if a[0]=='shift' or b[0]=='shift':
        aa,bb=bits(a),bits(b)
        if aa is not None and bb is not None:
            return xor(('bits',aa),('bits',bb))
    if 'bits' in {a[0],b[0]}:
        aa,bb=bits(a),bits(b)
        if aa is not None and bb is not None:
            result=tuple(x^y for x,y in zip(aa,bb))
            if all(len(x)<=64 for x in result):return canonical(('bits',result))
        return ('unknown',)
    if a[0] == b[0] == 'lin' and len(a[1]) + len(b[1]) <= 64:
        return ('lin', a[1] ^ b[1])
    return ('unknown',)


def shift(value, direction, count):
    if value[0]=='bits' and 0<=count<32:
        return ('bits',tuple(value[1][i-count] if i>=count else frozenset() for i in range(32))) if direction=='left' else ('bits',tuple(value[1][i+count] if i+count<32 else frozenset() for i in range(32)))
    return ('shift', value, direction, count) if 0 < count < 32 else ('unknown',)


def merge_shifts(a, b):
    if a[0] == b[0] == 'shift' and a[1] == b[1] and a[2] != b[2] and a[3] + b[3] == 32:
        return rotate(a[1], a[3] if a[2] == 'left' else b[3])
    if 'bits' in {a[0],b[0]}:
        aa,bb=bits(a),bits(b)
        if aa is not None and bb is not None and all(not x or not y or x==y for x,y in zip(aa,bb)):
            return canonical(('bits',tuple(x|y for x,y in zip(aa,bb))))
    return ('unknown',)


def bits(value):
    """Exact bounded XOR bits; non-linear OR/addition is never approximated."""
    if value[0]=='bits':return value[1]
    if value[0]=='lin':
        if len(value[1])>16:return None
        return tuple(frozenset((identity,(i-r)%32) for identity,r in value[1]) for i in range(32))
    if value[0]=='shift':
        b=bits(value[1])
        if b is None:return None
        n=value[3]
        return tuple(b[i-n] if i>=n else frozenset() for i in range(32)) if value[2]=='left' else tuple(b[i+n] if i+n<32 else frozenset() for i in range(32))
    return None


def truncate(value,width,start=0):
    b=bits(value)
    return ('bits',tuple(b[i+start] if i<width else frozenset() for i in range(32))) if b is not None else ('unknown',)


@__import__('functools').lru_cache(maxsize=1024)
def roles(value):
    """Match the complete linear transform, allowing reassociation of XOR.

    Match the entire polynomial of an input leaf. Other independent leaves may
    be XORed into the output (as in expanded SM3 message recurrence). Extra
    rotations of the witnessed input are never discarded.
    """
    if value[0]=='bits':
        normalized=canonical(value)
        if normalized[0]=='lin':return roles(normalized)
        contributions=defaultdict(lambda:defaultdict(set))
        for out,atoms in enumerate(value[1]):
            if len(atoms)>64:return []
            for identity,bit in atoms:
                if 'wide' in identity[1]:return []
                contributions[identity][bit].add((out-bit)%32)
        found=[]
        # Small sigmas contain a logical shift, so a rotate-only polynomial
        # cannot establish them. Require all 32 exact output-bit equations.
        for name,rotations,logical in [('sha256_small0',(25,14),3),
                                       ('sha256_small1',(15,13),10)]:
            for identity in contributions:
                if len(contributions[identity])!=32:continue
                if all({bit for ident,bit in value[1][out] if ident==identity} ==
                       ({(out-r)%32 for r in rotations} ^ ({out+logical} if out+logical<32 else set()))
                       for out in range(32)):
                    found.append(name);break
        for name,pattern in PATTERNS.items():
            for bybit in contributions.values():
                if len(bybit)<8:continue
                rs=next(iter(bybit.values()))
                if len(rs)==len(pattern) and all(s==rs for s in bybit.values()) and any(rs=={(p+r-pattern[0])%32 for p in pattern} for r in rs):
                    found.append(name);break
        return found
    if value[0] != 'lin' or not value[1]:
        return []
    grouped = defaultdict(set)
    for identity, rotation in value[1]:
        if isinstance(identity,tuple) and len(identity)>1 and 'wide' in identity[1]:
            return []
        grouped[identity].add(rotation)
    found = []
    if len(grouped)==4 and all(rs=={1} for rs in grouped.values()):
        found.append('sha1_schedule')
    for name, pattern in PATTERNS.items():
        if any(len(rs) == len(pattern) and
               any(rs == {(p + r-pattern[0]) % 32 for p in pattern} for r in rs)
               for rs in grouped.values()):
            found.append(name)
    return found


@__import__('functools').lru_cache(maxsize=1024)
def role_tags(value, role):
    """Tags belong to the input witnessing this role, not neighbouring terms.

    P0(x) XOR P1(y) XOR an unrelated addition must not make x an addition
    output. The same restriction binds SM4's verified S-box to its actual L
    input, including byte-wise partial expressions.
    """
    grouped=defaultdict(set)
    if value[0]=='lin':
        for identity,rotation in value[1]:grouped[identity].add((identity,rotation))
        inputs={identity:('lin',frozenset(terms)) for identity,terms in grouped.items()}
    elif value[0]=='bits':
        identities={identity for atoms in value[1] for identity,_ in atoms}
        inputs={identity:('bits',tuple(frozenset(atom for atom in atoms if atom[0]==identity) for atoms in value[1])) for identity in identities}
    else:return ()
    return tuple(sorted({tag for identity,part in inputs.items() if role in roles(part) for tag in identity[1]}))
