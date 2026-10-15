"""Algorithm constants derived from public standards, never sample hashes.

RFC 1321, FIPS 180-4, FIPS 197 and FIPS 46-3. DES table variants are
permutations of the standard substitution/permutation, including endian and
bit numbering conventions. An unused table never establishes an algorithm.
"""
from functools import lru_cache
import math

SHA256_K = tuple(int(x,16) for x in '''428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5 d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174 e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da 983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967 27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85 a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070 19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3 748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2'''.split())
SHA256_IV = (0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19)
SHA1_K = (0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xca62c1d6)
MD5_K = tuple(int(abs(math.sin(i+1))*2**32) for i in range(64))
DES_S = (
(14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13),
(15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9),
(10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12),
(7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14),
(2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3),
(12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13),
(4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12),
(13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11))
DES_P = (16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25)


def rol(x,n):
    n %= 32
    return ((x<<n)|(x>>(32-n)))&0xffffffff


def gf(a,b):
    result=0
    while b:
        if b&1:result^=a
        a=(a<<1)^ (0x11b if a&128 else 0);b>>=1
    return result


@lru_cache(maxsize=1)
def numeric_tables():
    tables=[('sha256_k',SHA256_K),('sha256_iv',SHA256_IV),('sha1_k',SHA1_K),('md5_k',MD5_K)]
    sbox=[]
    for x in range(256):
        y=0 if not x else next(v for v in range(1,256) if gf(x,v)==1)
        z=y
        for n in range(1,5):z^=((y<<n)|(y>>(8-n)))&255
        sbox.append(z^0x63)
    inv=[sbox.index(i) for i in range(256)]
    tables.extend([('aes_sbox',tuple(sbox)),('aes_sbox',tuple(inv))])
    for box,inverse in [(sbox,False),(inv,True)]:
        raw=[(gf(x,14)<<24)|(gf(x,9)<<16)|(gf(x,13)<<8)|gf(x,11) if inverse
             else (gf(x,2)<<24)|(x<<16)|(x<<8)|gf(x,3) for x in box]
        for n in (0,8,16,24):tables.append(('aes_t',tuple(rol(x,n) for x in raw)))
    # Packed SP boxes differ in bit numbering (32 rotations) and six-bit
    # input convention (identity or reversal). They remain exact full maps.
    for box,s in enumerate(DES_S):
        tables.append(('des_s',s))
        for reverse in (False,True):
            values=[]
            for i in range(64):
                j=int(f'{i:06b}'[::-1],2) if reverse else i
                row=((j>>4)&2)|(j&1);col=(j>>1)&15
                value=s[16*row+col] << (28-4*box)
                out=sum(((value>>(32-p))&1)<<(31-k) for k,p in enumerate(DES_P))
                values.append(out)
            for n in range(32):tables.append(('des_sp',tuple(rol(x,n) for x in values)))
    return tuple(tables)


@lru_cache(maxsize=1)
def byte_tables():
    result=[]
    for rotation in (8,16,24):
        raw=bytes(4*lane+(byte-rotation//8)%4 for lane in range(4) for byte in range(4))
        result.append(('lane_rotate_'+str(rotation),raw))
    for kind,values in numeric_tables():
        if max(values)<=255:result.append((kind,bytes(values)))
        for endian in ('little','big'):
            result.append((kind,b''.join(v.to_bytes(4,endian) for v in values)))
    # The IV discriminates SHA-256 from SHA-224 (shared compression).
    for endian in ('little','big'):
        result.append(('sha256_iv',b''.join(v.to_bytes(4,endian) for v in SHA256_IV)))
        for start in (0,4):
            result.append(('sha256_iv_'+str(start//4),b''.join(v.to_bytes(4,endian) for v in SHA256_IV[start:start+4])))
    return tuple(result)


def locate(regions):
    found=[]
    for base,offset,data,flags in regions:
        if flags&1 or not isinstance(data,bytes):continue
        for kind,raw in byte_tables():
            start=0
            while (at:=data.find(raw,start))>=0:
                found.append({'kind':kind,'address':base+at,'offset':offset+at,'length':len(raw)})
                start=at+len(raw)
    return found
