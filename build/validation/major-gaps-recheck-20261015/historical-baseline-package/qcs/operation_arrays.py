"""Bounded RC4 PRGA array/data-flow witness, independent of identifiers.

A swap alone is insufficient. We require byte-bounded index recurrences, a
swap of their two state entries, and a dependent state lookup XORed with input.
Unknown aliasing writes invalidate cached cells; nothing crosses CFG joins.
"""
from .guomi.linear import bits


class Arrays:
    def __init__(self,arithmetic):
        self.arithmetic=arithmetic
        self.loads={};self.cells={};self.stores=[];self.swaps=[];self.masks={};self.outputs=set()
    def reset(self):
        self.cells.clear();self.stores.clear();self.swaps.clear();self.outputs.clear();self.loads.clear()
    def mask(self,out,value,width):
        if width==8:self.masks[out]=value
    def byte_value(self,value):
        if value in self.masks:return self.masks[value]
        if value[0]=='bits':
            b=value[1]
            if not any(b[8:]) and len(b[0])==1:
                identity,bit=next(iter(b[0]))
                if bit==0 and all(b[i]==frozenset({(identity,i)}) for i in range(8)):
                    return ('lin',frozenset({(identity,0)}))
        return None
    def add_inputs(self,value):
        if value[0]=='lin' and len(value[1])==1:
            identity,r=next(iter(value[1]))
            if not r:return self.arithmetic.sums.get(identity)
        return None
    def bounded_sum(self,value):
        original=self.byte_value(value)
        return self.add_inputs(original) if original is not None else None
    def load(self,base,index,value,site):
        if len(self.loads)>12000:
            self.loads.clear();self.reset();self.outputs.clear();self.masks.clear()
        key=(base,index)
        if key in self.cells:return self.cells[key]
        self.loads[value]=(base,index,site)
        self.cells[key]=value
        terms=self.bounded_sum(index)
        if terms:
            left,right=terms
            for b,i,j,x,y,p in self.swaps[-32:]:
                if base!=b or site<p or {left,right}!={x,y}:continue
                self.outputs.add(value)
        return value
    def output(self,value):
        # A byte output store may truncate a previously full-width table read.
        return value in self.outputs or self.byte_value(value) in self.outputs
    def store(self,base,index,value,site):
        loaded=self.loads.get(value)
        if loaded and loaded[0]==base and loaded[1]!=index:
            other=loaded[1]
            before=self.cells.get((base,index))
            # After the first write, its old value survives in a temporary.
            for old in self.stores[-32:]:
                b,i,j,x,y,p=old
                if b==base and i==other and j==index and value==x and site>=p:
                    # x was loaded at i; y was loaded at j. Verify that i is
                    # incremented modulo 256, and j adds that state value.
                    for ii,jj,xx in [(i,j,x),(j,i,y)]:
                        first=self.bounded_sum(ii);second=self.bounded_sum(jj)
                        if first and ('constant',1) in first and second and xx in second:
                            self.swaps.append((base,i,j,x,y,site));break
            if before is not None and self.loads.get(before,(None,None))[:2]==(base,index):
                self.stores.append((base,index,other,before,value,site))
        # A write through another pointer might alias this state.
        self.cells={k:v for k,v in self.cells.items() if k[0]==base}
        self.stores=[s for s in self.stores if s[0]==base]
        self.swaps=[s for s in self.swaps if s[0]==base]
        self.cells[(base,index)]=value
        if len(self.stores)>96:self.stores=self.stores[-48:]
    def xor(self,a,b):
        return any(self.output(v) for v in (a,b)) and a!=b
