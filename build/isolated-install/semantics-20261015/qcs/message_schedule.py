"""Exact local source message recurrences, including 16-word ring buffers.

Indices are one induction variable plus an integer offset, optionally reduced
modulo 16. Cells are invalidated at unknown calls, writes and control-flow joins.
A recurrence is a bound state-read/write equation, never an algorithm finding by
itself. The existing round/IV/constant evidence is still required.
"""
from .guomi.linear import rotate,shift,xor


def index(node,env,key):
    from .guomi.source_semantics import number,txt
    if node is None:return None
    if node.type=='parenthesized_expression':return index(node.named_children[0],env,key)
    if node.type=='identifier':
        name=key(node);return (name,env.get(name),0,None)
    if node.type=='binary_expression':
        a=node.child_by_field_name('left');b=node.child_by_field_name('right')
        operator=txt(node.child_by_field_name('operator'));n=number(txt(b))
        value=index(a,env,key)
        if value is None or n is None:return None
        name,version,delta,mod=value
        if operator in {'+','-'} and mod is None:return name,version,delta+(n if operator=='+' else -n),None
        if (operator=='&' and n==15) or (operator=='%' and n==16):return name,version,delta%16,16
    return None


class Schedules:
    def __init__(self,arithmetic):
        self.arithmetic=arithmetic;self.cells={}
    def reset(self):self.cells.clear()
    def read(self,base,at,fallback):
        if at is None:return fallback
        if len(self.cells)>4096:self.reset()
        return self.cells.setdefault((base,at),fallback)
    def additions(self,value,depth=0):
        if depth>5:return [value]
        if value[0]=='lin' and len(value[1])==1:
            identity,rotation=next(iter(value[1]))
            if rotation==0 and identity in self.arithmetic.sums:
                a,b=self.arithmetic.sums[identity]
                return self.additions(a,depth+1)+self.additions(b,depth+1)
        return [value]
    def store(self,base,at,value):
        if at is None:
            self.reset();return []
        name,version,delta,mod=at
        def prior(offset):
            d=delta+offset
            if mod:d%=mod
            return self.cells.get((base,(name,version,d,mod)))
        result=[]
        words=[prior(n) for n in [-16,-7,-15,-2]]
        if all(v is not None for v in words):
            a,b,c,d=words
            small0=xor(xor(rotate(c,-7),rotate(c,-18)),shift(c,'right',3))
            small1=xor(xor(rotate(d,-17),rotate(d,-19)),shift(d,'right',10))
            if sorted(map(repr,self.additions(value)))==sorted(map(repr,[a,b,small0,small1])):
                result.append(('sha256_schedule',('state',base,'ring_words',mod,'offsets',-16,-7,-15,-2)))
        words=[prior(n) for n in [-3,-8,-14,-16]]
        if all(v is not None for v in words):
            expected=rotate(xor(xor(words[0],words[1]),xor(words[2],words[3])),1)
            if value==expected:result.append(('sha1_bound_schedule',('state',base,'ring_words',mod)))
        words=[prior(n) for n in [-16,-9,-3,-13,-6]]
        if all(v is not None for v in words):
            a,b,c,d,e=words;inside=xor(xor(a,b),rotate(c,15))
            expected=xor(xor(xor(xor(inside,rotate(inside,15)),rotate(inside,23)),rotate(d,7)),e)
            if value==expected:result.append(('sm3_bound_schedule',('state',base,'ring_words',mod)))
        # A write through another source pointer may alias every old cell.
        self.cells={k:v for k,v in self.cells.items() if k[0]==base}
        self.cells[base,at]=value
        return result
