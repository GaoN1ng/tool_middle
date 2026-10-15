"""Exact Montgomery differential-add/double over documented field APIs.

API identifiers supply field arithmetic only. The classifier requires all four
dependent projective equations, the 121665/121666 constant, a bound input point,
and inversion/multiplication/serialization of the resulting x coordinate.
"""
from .guomi.bignum import Value

FIELD_APIS={'fe25519_add':'add','fe25519_sub':'sub','fe25519_mul':'mul',
            'fe25519_sq':'square','fe25519_mul121666':'a24',
            'fe25519_inv':'inverse','fe25519_frombytes':'decode',
            'fe25519_tobytes':'encode','fe_copy':'copy','fe_0':'zero','fe_1':'one',
            'fe_cswap':'swap'}


class Ladder:
    def __init__(self):
        self.values={};self.inputs={};self.swaps=[];self.rounds=[];self.history=[]
        self.serial=0;self.matches=[];self.inverse_sources={};self.normalized={}

    def value(self,key):
        if key not in self.values:self.values[key]=Value.symbol(key+'@'+str(self.serial))
        return self.values[key]

    def clobber(self,args):
        # Unknown/local-shadowed calls may overwrite any state buffer passed
        # to them. Do not retain a completed round or a cached inverse across
        # such a write, even if the subsequent API call reuses the same name.
        if set(args)&(self.values.keys()|self.inputs.keys()|self.normalized.keys()):
            self.values.clear();self.inputs.clear();self.swaps.clear();self.rounds.clear()
            self.inverse_sources.clear();self.normalized.clear();self.candidate=None

    def feed(self,name,args,site):
        op=FIELD_APIS.get(name)
        if op is None:return False
        self.history.append({'operation':name,'arguments':args,'offset':site})
        if len(self.history)>128:self.history=self.history[-128:]
        if op=='swap' and len(args)>=3:
            a,b=args[:2];self.swaps.append((a,b,site))
            if len(self.swaps)%2==0:
                # Symbolic loop-header states; the same four buffers must be
                # written by a complete round before final normalization.
                self.serial+=1
                previous=self.swaps[-2:];keys=[k for pair in previous for k in pair[:2]]
                if len(set(keys))==4:
                    for k in keys:self.values[k]=Value.symbol(k+'@'+str(self.serial))
                    self.candidate=(tuple(keys),{k:self.values[k] for k in keys},site)
            return True
        if not args:return True
        dst=args[0]
        if op!='encode':
            self.normalized.pop(dst,None)
            self.inverse_sources.pop(dst,None)
        try:
            if op=='decode' and len(args)>=2:
                self.values[dst]=Value.symbol('peer-coordinate:'+args[1]);self.inputs[dst]=self.values[dst]
            elif op in {'zero','one'}:self.values[dst]=Value.constant(op=='one')
            elif op=='copy' and len(args)>=2:self.values[dst]=self.value(args[1])
            elif op in {'add','sub','mul'} and len(args)>=3:
                value=self.value(args[1]).op(self.value(args[2]),op)
                if op=='mul':
                    for x,z,origin,witness in self.rounds:
                        if z in self.inverse_sources and {args[1],args[2]}=={x,z}:
                            self.normalized[dst]=(value,origin,witness)
                self.values[dst]=value
            elif op=='square' and len(args)>=2:self.values[dst]=self.value(args[1]).op(self.value(args[1]),'mul')
            elif op=='a24' and len(args)>=2:self.values[dst]=self.value(args[1]).op(Value.constant(121666),'mul')
            elif op=='inverse' and len(args)>=2:
                old=self.value(args[1]);self.values[dst]=old.inverse('2^255-19')
                self.inverse_sources[dst]=old
            elif op=='encode' and len(args)>=2:
                value=self.value(args[1])
                if args[1] in self.normalized:
                    expected,origin,witness=self.normalized[args[1]]
                    if value.equal(expected):
                        self.matches.append({'algorithm':'ECDH','equation':'Montgomery ladder X/Z differential-add/double; x=X*Z^-1 serialized',
                            'offset':origin,'kind':'montgomery_ladder','modulus':'2^255-19',
                            'operation_witnesses':witness+self.history[-16:]})
            candidate=getattr(self,'candidate',None)
            if candidate and op in {'mul','square'}:
                keys,initial,origin=candidate;x2,x3,z2,z3=keys
                X,Z,Y,T=[initial[k] for k in (x2,z2,x3,z3)]
                A=X.op(Z,'add');B=X.op(Z,'sub');AA=A.op(A,'mul');BB=B.op(B,'mul');E=AA.op(BB,'sub')
                DA=Y.op(T,'sub').op(A,'mul');CB=Y.op(T,'add').op(B,'mul')
                plus=DA.op(CB,'add');minus=DA.op(CB,'sub')
                expected_x2=AA.op(BB,'mul')
                expected_z2=E.op(BB.op(E.op(Value.constant(121666),'mul'),'add'),'mul')
                for peer in self.inputs.values():
                    checks=[(x2,expected_x2),(z2,expected_z2),(x3,plus.op(plus,'mul')),
                            (z3,peer.op(minus.op(minus,'mul'),'mul'))]
                    if all(self.value(k).equal(v) for k,v in checks):
                        self.rounds.append((x2,z2,origin,list(self.history)))
                        self.candidate=None;break
        except ValueError:
            self.values[dst]=Value.symbol('unknown@'+str(site))
        return True
