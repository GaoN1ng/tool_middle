"""Bounded big-number equations over documented generic arithmetic APIs.

Identifiers select an API's argument convention, never an algorithm. A match
requires related values, one modulus and the SM2 equation. Polynomial fractions
permit reordered products and multiplicative blinding without guessing variable
names. This is successful-operation-path evidence, not a control-flow proof.
"""
from dataclasses import dataclass

MAX_TERMS = 96
OBSERVERS={'BN_is_zero','BN_is_negative','BN_set_flags','bn_set_top_fixed','bn_get_top',
           'bn_get_words','mp_iszero','sp_iszero','mp_isneg','sp_isneg',
           'EC_GROUP_get0_order','EC_GROUP_get_mont_data'}
OBSERVERS.update({'nn_check_initialized','nn_iszero','nn_isone','nn_cmp',
                  'nn_export_to_buf','fp_export_to_buf','fp_check_initialized','prj_pt_check_initialized',
                  'prj_pt_unique','prj_pt_iszero','dbg_nn_print','dbg_buf_print'})


def poly_add(a, b, sign=1):
    out = dict(a)
    for m, c in b.items():
        out[m] = out.get(m, 0) + sign*c
        if not out[m]: del out[m]
    if len(out) > MAX_TERMS: raise ValueError('big-number polynomial budget')
    return out


def poly_mul(a, b):
    if len(a)*len(b) > MAX_TERMS*4: raise ValueError('big-number product budget')
    out = {}
    for ma, ca in a.items():
        for mb, cb in b.items():
            m = tuple(sorted(ma+mb))
            if len(m) > 24: raise ValueError('big-number degree budget')
            out[m] = out.get(m, 0)+ca*cb
    out = {m:c for m,c in out.items() if c}
    if len(out)>MAX_TERMS: raise ValueError('big-number polynomial budget')
    return out


@dataclass
class Value:
    num: dict
    den: dict
    moduli: frozenset = frozenset()

    @classmethod
    def symbol(cls, name): return cls({(str(name),):1}, {():1})
    @classmethod
    def constant(cls, n): return cls({():n} if n else {}, {():1})
    def op(self, other, operation, modulus=None):
        mods=self.moduli|other.moduli|(frozenset({str(modulus)}) if modulus else frozenset())
        if operation=='mul': return Value(poly_mul(self.num,other.num),poly_mul(self.den,other.den),mods)
        return Value(poly_add(poly_mul(self.num,other.den),poly_mul(other.num,self.den),
                              -1 if operation=='sub' else 1),poly_mul(self.den,other.den),mods)
    def inverse(self, modulus): return Value(self.den,self.num,self.moduli|{str(modulus)})
    def equal(self, other):
        return bool(self.den and other.den) and poly_mul(self.num,other.den)==poly_mul(other.num,self.den)
    def symbols(self): return {v for m in [*self.num,*self.den] for v in m}
    def atom(self):
        return next(iter(self.num))[0] if self.den=={():1} and len(self.num)==1 and len(next(iter(self.num)))==1 and next(iter(self.num.values()))==1 else None


# (operation, input indices, output index, modulus index). mp/sp conventions
# come from wolfSSL/LibTomMath; BN conventions from OpenSSL's public API.
OPERATIONS = {}
for prefix in ('mp_', 'sp_'):
    for name, op in [('add','add'),('sub','sub'),('mul','mul')]:
        OPERATIONS[prefix+name]=(op,(0,1),2,None)
        OPERATIONS[prefix+name+'_d']=(op,(0,1),2,None)
        for suffix in ('mod','mod_ct'):
            OPERATIONS[prefix+name+suffix]=(op,(0,1),3,2)
    OPERATIONS[prefix+'invmod']=('inv',(0,),2,1)
    OPERATIONS[prefix+'mod']=('copy',(0,),2,1)
    OPERATIONS[prefix+'copy']=('copy',(0,),1,None)
    OPERATIONS[prefix+'set']=('set',(1,),0,None)
    OPERATIONS[prefix+'cmp']=('compare',(0,1),None,None)
for op in ('add','sub','mul'):
    OPERATIONS['BN_'+op]=(op,(1,2),0,None)
    OPERATIONS['BN_mod_'+op]=(op,(1,2),0,3)
for name in ('BN_mod_add_quick','BN_mod_sub_quick'):
    OPERATIONS[name]=('sub' if 'sub' in name else 'add',(1,2),0,3)
OPERATIONS['bn_mod_sub_fixed_top']=('sub',(1,2),0,3)
OPERATIONS.update({'BN_mod_inverse':('inv',(1,),0,2),
                   'BN_copy':('copy',(1,),0,None), 'BN_set_word':('set',(1,),0,None),
                   'BN_add_word':('add',(0,1),0,None), 'BN_cmp':('compare',(0,1),None,None),
                   'BN_nnmod':('copy',(1,),0,2)})
for op in ('add','sub','mul'):
    OPERATIONS['mbedtls_mpi_'+op+'_mpi']=(op,(1,2),0,None)
    if op!='mul':OPERATIONS['mbedtls_mpi_'+op+'_int']=(op,(1,2),0,None)
OPERATIONS.update({'mbedtls_mpi_mod_mpi':('copy',(1,),0,2),
                   'mbedtls_mpi_inv_mod':('inv',(1,),0,2),
                   'mbedtls_mpi_copy':('copy',(1,),0,None),
                   'mbedtls_mpi_lset':('set',(1,),0,None),
                   'mbedtls_mpi_cmp_mpi':('compare',(0,1),None,None)})
for op in ('add','sub','mul'):
    OPERATIONS['nn_'+op]=(op,(1,2),0,None)
    OPERATIONS['nn_mod_'+op]=(op,(1,2),0,3)
OPERATIONS.update({'nn_mod':('copy',(1,),0,2),'nn_modinv':('inv',(1,),0,2),
                   'nn_modinv_fermat':('inv',(1,),0,2),'nn_copy':('copy',(1,),0,None)})
for prefix in ('mpz_','__gmpz_'):
    for op in ('add','sub','mul'):
        OPERATIONS[prefix+op]=(op,(1,2),0,None)
    for suffix in ('mod','fdiv_r','tdiv_r'):
        OPERATIONS[prefix+suffix]=('copy',(1,),0,2)
    OPERATIONS[prefix+'invert']=('inv',(1,),0,2)
    OPERATIONS[prefix+'set']=('copy',(1,),0,None)
    OBSERVERS.update(prefix+suffix for suffix in ('size','sizeinbase','cmp','sgn'))


class Equations:
    def __init__(self, shadowed=()):
        self.shadowed=set(shadowed)
        self.values={}; self.sums=[]; self.ones=[]; self.history=[]; self.matches=[]
        self.points={}; self.coordinates={}; self.inverses=[]
        self.pending_sums={}
        self.group_orders={};self.mont_groups={}

    def get(self, key):
        key=str(key)
        if key in {'BN_value_one()','1','0x1'}: return Value.constant(1)
        if key=='0': return Value.constant(0)
        if key not in self.values: self.values[key]=Value.symbol(key)
        return self.values[key]

    def feed(self, name, args, site):
        if name in self.shadowed:
            for arg in args:
                key=str(arg).lstrip('&')
                if key in self.values:
                    self.values[key]=Value.symbol('shadowed@'+str(site)+':'+key)
                    self.pending_sums.pop(key,None)
            return
        args=[str(a).lstrip('&') for a in args]
        record={'operation':name,'arguments':args,'offset':site}
        if name=='nn_inc' and len(args)>=2:
            self.history.append(record);a=self.get(args[1]);v=a.op(Value.constant(1),'add')
            self.values[args[0]]=v
            if a.atom():self.ones.append((a,v,site))
            return
        if name in {'ossl_ec_group_do_inverse_ord','bn_to_mont_fixed_top',
                    'BN_to_montgomery','bn_mul_mont_fixed_top','BN_mod_mul_montgomery'}:
            # Montgomery conversion has a scale R. Products divide by R; never
            # flatten these operations to plain multiplication. The modulus
            # must be bound to an actual group/order accessor.
            try:
                if name=='ossl_ec_group_do_inverse_ord' and len(args)>=3:
                    n=self.group_orders.get(args[0])
                    if not n:return
                    original=self.get(args[2]);value=original.inverse(n);dst=args[1]
                    self.inverses.append((original,n,site))
                elif name in {'bn_to_mont_fixed_top','BN_to_montgomery'} and len(args)>=3:
                    n=self.group_orders.get(self.mont_groups.get(args[2]))
                    if not n:return
                    dst=args[0];value=self.get(args[1]).op(Value.symbol('montgomery-scale:'+args[2]),'mul',n)
                elif len(args)>=4:
                    n=self.group_orders.get(self.mont_groups.get(args[3]))
                    if not n:return
                    dst=args[0];scale=Value.symbol('montgomery-scale:'+args[3]).inverse(n)
                    value=self.get(args[1]).op(self.get(args[2]),'mul',n).op(scale,'mul',n)
                else:return
                self.values[dst]=value;self.history.append(record);self.signature(dst,value,site)
            except ValueError:self.values[args[0]]=Value.symbol('unknown@'+str(site))
            return
        if name=='EC_POINT_mul' and len(args)>=5:
            # Store the exact generator/public-point scalar values at this call.
            self.points[args[1]]=(args[0],self.get(args[2]),args[3],self.get(args[4]),site)
            self.history.append(record); return
        if name in {'EC_POINT_get_affine_coordinates','EC_POINT_get_affine_coordinates_GFp'} and len(args)>=3:
            point=self.points.get(args[1])
            if point and point[0]==args[0]: self.coordinates[args[2]]=point
            self.history.append(record); return
        spec=OPERATIONS.get(name)
        if not spec:
            if name not in OBSERVERS:
                for arg in args:
                    if arg in self.values:
                        self.values[arg]=Value.symbol('clobbered@'+str(site)+':'+arg)
                        self.pending_sums.pop(arg,None)
            return
        op,inputs,out,mod=spec
        if len(args)<=max((*inputs,*([] if out is None else [out]),*([] if mod is None else [mod]))):return
        self.history.append(record)
        vs=[self.get(args[i]) for i in inputs]
        n=args[mod] if mod is not None else None
        try:
            if op=='compare': self.verify(args,vs,site); return
            if op=='inv':
                v=vs[0].inverse(n); self.inverses.append((vs[0],n,site))
            elif op in {'copy','set'}:
                v=Value(vs[0].num,vs[0].den,vs[0].moduli|({n} if n else set()))
            else: v=vs[0].op(vs[1],op,n)
            dst=args[out]
            pending=self.pending_sums.get(args[inputs[0]]) if op=='copy' else None
            self.pending_sums.pop(dst,None)
            self.values[dst]=v
            if pending and n:
                a,b,old,origin=pending
                if old.equal(v):self.sums.append((dst,a,b,v,n,origin))
            if op=='add':
                if n and vs[0].atom() and vs[1].atom() and vs[0].atom()!=vs[1].atom():
                    self.sums.append((dst,vs[0],vs[1],v,n,site))
                elif not n and vs[0].atom() and vs[1].atom() and vs[0].atom()!=vs[1].atom():
                    self.pending_sums[dst]=(vs[0],vs[1],v,site)
                for a,b in (vs,vs[::-1]):
                    if a.atom() and b.equal(Value.constant(1)):
                        self.ones.append((a,v,site))
            self.signature(dst,v,site)
        except ValueError:
            # Complex/unrecognised arithmetic must not retain an earlier value.
            if out is not None: self.values[args[out]]=Value.symbol('unknown@'+str(site))

    def signature(self, dst, s, site):
        if not self.inverses or not self.ones or len(s.moduli)!=1:return
        n=next(iter(s.moduli))
        for rptr,a,b,r,mod,rsite in self.sums[-16:]:
            if mod!=n or dst==rptr or rsite>=site:continue
            for d,den,dsite in self.ones[-16:]:
                if d.atom() in r.symbols() or not any(im==n and d.atom() in iv.symbols() for iv,im,_ in self.inverses):continue
                # Multiplication by d+1 cancels both direct inversion and
                # multiplicative blinding, using exact cross multiplication.
                target=s.op(den,'mul').op(r.op(d,'mul'),'add')
                k=target.atom()
                if k and k not in r.symbols()|{d.atom()}:
                    self.matches.append({'equation':'r=(e+x) mod n; s*(1+d)=k-r*d mod n',
                        'kind':'signature_arithmetic','modulus':n,'r':rptr,'s':dst,
                        'private_scalar':d.atom(),'nonce':k,'offset':rsite,
                        'operation_witnesses':self.history[-64:]});return
                for k in target.symbols()-r.symbols()-{d.atom()}:
                    if target.equal(Value.symbol(k)):
                        self.matches.append({'equation':'r=(e+x) mod n; s*(1+d)=k-r*d mod n',
                            'kind':'signature_arithmetic','modulus':n,'r':rptr,'s':dst,
                            'private_scalar':d.atom(),'nonce':k,'offset':rsite,
                            'operation_witnesses':self.history[-64:]});return

    def verify(self, args, values, site):
        for lhs,rval in (values,values[::-1]):
            r=rval.atom()
            if not r or len(lhs.moduli)!=1:continue
            n=next(iter(lhs.moduli))
            for x,point in self.coordinates.items():
                group,s,pub,t,psite=point
                if not s.atom() or s.atom()==r or pub in {'NULL','0'}:continue
                expected=Value.symbol(r).op(s,'add',n)
                if t.moduli!={n} or not t.equal(expected):continue
                delta=lhs.op(Value.symbol(x),'sub')
                # The remaining term must be a distinct input digest.
                if delta.atom() and delta.atom() not in {r,s.atom(),x} and psite<site:
                    self.matches.append({'equation':'t=(r+s) mod n; Q=s*G+t*P; r=(e+x(Q)) mod n',
                        'kind':'verification_curve_equation','modulus':n,'offset':psite,
                        'operation_witnesses':self.history[-64:]});return
