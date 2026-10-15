"""Conventional curve-signature equations over trusted generic math APIs.

No EC multiplication or modular inverse alone identifies ECDSA. A generator
multiplication, its coordinate reduced to r, an inverse of the same nonce and
s*k=e+r*d over the same order are all required. Fully static, unrecognised
primitive implementations remain outside this analysis.
"""
from .guomi.bignum import Equations,Value,OPERATIONS

EXPONENTS={'BN_mod_exp':(0,1,2,3),'BN_mod_exp_mont':(0,1,2,3),
 'BN_mod_exp_mont_consttime':(0,1,2,3),'mbedtls_mpi_exp_mod':(0,1,2,3),
 'mbedtls_mpi_exp_mod_unsafe':(0,1,2,3),'mp_exptmod':(3,0,1,2),'sp_exptmod':(3,0,1,2)}
CURVE_MUL={'mbedtls_ecp_mul','mbedtls_ecp_mul_restartable'}
CURVE_MUL.update({'prj_pt_mul','prj_pt_mul_blind'})
for prefix in ('mpz_','__gmpz_'):
    EXPONENTS.update({prefix+'powm':(0,1,2,3),prefix+'powm_sec':(0,1,2,3)})


class ConventionalEquations(Equations):
    def __init__(self,shadowed=(), *, pointer_size=None):
        super().__init__(shadowed)
        self.general_matches=[]
        self.powers=[];self.crt_remainders=[]
        self.peer_points={}
        self.affine_points=set()
        self.imported_points=set()
        self.reduced_coordinates=[]
        self.pointer_size=pointer_size
        from .curve_ladder import Ladder
        self.ladder=Ladder()
        from .curve_exchange import Exchange
        self.exchange=Exchange()

    def match(self,algorithm,equation,site,kind,modulus=None):
        self.general_matches.append({'algorithm':algorithm,'equation':equation,'offset':site,
            'kind':kind,'modulus':modulus,'operation_witnesses':self.history[-64:]})

    def feed(self,name,args,site):
        args=[str(a).lstrip('&') for a in args]
        def pointer(s):
            s=s.strip('()').lstrip('&').strip('()')
            return s
        args=[pointer(a) for a in args]
        record={'operation':name,'arguments':args,'offset':site}
        if name not in self.shadowed and self.exchange.feed(name,args,site):
            self.general_matches.extend(self.exchange.matches);self.exchange.matches=[]
            return
        if name not in self.shadowed and self.ladder.feed(name,args,site):
            self.general_matches.extend(self.ladder.matches);self.ladder.matches=[]
            return
        self.ladder.clobber(args)
        self.exchange.clobber(args)
        if name not in self.shadowed and name=='ec_pub_key_import_from_aff_buf' and len(args)>=5:
            self.imported_points.add(args[0]+'.y')
            if self.pointer_size in {4,8}:
                # libecc's documented ec_pub_key is enum, aligned pointer,
                # then prj_pt y. Bind that field only after the actual import;
                # arbitrary same-object offsets never introduce a peer point.
                import re
                obj=args[0];match=re.fullmatch(r'(.*)\[(-?\d+)\]',obj)
                if match:obj=match[1]+'['+str(int(match[2])+2*self.pointer_size)+']'
                else:obj+='['+str(2*self.pointer_size)+']'
                self.imported_points.add(obj)
            self.history.append(record);return
        if name not in self.shadowed and name in {'prj_pt_import_from_buf','prj_pt_import_from_aff_buf'} and len(args)>=4:
            self.imported_points.add(args[0]);self.history.append(record);return
        if name not in self.shadowed and name=='prj_pt_unique' and len(args)>=2:
            if args[1] in self.peer_points:
                self.peer_points[args[0]]=self.peer_points[args[1]]
                self.affine_points.add(args[0])
            if args[1] in self.points:
                relation=self.points[args[1]];self.points[args[0]]=relation
                for field in ('.X.fp_val','->X.fp_val'):self.coordinates[args[0]+field]=relation
                if args[0].startswith(('stack:','input:','load:')):self.coordinates[args[0]]=relation
            self.history.append(record);return
        if name not in self.shadowed and name in {'prj_pt_mul','prj_pt_mul_blind'} and len(args)>=3:
            out,scalar,base=args[:3];self.history.append(record)
            # The generator must be an actual group-field access or bound by
            # the source declaration pass, never a variable named "G" alone.
            group=self.peer_points.get('generator:'+base)
            if group or base.endswith(('->G','.G','->ec_gen','.ec_gen')):
                if not group:group=base.rsplit('->',1)[0] if '->' in base else base.rsplit('.',1)[0]
                relation=(group,self.get(scalar),'NULL',Value.constant(0),site)
                self.points[out]=relation
                self.coordinates[out+'.X.fp_val']=relation
                self.coordinates[out+'->X.fp_val']=relation
            elif base in self.imported_points:
                self.peer_points[out]=('projective-group',self.get(scalar),base,site)
            else:
                # P is the actual base point operand, not a spelling guessed
                # to mean G. Signing classification still needs the bound
                # x(kP), reduced r, k inverse and s*k=e+r*d equation.
                self.points[out]=('projective-base:'+base,self.get(scalar),'NULL',Value.constant(0),site)
            return
        if name not in self.shadowed and name=='_prj_pt_unprotected_mult' and len(args)>=3:
            if args[2] in self.imported_points:self.imported_points.add(args[0])
            self.history.append(record);return
        if name not in self.shadowed and name in {'nn_export_to_buf','fp_export_to_buf'} and len(args)>=3:
            coordinate=args[2]
            for out,peer in list(self.peer_points.items()):
                fields=({out+'.X.fp_val',out+'->X.fp_val'} if name=='nn_export_to_buf' else {out+'.X',out+'->X'})
                # A binary pointer has no source field spelling. These exact
                # documented layouts both put X/fp_val at offset zero.
                if coordinate.startswith(('stack:','input:','load:')):fields.add(out)
                if out in self.affine_points and coordinate in fields:
                    self.history.append(record);self.match('ECDH','Static/projective Q=d*P; affine x(Q) serialized',site,'peer_scalar_coordinate')
        if name not in self.shadowed and name in EXPONENTS:
            out,base,exp,mod=EXPONENTS[name]
            if len(args)<=max(out,base,exp,mod):return
            self.history.append(record);value=Value.symbol('power@'+str(site))
            value.moduli=frozenset({args[mod]})
            self.powers.append((value,self.get(args[base]),self.get(args[exp]),args[mod],site))
            self.values[args[out]]=value;return
        if name not in self.shadowed and name in CURVE_MUL and len(args)>=4:
            group,point,scalar,base=args[:4];self.history.append(record)
            if base in {group+'->G',group+'.G'}:
                relation=(group,self.get(scalar),'NULL',Value.constant(0),site)
                self.points[point]=relation;self.coordinates[point+'.X']=relation
            else:self.peer_points[point]=(group,self.get(scalar),base,site)
            return
        if name not in self.shadowed and name=='EC_POINT_mul' and len(args)>=5 and args[2] in {'NULL','0','nullptr'} and args[3] not in {'NULL','0','nullptr'}:
            self.peer_points[args[1]]=(args[0],self.get(args[4]),args[3],site)
        if name not in self.shadowed and name in {'EC_POINT_get_affine_coordinates','EC_POINT_get_affine_coordinates_GFp'} and len(args)>=3:
            peer=self.peer_points.get(args[1])
            if peer and peer[0]==args[0]:self.peer_points['coordinate:'+args[2]]=peer
        spec=OPERATIONS.get(name)
        if name not in self.shadowed and name in {'mbedtls_mpi_copy','BN_copy'} and len(args)>=2:
            point=args[1].removesuffix('.X')
            if point!=args[1] and point in self.peer_points:
                self.history.append(record);self.match('ECDH','Q=d*P with peer point; x(Q) copied to output',site,'peer_scalar_coordinate')
        if name not in self.shadowed and name in {'BN_bn2bin','BN_bn2binpad','mbedtls_mpi_write_binary'} and args:
            if 'coordinate:'+args[0] in self.peer_points:
                self.history.append(record);self.match('ECDH','Q=d*P with peer point; x(Q) serialized to output',site,'peer_scalar_coordinate')
        super().feed(name,args,site)
        if not spec or name in self.shadowed:return
        op,inputs,out,mod=spec
        if out is None or len(args)<=out:return
        value=self.values.get(args[out])
        if not value:return
        if mod is not None and len(args)>mod:
            for coordinate in self.coordinates:
                if value.moduli=={args[mod]} and value.equal(Value.symbol(coordinate)):
                    self.reduced_coordinates.append((args[out],value))
        # A complete CRT path: two exponentiations of the same input, an
        # explicitly reduced difference/coefficient modulo p, and q*h+m2.
        if mod is not None and len(args)>mod:
            n=args[mod]
            for m1,c1,e1,p,p1 in self.powers[-12:]:
                for m2,c2,e2,q,p2 in self.powers[-12:]:
                    if p==q or p!=n or not c1.equal(c2):continue
                    difference=m1.op(m2,'sub')
                    for coefficient in value.symbols()-m1.symbols()-m2.symbols():
                        if value.equal(difference.op(Value.symbol(coefficient),'mul')):
                            self.crt_remainders.append((value,m2,q,site))
        for h,m2,q,origin in self.crt_remainders[-24:]:
            if origin<site and value.equal(m2.op(h.op(Value.symbol(q),'mul'),'add')):
                self.match('RSA','m1=c^dp mod p; m2=c^dq mod q; h=(m1-m2)*qInv mod p; m=m2+q*h',origin,'crt_exponent_recombination')
                break
    def signature(self,dst,s,site):
        super().signature(dst,s,site)
        if not self.inverses or len(s.moduli)!=1:return
        n=next(iter(s.moduli))
        for coordinate,point in self.coordinates.items():
            group,k,pub,other,psite=point
            if pub not in {'NULL','0','nullptr'} or not k.atom() or psite>=site:continue
            if not any(mod==n and k.atom() in inv.symbols() for inv,mod,_ in self.inverses):continue
            candidates=list(self.values.items())+self.reduced_coordinates[-16:]
            for rptr,r in candidates:
                if rptr==dst or r.moduli!={n} or not r.equal(Value.symbol(coordinate)):continue
                numerator=s.op(k,'mul')
                for d in numerator.symbols()-r.symbols()-k.symbols():
                    rest=numerator.op(r.op(Value.symbol(d),'mul'),'sub')
                    candidates=rest.symbols()-r.symbols()-k.symbols()-{d}
                    if not any(rest.equal(Value.symbol(e)) for e in candidates):continue
                    self.general_matches.append({'algorithm':'ECDSA','equation':'R=k*P for the bound base point; r=x(R) mod n; s*k=e+r*d mod n',
                        'modulus':n,'offset':psite,'kind':'signature_curve_equation',
                        'operation_witnesses':self.history[-64:]});return
