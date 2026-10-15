"""SM2 key-agreement equations with actual truncated-coordinate witnesses.

Documented fixed-curve arithmetic APIs supply primitives, never a finding by
themselves. Both x-hat values and the dependent local scalar/peer point equation
must be bound before the result is serialized for the KDF.
"""
from .guomi.bignum import Value

APIS={'sm2_z256_modn_mul','sm2_z256_modn_add','sm2_z256_point_mul',
      'sm2_z256_point_add','sm2_z256_point_get_xy','sm2_z256_point_to_bytes',
      'sm2_z256_point_is_at_infinity','sm2_z256_point_from_octets',
      'sm2_z256_point_to_uncompressed_octets','sm2_kdf'}


def source_xhat_helpers(analysis):
    from .guomi.source_semantics import walk,txt,call_name,number
    result={}
    for name,(parameters,body,definition) in analysis.functions.items():
        if len(parameters)!=2 or body is None or body.has_error or name in analysis.ambiguous_functions:continue
        source,destination=parameters
        coordinates=[];stores={};valid=True
        for node in walk(body):
            if node.type=='call_expression':
                called=call_name(node);args=node.child_by_field_name('arguments')
                args=list(args.named_children) if args else []
                if called=='sm2_z256_point_get_xy' and called not in analysis.functions and len(args)>=3 and txt(args[0])==source and txt(args[2]) in {'NULL','0','nullptr'}:
                    coordinates.append(txt(args[1]))
                if any(destination in {txt(a),txt(a).lstrip('&')} for a in args):valid=False
            if node.type=='assignment_expression':
                left=node.child_by_field_name('left')
                if left.type!='subscript_expression' or txt(left.child_by_field_name('argument'))!=destination:continue
                i=number(txt(left.child_by_field_name('index')))
                if i is None or i in stores or txt(node.child_by_field_name('operator'))!='=':valid=False;continue
                stores[i]=node.child_by_field_name('right')
        def expr(node):
            if node.type=='parenthesized_expression':return expr(node.named_children[0])
            if node.type=='number_literal':return number(txt(node))
            if node.type=='subscript_expression':return (txt(node.child_by_field_name('argument')),number(txt(node.child_by_field_name('index'))))
            if node.type=='binary_expression':return (txt(node.child_by_field_name('operator')),expr(node.child_by_field_name('left')),expr(node.child_by_field_name('right')))
            return None
        if valid and len(coordinates)==1 and set(stores)=={0,1,2,3}:
            # Stores hidden behind another branch cannot be collected as one
            # completed helper. Nor may the affine coordinate be overwritten
            # before supplying x-hat. A subsequent secure-clear is harmless.
            for i,right in stores.items():
                assignment=right.parent;parent=assignment.parent
                if parent is not None and parent.type=='expression_statement':parent=parent.parent
                if parent!=body:valid=False
            for node in walk(body):
                if node.type=='assignment_expression':
                    left=txt(node.child_by_field_name('left'))
                    if left==coordinates[0] or left.startswith(coordinates[0]+'['):valid=False
            if not valid:continue
            x=coordinates[0];expected={0:(x,0),1:('|',('&',(x,1),(1<<63)-1),1<<63),2:0,3:0}
            if {i:expr(v) for i,v in stores.items()}==expected:
                result[name]={'point_parameter':0,'output_parameter':1,'definition_offset':definition.start_byte,
                              'proof':'Actual affine x, low limb copy, masked next limb with bit 127 set, two zero upper limbs'}
    return result


class Exchange:
    def __init__(self):
        self.scalars={};self.points={};self.xhats={};self.serialized={}
        self.history=[];self.matches=[]

    def scalar(self,key):return self.scalars.get(key,Value.symbol(key))
    def point(self,key):return self.points.get(key,{key:Value.constant(1)})

    def clobber(self,args):
        if set(args)&(self.scalars.keys()|self.points.keys()|self.xhats.keys()|self.serialized.keys()):
            self.scalars.clear();self.points.clear();self.xhats.clear();self.serialized.clear()

    def xhat(self,destination,point,site,proof):
        self.xhats[destination]=point
        self.scalars[destination]=Value.symbol('xhat:'+point)
        self.history.append({'operation':'xhat=2^127+(affine_x mod 2^127)',
                             'arguments':[destination,point],'offset':site,'proof':proof})

    def feed(self,name,args,site):
        if name not in APIS:return False
        self.history.append({'operation':name,'arguments':args,'offset':site})
        if len(self.history)>128:self.history=self.history[-128:]
        if len(args)<2:return True
        out=args[0]
        try:
            if name=='sm2_z256_point_to_uncompressed_octets':
                # The documented serializer reads the point and writes only
                # the octet destination. Do not invalidate its input equation.
                # Aliasing the destination with tracked state is still a write.
                self.clobber(args[1:2])
                return True
            if name in {'sm2_z256_modn_mul','sm2_z256_modn_add'} and len(args)>=3:
                self.scalars[out]=self.scalar(args[1]).op(self.scalar(args[2]),'mul' if name.endswith('mul') else 'add','SM2-order')
            elif name=='sm2_z256_point_mul' and len(args)>=3:
                scalar=self.scalar(args[1]);point=self.point(args[2])
                self.points[out]={base:value.op(scalar,'mul') for base,value in point.items()}
            elif name=='sm2_z256_point_add' and len(args)>=3:
                a,b=self.point(args[1]),self.point(args[2]);self.points[out]=dict(a)
                for base,value in b.items():self.points[out][base]=self.points[out].get(base,Value.constant(0)).op(value,'add')
            elif name=='sm2_z256_point_to_bytes':
                point=self.point(out)
                if len(point)==2:self.serialized[args[1]]=(point,site)
            elif name=='sm2_kdf' and args[0] in self.serialized:
                point,origin=self.serialized[args[0]]
                for peer_ephemeral,coefficient in point.items():
                    xhat=Value.symbol('xhat:'+peer_ephemeral)
                    for peer_static,t in point.items():
                        if peer_static==peer_ephemeral or not coefficient.equal(t.op(xhat,'mul')):continue
                        # t=d+xhat(Rlocal)*rlocal must have exactly these two
                        # polynomial terms and distinct local/peer x-hats.
                        if t.den!={():1} or len(t.num)!=2:continue
                        singles=[m[0] for m,c in t.num.items() if c==1 and len(m)==1]
                        products=[m for m,c in t.num.items() if c==1 and len(m)==2]
                        if len(singles)!=1 or len(products)!=1:continue
                        for factor in products[0]:
                            if not factor.startswith('xhat:') or factor=='xhat:'+peer_ephemeral:continue
                            if singles[0] in products[0]:continue
                            self.matches.append({'algorithm':'SM2','equation':'xhat=2^127+(x mod 2^127); t=d+xhat(Rlocal)*rlocal; U=t*(Ppeer+xhat(Rpeer)*Rpeer); serialize U for KDF',
                                'kind':'key_agreement_curve_equation','modulus':'SM2-order','offset':origin,
                                'operation_witnesses':self.history[-64:]})
        except ValueError:
            self.scalars.pop(out,None);self.points.pop(out,None)
        return True
