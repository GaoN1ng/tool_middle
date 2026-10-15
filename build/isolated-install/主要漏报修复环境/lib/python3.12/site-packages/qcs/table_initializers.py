"""Recover complete constant tables from bounded, typed C initializers.

This interpreter evaluates local AST nodes in Python-owned scalar/array storage.
It cannot compile code, execute target instructions, resolve external APIs or
perform I/O. A recovered table is evidence only when the normal operation graph
actually reads it. Unknown types, uninitialized reads and unsupported syntax
reject a constructor transaction; partial tables never acquire a standard role.
"""
from __future__ import annotations
from dataclasses import dataclass
import re
import time


class Declined(Exception):pass
class Returned(Exception):
    def __init__(self,value):self.value=value


@dataclass
class Array:
    values:list
    width:int


class Interpreter:
    def __init__(self,analysis,deadline):
        self.a=analysis;self.deadline=deadline;self.visits=0;self.depth=0;self.globals={};self.global_types={};self.cells=0
        self.written=set();self.trace=[]
        from .guomi.source_semantics import walk,txt
        self.txt=txt;self.walk=walk
        for node in analysis.tree.root_node.named_children:
            if node.type=='declaration':self.declare(node,self.globals,self.global_types,global_=True)

    def tick(self):
        self.visits+=1
        if self.visits>600000 or (not self.visits%256 and time.monotonic()>self.deadline):raise Declined('initializer budget')

    def width(self,kind):
        kind=re.sub(r'\b(?:const|volatile|register|static)\b','',kind).replace(' ','')
        if kind=='void':return 0
        abi={'unsignedlong':64,'signedlong':64,'long':64,
             'unsignedshort':16,'signedshort':16,'short':16}
        seen=set()
        while isinstance(kind,str) and kind not in seen:
            seen.add(kind);kind=abi.get(kind,self.a.scalar_types.get(kind))
        if kind not in {8,16,32,64}:raise Declined('unknown scalar type')
        return kind

    def literal(self,node):
        s=re.sub(r'[uUlL]+$','',self.txt(node))
        try:return int(s,8 if re.fullmatch(r'0[0-7]+',s) else 0)
        except ValueError:raise Declined('noninteger literal')

    def declare(self,node,env,types,global_=False):
        width=None
        for decl in node.named_children:
            if decl.type not in {'identifier','array_declarator','pointer_declarator','init_declarator'}:continue
            d=decl.child_by_field_name('declarator') if decl.type=='init_declarator' else decl
            if d is None or any(n.type=='function_declarator' for n in self.walk(d)):continue
            # Pointer declarations in the constructor are not guessed.
            if d.type=='pointer_declarator':raise Declined('local pointer declaration')
            name=next((self.txt(n) for n in self.walk(d) if n.type=='identifier'),None)
            if not name:continue
            if width is None:width=self.width(self.txt(node.child_by_field_name('type')))
            dims=[]
            for size in re.findall(r'\[([^\]]*)\]',self.txt(d)):
                if size=='':dims.append(None)
                elif size.isdigit():dims.append(int(size))
                elif size in self.a.constants:dims.append(self.a.constants[size])
                else:raise Declined('unknown array size')
            value=decl.child_by_field_name('value') if decl.type=='init_declarator' else None
            if dims:
                vals=self.initializer(value,env,types) if value is not None else []
                def build(shape,items):
                    count=shape[0] if shape[0] is not None else len(items)
                    if not 0<count<=4096:raise Declined('array bound')
                    self.cells+=count
                    if self.cells>32768 or len(shape)>4:raise Declined('total initializer storage bound')
                    if len(shape)>1:
                        if items and any(not isinstance(x,list) for x in items):raise Declined('flat multidimensional initializer')
                        return Array([build(shape[1:],items[i] if i<len(items) else []) for i in range(count)],width)
                    if any(not isinstance(x,int) for x in items) or len(items)>count:raise Declined('initializer shape')
                    fill=0 if global_ or value is not None else None
                    return Array([self.cast(x,width) for x in items]+[fill]*(count-len(items)),width)
                env[name]=build(dims,vals)
            elif value is not None:env[name]=self.cast(self.expr(value,env,types),width)
            elif global_:env[name]=0
            else:env[name]=None
            types[name]=width

    def initializer(self,node,env,types):
        if node.type!='initializer_list':return self.expr(node,env,types)
        return [self.initializer(n,env,types) for n in node.named_children if n.type!='comment']

    def cast(self,value,width):
        if not isinstance(value,int):raise Declined('nonscalar cast')
        # Signed int induction variables retain their mathematical sign; all
        # narrowed byte/word typedefs use their actual declared storage width.
        return value&((1<<width)-1) if width in {8,16,64} else value&0xffffffff if width==32 and value>=0 else value

    def binding(self,node,env,types):
        if node.type=='parenthesized_expression':return self.binding(node.named_children[0],env,types)
        if node.type=='identifier':
            name=self.txt(node)
            scope=env if name in env else self.globals
            if name not in scope:raise Declined('unbound lvalue')
            return scope,name,types.get(name,self.global_types.get(name,32))
        if node.type=='subscript_expression':
            array=self.expr(node.child_by_field_name('argument'),env,types);index=self.expr(node.child_by_field_name('index'),env,types)
            if not isinstance(array,Array) or not isinstance(index,int) or not 0<=index<len(array.values):raise Declined('array access')
            return array.values,index,array.width
        raise Declined('unsupported lvalue')

    def expr(self,node,env,types):
        self.tick()
        if node is None or node.has_error:raise Declined('missing/error expression')
        kind=node.type
        if kind=='number_literal':return self.literal(node)
        if kind in {'parenthesized_expression','cast_expression'}:
            result=self.expr(node.named_children[-1],env,types)
            return self.cast(result,self.width(self.txt(node.child_by_field_name('type')))) if kind=='cast_expression' else result
        if kind=='identifier':
            name=self.txt(node)
            value=env.get(name,self.globals.get(name,self.a.constants.get(name)))
            if value is None:raise Declined('uninitialized read')
            return value
        if kind=='subscript_expression':
            scope,key,_=self.binding(node,env,types);value=scope[key]
            if value is None:raise Declined('uninitialized array read')
            return value
        if kind=='conditional_expression':
            return self.expr(node.child_by_field_name('consequence' if self.expr(node.child_by_field_name('condition'),env,types) else 'alternative'),env,types)
        if kind=='comma_expression':
            result=0
            for child in node.named_children:result=self.expr(child,env,types)
            return result
        if kind=='unary_expression':
            v=self.expr(node.child_by_field_name('argument'),env,types);op=self.txt(node.child_by_field_name('operator'))
            if not isinstance(v,int):raise Declined('noninteger unary')
            if op=='!':return int(not v)
            if op=='~':return ~v
            if op=='-':return -v
            if op=='+':return v
            raise Declined('unknown unary')
        if kind=='update_expression':
            scope,key,width=self.binding(node.child_by_field_name('argument'),env,types);old=scope[key]
            if not isinstance(old,int):raise Declined('uninitialized update')
            value=self.cast(old+(1 if self.txt(node.child_by_field_name('operator'))=='++' else -1),width);scope[key]=value
            return value if self.txt(node).startswith(('++','--')) else old
        if kind in {'binary_expression','assignment_expression'}:
            left,right=node.child_by_field_name('left'),node.child_by_field_name('right');op=self.txt(node.child_by_field_name('operator'))
            if kind=='assignment_expression':
                scope,key,width=self.binding(left,env,types);b=self.expr(right,env,types)
                value=b if op=='=' else self.binary(scope[key],b,op[:-1]);scope[key]=self.cast(value,width)
                if scope is self.globals:self.written.add(key)
                return scope[key]
            a=self.expr(left,env,types)
            if op=='&&' and not a:return 0
            if op=='||' and a:return 1
            return self.binary(a,self.expr(right,env,types),op)
        if kind=='call_expression':
            name=self.txt(node.child_by_field_name('function'));args=node.child_by_field_name('arguments')
            values=[self.expr(n,env,types) for n in args.named_children]
            return self.call(name,values)
        raise Declined('unsupported expression '+kind)

    def binary(self,a,b,op):
        if not isinstance(a,int) or not isinstance(b,int):raise Declined('noninteger operands')
        if op=='+':return a+b
        if op=='-':return a-b
        if op=='*':return a*b
        if op in {'/','%'}:
            if not b:raise Declined('zero divisor')
            q=(abs(a)//abs(b))*(-1 if (a<0)!=(b<0) else 1)
            return q if op=='/' else a-q*b
        if op in {'<<','>>'}:
            if not 0<=b<64:raise Declined('shift bound')
            return a<<b if op=='<<' else a>>b
        if op=='^':return a^b
        if op=='&':return a&b
        if op=='|':return a|b
        if op=='<':return int(a<b)
        if op=='<=':return int(a<=b)
        if op=='>':return int(a>b)
        if op=='>=':return int(a>=b)
        if op=='==':return int(a==b)
        if op=='!=':return int(a!=b)
        if op=='&&':return int(bool(a and b))
        if op=='||':return int(bool(a or b))
        raise Declined('unknown binary')

    def statement(self,node,env,types):
        self.tick()
        if node is None:return
        kind=node.type
        if node.has_error:raise Declined('parse error')
        if kind=='comment':return
        if kind=='compound_statement':
            for child in node.named_children:self.statement(child,env,types)
        elif kind=='declaration':self.declare(node,env,types)
        elif kind=='return_statement':raise Returned(self.expr(node.named_children[0],env,types) if node.named_children else 0)
        elif kind=='expression_statement':
            for child in node.named_children:self.expr(child,env,types)
        elif kind=='if_statement':self.statement(node.child_by_field_name('consequence' if self.expr(node.child_by_field_name('condition'),env,types) else 'alternative'),env,types)
        elif kind=='else_clause':
            for child in node.named_children:self.statement(child,env,types)
        elif kind=='for_statement':
            init=node.child_by_field_name('initializer')
            if init is not None:
                if init.type=='declaration':self.declare(init,env,types)
                else:self.expr(init,env,types)
            condition=node.child_by_field_name('condition');update=node.child_by_field_name('update')
            if condition is None:raise Declined('unbounded loop')
            for _ in range(4096):
                if not self.expr(condition,env,types):return
                self.statement(node.child_by_field_name('body'),env,types)
                if update is not None:self.expr(update,env,types)
            raise Declined('loop bound')
        else:raise Declined('unsupported statement '+kind)

    def call(self,name,args):
        self.tick()
        target=self.a.macros.get(name) or self.a.functions.get(name)
        if target is None or name in self.a.ambiguous_functions or self.depth>=12:raise Declined('unresolved/recursive call')
        params,body,definition=target
        if params==['']:params=[]
        if len(params)!=len(args):raise Declined('argument count')
        local=dict(zip(params,args));types={}
        if name not in self.a.macros:
            fdecl=next(n for n in self.walk(definition.child_by_field_name('declarator')) if n.type=='function_declarator')
            for parameter in fdecl.child_by_field_name('parameters').named_children:
                identifiers=[n for n in self.walk(parameter.child_by_field_name('declarator')) if n.type=='identifier'] if parameter.child_by_field_name('declarator') is not None else []
                if identifiers:
                    p=self.txt(identifiers[0]);types[p]=self.width(self.txt(parameter.child_by_field_name('type')))
                    if isinstance(local.get(p),int):local[p]=self.cast(local[p],types[p])
        self.depth+=1
        try:
            try:self.statement(body,local,types);value=0
            except Returned as result:value=result.value
        finally:self.depth-=1
        if name not in self.a.macros:
            width=self.width(self.txt(definition.child_by_field_name('type')))
            if width:value=self.cast(value,width)
        return value


def recover(analysis,seconds=2):
    """Transactional constructors; exact full standard maps only, never labels."""
    from .operation_tables import numeric_tables
    from .guomi.source_semantics import walk,txt
    # Only unresolved global arrays justify this optional analysis budget.
    declarations=[n for n in analysis.tree.root_node.named_children if n.type=='declaration']
    if not any(n.type=='array_declarator' and n.parent.type=='declaration' for d in declarations for n in walk(d)):return []
    deadline=time.monotonic()+seconds;verified={values:kind for kind,values in numeric_tables()}
    for kind,values in numeric_tables():
        if kind=='aes_t':verified[tuple(int.from_bytes(x.to_bytes(4,'little'),'big') for x in values)]=kind
    results=[]
    for name,(params,body,definition) in analysis.functions.items():
        if time.monotonic()>deadline:break
        if any(params) or body is None or len(body.text)>6000:continue
        try:
            interpreter=Interpreter(analysis,deadline);interpreter.call(name,[])
        except (Declined,ValueError,StopIteration,KeyError):continue
        for key,array in interpreter.globals.items():
            if not isinstance(array,Array) or any(not isinstance(x,int) for x in array.values):continue
            role=verified.get(tuple(array.values))
            if role is None or key in analysis.tables:continue
            analysis.tables[key]=role;analysis.table_sizes[key]=len(array.values)
            results.append({'table':key,'kind':role,'elements':len(array.values),'constructor':name,
                'offset':definition.start_byte,'node_visits':interpreter.visits,
                'method':'Complete typed bounded local initializer result matches a standard table; consumers require actual operation-graph reads'})
    return results
