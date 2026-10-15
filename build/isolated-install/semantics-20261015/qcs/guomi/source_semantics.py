"""Bounded C/C++ operation graphs, including local functions and macros.

No algorithm name is a classification feature. Names only resolve actual local
definitions/table references or documented OpenSSL big-number operations. This
does not compile the input, follow includes, or implement the C preprocessor.
"""
from collections import Counter
from functools import lru_cache
import json
from pathlib import Path
import re

from .linear import leaf, rotate, shift, xor, merge_shifts, roles
from .binary_semantics import DATA, table_patterns
from ..model import evidence, error
from .bignum import Equations
from ..operations import Arithmetic, recognize, emit
from ..operation_tables import numeric_tables, SHA256_IV
from ..operation_arrays import Arrays
from ..message_schedule import Schedules,index as schedule_index
from ..operation_bignum import ConventionalEquations

MAX_SOURCE = 4 * 1024 * 1024
MAX_NODES = 150_000
MAX_TOTAL_NODES = 2_000_000


def walk(node):
    yield node
    for child in node.named_children:
        yield from walk(child)


@lru_cache(maxsize=2)
def parser(cpp):
    from tree_sitter import Parser, Language
    if cpp:
        import tree_sitter_cpp as language
    else:
        import tree_sitter_c as language
    return Parser(Language(language.language()))


def number(text):
    # A numeric object macro may wrap its literal in a fixed-width cast.
    text=re.sub(r'^\(*\((?:u?int32_t|unsigned|unsignedint)\)', '',text)
    text=text.strip('()')
    try:
        return int(re.sub(r'[uUlL]+$', '', text), 0)
    except ValueError:
        return None


def txt(node):
    return re.sub(r'\s+', '', node.text.decode(errors='replace')) if node else ''


def array_base(node):
    while node is not None and node.type=='parenthesized_expression' and node.named_children:
        node=node.named_children[0]
    return node


def call_name(node):
    function = node.child_by_field_name('function')
    return txt(function)


def numeric_op(a, b, op):
    if a[0] == b[0] == 'constant':
        x, y = a[1], b[1]
        if op == '-': return ('constant', x - y)
        if op == '+': return ('constant', x + y)
        if op == '*': return ('constant', x * y)
        if op == '&': return ('constant', x & y)
        if op == '|': return ('constant', x | y)
        if op == '^': return ('constant', x ^ y)
        if op in {'<<','>>'} and 0<=y<32:return ('constant', (x<<y) if op=='<<' else (x&0xffffffff)>>y)
    return None


class Analysis:
    def __init__(self, raw, cpp, *, declaration_contexts=()):
        # The lexer masks quoted include paths. An incomplete #include can
        # otherwise consume the next function as its parse-error recovery.
        raw=re.sub(rb'(?m)^[ \t]*#[ \t]*(?:include|pragma)\b[^\r\n]*',
                   lambda m:b' '*len(m[0]),raw)
        # These are compiler spellings of language qualifiers, not function
        # identifiers. Preserve offsets while making declarations parseable.
        for spelling, standard in ((b'__const',b'const'),(b'__inline__',b'inline'),(b'__inline',b'inline'),(b'__restrict__',b'restrict')):
            raw=re.sub(rb'\b'+spelling+rb'\b',lambda m:standard+b' '*(len(m[0])-len(standard)),raw)
        from ..source_declarations import expand
        raw,self.declaration_expansions=expand(raw,cpp,declaration_contexts)
        self.raw, self.cpp = raw, cpp
        self.tree = parser(cpp).parse(raw)
        self.functions, self.macros, self.tables = {}, {}, {}
        self.table_sizes={}
        self.ambiguous_functions=set()
        self.events, self.calls, self.node_visits = [], [], 0
        self.root = None
        self.site = None
        self.constants = {}
        self.scalar_types={**{f'{sign}int{width}_t':width for sign in ('','u') for width in (8,16,32,64)},
                           'unsignedint':32,'unsigned':32,'int':32,'signedint':32,
                           'unsignedchar':8,'signedchar':8,'char':8,
                           'unsignedlonglong':64,'longlong':64}
        self.wide_names = set()
        self.serial = 0
        self.inline_depth=0
        self.arithmetic=Arithmetic()
        self.arrays=Arrays(self.arithmetic)
        self.schedules=Schedules(self.arithmetic)
        self.aliases={}
        self.lexical_site=None
        self.macro_versions={}
        self.constant_versions={}
        self.context_macros={}
        self.table_scopes={}
        self.prepare()
        from ..sm4_tables import TableRounds
        self.table_rounds = TableRounds()
        self.table_positions = {}
        patterns = list(table_patterns())
        for node in walk(self.tree.root_node):
            if node.type=='type_definition':
                declared=node.child_by_field_name('declarator')
                underlying=node.child_by_field_name('type')
                if declared and declared.type=='type_identifier' and underlying and underlying.type in {'type_identifier','primitive_type','sized_type_specifier'}:
                    self.scalar_types.setdefault(txt(declared),txt(underlying))
            if node.type != 'init_declarator':
                continue
            value = node.child_by_field_name('value')
            name = re.match(r'\w+', txt(node.child_by_field_name('declarator')))
            if not name or self.tables.get(name[0]) != 'block_table' or value is None:
                continue
            ns = [number(txt(n)) for n in walk(value) if n.type == 'number_literal']
            for pattern_index, (kind, raw) in enumerate(patterns):
                if kind == 'block_table' and ns == [int.from_bytes(raw[i:i+4], 'little') for i in range(0, len(raw), 4)]:
                    self.table_positions[name[0]] = (pattern_index - 2) % 9 % 4 * 8
                    break
        self.entry_functions=set(self.functions)
        self.function_limits=[]
        self.function_visits={}
        self.bound_initials={}
        self.linkage_plans=[]
        self.controlflow={'branches':0,'loops':0,'joins':0}

    def reset_arrays(self):
        self.arrays.reset();self.schedules.reset()

    def key(self,node):
        name=txt(node)
        # Macro arguments are substituted simultaneously. Sequential replace
        # turns a->b, b->c into a->c and silently merges independent state words.
        return re.sub(r'\b[A-Za-z_]\w*\b',
                      lambda m:self.aliases.get(m[0],m[0]),name)

    def fresh(self, table_tags=()):
        self.serial += 1
        return leaf((self.serial, tuple(sorted(table_tags))))

    def prepare(self):
        standard_tables={values:kind for kind,values in numeric_tables()}
        for node in walk(self.tree.root_node):
            if node.type in {'declaration','parameter_declaration'} and re.search(r'\b(uint64_t|int64_t|word64|u64|unsigned\s+long\s+long)\b',node.text.decode(errors='replace')):
                self.wide_names.update(txt(n) for n in walk(node) if n.type=='identifier')
            if node.type == 'preproc_def':
                n, v = node.child_by_field_name('name'),node.child_by_field_name('value')
                val=number(txt(v))
                if n and val is not None:
                    self.constants[txt(n)]=val
                    self.constant_versions.setdefault(txt(n),[]).append((node.start_byte,val))
            if node.type == 'function_definition':
                decl = node.child_by_field_name('declarator')
                fdecl = next((n for n in walk(decl) if n.type == 'function_declarator'), None) if decl else None
                if not fdecl: continue
                name = txt(fdecl.child_by_field_name('declarator'))
                params = fdecl.child_by_field_name('parameters')
                names = []
                for p in params.named_children if params else []:
                    d = p.child_by_field_name('declarator')
                    ident = [x for x in walk(d) if x.type in {'identifier','field_identifier'}] if d else []
                    names.append(txt(ident[-1]) if ident else '')
                if name in self.functions:
                    previous=self.functions[name]
                    self.functions[name+'@'+str(previous[2].start_byte)]=previous
                    self.ambiguous_functions.add(name)
                self.functions[name] = (names, node.child_by_field_name('body'), node)
            elif node.type == 'preproc_function_def':
                name = txt(node.child_by_field_name('name'))
                params = node.child_by_field_name('parameters')
                value = node.child_by_field_name('value')
                if not name or not value: continue
                body = value.text.replace(b'\\\n', b' ').replace(b'\\\r\n', b' ')
                # Parse token-pasting macros with valid placeholder tokens;
                # the actual invocation is instantiated before evaluation.
                parsed_body=re.sub(rb'\s*##\s*',b'',body)
                expression = ((b';' not in body and not body.strip().startswith(b'do')) or
                              bool(re.match(rb'\(*\s*__extension__\b|\(\s*\{',body.strip())))
                wrapped = b'int helper(){' + (b'return ' if expression else b'') + parsed_body + b';}'
                tree = parser(cpp=self.cpp).parse(wrapped)
                function = next((n for n in walk(tree.root_node) if n.type == 'function_definition'), None)
                if function:
                    names = [txt(x) for x in params.named_children] if params else []
                    self.macros[name] = (names, function.child_by_field_name('body'), node)
                    self.macro_versions.setdefault(name,[]).append(self.macros[name])
            elif node.type == 'init_declarator':
                value = node.child_by_field_name('value')
                if value and value.type=='number_literal' and node.parent and node.parent.type=='declaration':
                    declaration=node.parent.text.decode(errors='replace')
                    named=re.search(r'\bconst\s+(?:unsigned\s+)?\w+\s+(\w+)(?:\s+\w+)*\s*=',declaration)
                    n=number(txt(value))
                    if named and n is not None and not any(p.type=='function_definition' for p in self.ancestors(node)):
                        self.constants[named[1]]=n
                        self.constant_versions.setdefault(named[1],[]).append((node.start_byte,n))
                if not value or value.type != 'initializer_list': continue
                ns = [number(txt(n)) for n in walk(value) if n.type == 'number_literal']
                if any(n is None for n in ns): continue
                name = re.match(r'\w+', txt(node.child_by_field_name('declarator')))
                if not name: continue
                # Flash-storage annotations may be parsed as a second
                # declarator. The preceding array still binds the initializer.
                if node.parent and node.parent.type=='declaration':
                    declared=re.search(r'(\w+)\s*(?:\[[^\]]*\]\s*)+(?:\w+\s*)*=',node.parent.text.decode(errors='replace'))
                    if declared:name=re.match(r'\w+',declared[1])
                    arrays=[n for n in node.parent.named_children if n.type=='array_declarator' and n.end_byte<=node.start_byte]
                    if arrays:
                        declared=re.match(r'\w+',txt(arrays[-1]))
                        if declared:name=declared
                if ns == DATA['sm4_sbox']: self.tables[name[0]] = 'sbox'
                elif ns == DATA['sm4_ck']: self.tables[name[0]] = 'ck'
                elif tuple(ns) in standard_tables:self.tables[name[0]]=standard_tables[tuple(ns)]
                elif len(ns)==512 and all(standard_tables.get(tuple(ns[i:i+64]))=='des_sp' for i in range(0,512,64)):
                    self.tables[name[0]]='des_sp'
                elif len(ns) == 256:
                    for kind, raw in table_patterns():
                        if len(raw) == 1024 and ns == [int.from_bytes(raw[i:i+4],'little') for i in range(0,1024,4)]:
                            self.tables[name[0]] = kind; break
                owner=next((ancestor for ancestor in self.ancestors(node) if ancestor.type=='function_definition'),None)
                if name[0] in self.tables:self.table_sizes[name[0]]=len(ns)
                if owner is not None:
                    role=standard_tables.get(tuple(ns))
                    if ns==DATA['sm4_sbox']:role='sbox'
                    elif ns==DATA['sm4_ck']:role='ck'
                    self.table_scopes.setdefault(name[0],[]).append((owner.start_byte,owner.end_byte,role))

    def table_kind(self, name):
        if name in self.table_scopes:
            definition=self.functions.get(self.root)
            if definition:
                site=definition[2].start_byte
                local=[role for start,end,role in self.table_scopes[name] if start<=site<end]
                if local:return local[-1]
            # A function-local initializer is not visible to other functions.
            return None
        return self.tables.get(name)

    @staticmethod
    def ancestors(node):
        while node.parent:
            node=node.parent
            yield node

    def expr(self, node, env, depth=0):
        if node is None or depth > 32: return self.fresh()
        if node.has_error:return self.fresh()
        self.node_visits += 1
        if self.node_visits > MAX_NODES: raise ValueError('Source operation node budget exhausted')
        kind = node.type
        if kind in {'identifier','field_expression','subscript_expression'}:
            name = self.key(node)
            if kind=='identifier' and name in self.scalar_types and name not in env:
                # A typedef passed as a macro parameter is a type token. It
                # must not create a value binding that shadows subsequent casts.
                return ('type',name)
            if kind=='identifier' and name in self.constants and name not in env:
                site=self.lexical_site if self.lexical_site is not None else node.start_byte
                preceding=[v for p,v in self.constant_versions[name] if p<=site]
                if not preceding:return self.fresh()
                val=preceding[-1]
                self.events.append((self.root,'constant',val,self.site if self.site is not None else node.start_byte))
                return ('constant',val)
            if kind=='identifier' and name in (self.functions.keys() | self.macros.keys()) and name not in env:
                return ('callable',name)
            if kind=='identifier' and name not in env and name in self.table_sizes:
                role=self.table_kind(name)
                if role:return ('table_pointer',role,0,0,self.table_sizes[name])
            if kind == 'subscript_expression':
                index=self.expr(node.child_by_field_name('index'),env,depth+1)
                base = self.key(array_base(node.child_by_field_name('argument')))
                role = self.table_kind(base) if base not in env else None
                pointer=env.get(base)
                if pointer and pointer[0]=='table_pointer' and len(pointer)==5:
                    if index[0]=='constant' and 0<=pointer[2]+index[1]<=pointer[3]+index[1]<pointer[4]:role=pointer[1]
                    elif index[0]=='index_range' and 0<=pointer[2]+index[1]<=pointer[3]+index[2]<pointer[4]:role=pointer[1]
                if role:
                    self.events.append((self.root, 'table_read', role, self.site if self.site is not None else node.start_byte))
                    value = self.fresh([role])
                    self.table_rounds.remember(value, index,
                        {'kind': role, 'byte_position': self.table_positions.get(base)})
                    from .linear import truncate
                    return truncate(value, 8) if role == 'sbox' else value
                base=self.key(array_base(node.child_by_field_name('argument')))
                candidate=self.schedules.read(base,schedule_index(node.child_by_field_name('index'),env,self.key),self.fresh(['wide'] if base in self.wide_names else []))
                value=self.arrays.load(base,index,candidate,self.site if self.site is not None else node.start_byte)
                env[name]=value
                return value
            if name not in env: env[name] = self.fresh(['wide'] if name in self.wide_names else [])
            return env[name]
        if kind == 'number_literal':
            n = number(txt(node))
            if n is not None:
                self.events.append((self.root, 'constant', n, node.start_byte))
                return ('constant', n)
            return self.fresh()
        if kind in {'parenthesized_expression', 'cast_expression', 'extension_expression'}:
            value=self.expr(node.named_children[-1], env, depth+1) if node.named_children else self.fresh()
            if kind=='cast_expression' and txt(node.child_by_field_name('type')) in {'unsignedchar','uint8_t','u8','byte'}:
                self.events.append((self.root,'and',None,self.site if self.site is not None else node.start_byte))
                from .linear import truncate
                value = truncate(value, 8)
            return value
        if kind=='compound_statement':
            # GNU statement expressions evaluate to the final expression;
            # declarations are private to the expression's lexical scope.
            local=dict(env);children=node.named_children
            if not children or children[-1].type!='expression_statement':return self.fresh()
            for statement in children[:-1]:self.statements(statement,local,0)
            final=children[-1].named_children
            return self.expr(final[-1],local,depth+1) if final else self.fresh()
        if kind=='update_expression':
            argument=node.child_by_field_name('argument')
            name=self.key(argument)
            old=env.get(name)
            if old and old[0]=='table_pointer':
                from ..source_pointers import advance
                op=txt(node.child_by_field_name('operator'))
                updated=advance(old,1 if op=='++' else -1) if op in {'++','--'} else None
                env[name]=updated or self.fresh()
                return old if node.named_children and node.named_children[0]==argument else env[name]
        if kind=='unary_expression':
            argument=node.child_by_field_name('argument')
            operator=node.child_by_field_name('operator')
            value=self.expr(argument,env,depth+1)
            op=txt(operator)
            if value[0]=='constant' and op in {'+','-','~'}:
                n=value[1]
                return ('constant',n if op=='+' else -n if op=='-' else (~n)&0xffffffff)
            out = self.fresh()
            if op == '~':self.arithmetic.rounds.remember('not', [value], out)
            return out
        if kind=='pointer_expression' and txt(node).startswith('&'):
            argument=node.child_by_field_name('argument')
            name=txt(argument)
            if name in self.constants:return ('constant_pointer',self.constants[name])
            if argument and argument.type=='subscript_expression':
                base=txt(argument.child_by_field_name('argument'))
                if base in self.tables:return ('table_pointer',self.tables[base])
            return self.fresh()
        if kind in {'binary_expression', 'assignment_expression'}:
            left, right = node.child_by_field_name('left'), node.child_by_field_name('right')
            opnode = node.child_by_field_name('operator'); op = opnode.text.decode() if opnode else ''
            a = self.fresh() if kind=='assignment_expression' and op=='=' else self.expr(left,env,depth+1)
            b = self.expr(right,env,depth+1)
            if kind == 'assignment_expression' and op == '=': value = b
            elif op in {'^','^='}:
                value = numeric_op(a,b,'^') or xor(a,b); self.events.append((self.root,'xor',None,self.site if self.site is not None else opnode.start_byte))
                if value[0]=='unknown':
                    for constant,other in ((a,b),(b,a)):
                        if constant[0]=='constant' and constant[1]&0xffffffff==0xffffffff:
                            value=self.fresh()
                            self.arithmetic.rounds.remember('not',[other],value)
                            break
                if self.arrays.xor(a,b):self.events.append((self.root,'rc4_prga',None,self.site if self.site is not None else node.start_byte))
            elif op in {'|','|='}:
                from .binary_semantics import tags
                value = numeric_op(a,b,'|') or merge_shifts(a,b)
                if value[0]=='unknown':value=self.fresh(tags(a)|tags(b))
                self.arithmetic.rounds.remember('or', [a,b], value)
            elif op in {'<<','>>'} and b[0] == 'constant':
                value = numeric_op(a,b,op) or (a if b[1]==0 else shift(a, 'left' if op=='<<' else 'right', b[1]))
            else:
                from .binary_semantics import tags
                value = numeric_op(a,b,op) or self.fresh(tags(a)|tags(b)|({'add'} if op in {'+','+='} else set()))
                if op in {'+','+=','-','-='} and b[0]=='constant':
                    from ..source_pointers import advance
                    value=advance(a,b[1]*(-1 if op in {'-','-='} else 1)) or value
                if op in {'&','&='} and b==('constant',0xffffffff):value=a
                elif op in {'&','&='} and b[0]=='constant':
                    from .linear import bits
                    word = bits(a)
                    if word is not None:
                        value = ('bits', tuple(atoms if b[1] & (1 << i) else frozenset()
                                               for i, atoms in enumerate(word)))
                if op in {'&','&='} and b==('constant',255):self.arrays.mask(value,a,8)
                if op=='%' and b==('constant',256):self.arrays.mask(value,a,8)
                if op in {'+','+='}:self.arithmetic.add(a,b,value)
                if op in {'+','+='}: self.events.append((self.root,'add',None,self.site if self.site is not None else opnode.start_byte))
                if op in {'&','&='}: self.events.append((self.root,'and',None,self.site if self.site is not None else opnode.start_byte))
                if op in {'&','&='}:self.arithmetic.rounds.remember('and', [a,b], value)
            if value[0]=='unknown': value=self.fresh()
            if kind=='assignment_expression':
                env[self.key(left)] = value
                if op=='=' and left.type in {'subscript_expression','field_expression'} and value[0]=='constant' and value[1] in SHA256_IV:
                    self.events.append((self.root,'iv_store',value[1],self.site if self.site is not None else node.start_byte))
                if left.type=='subscript_expression':
                    index=self.expr(left.child_by_field_name('index'),env,depth+1)
                    if self.arrays.output(value):self.events.append((self.root,'rc4_prga',None,self.site if self.site is not None else node.start_byte))
                    base=self.key(left.child_by_field_name('argument'))
                    for role,detail in self.schedules.store(base,schedule_index(left.child_by_field_name('index'),env,self.key),value):
                        self.events.append((self.root,role,detail,self.site if self.site is not None else node.start_byte))
                    self.arrays.store(base,index,value,self.site if self.site is not None else node.start_byte)
            self.record(value,node)
            return value
        if kind=='call_expression':
            name=call_name(node); argsnode=node.child_by_field_name('arguments')
            if env.get(name,('',))[0]=='callable':name=env[name][1]
            args=list(argsnode.named_children) if argsnode else []
            # In a separately parsed macro body, (word_type)(x) is ambiguous
            # to tree-sitter and can look like a call. Resolve it only through
            # actual typedef chains (including local headers), never spelling
            # heuristics such as a type name containing "32".
            cast=re.fullmatch(r'\(([A-Za-z_]\w*)\)',name)
            cast_type=self.aliases.get(cast[1],cast[1]) if cast else None
            if cast and len(args)==1 and env.get(cast_type,('type',))[0]=='type' and cast_type not in self.functions:
                scalar=self.scalar_types.get(cast_type);seen=set()
                while isinstance(scalar,str) and scalar not in seen:
                    seen.add(scalar);scalar=self.scalar_types.get(scalar)
                if scalar in {8,16,32,64}:
                    value=self.expr(args[0],env,depth+1)
                    if scalar==64:return self.fresh(['wide'])
                    if scalar<32:
                        from .linear import truncate
                        return truncate(value,scalar)
                    return value
            hardware={'vsm4eq_u32':('sm4e',2),'vsm4ekeyq_u32':('sm4ekey',2),
                      'vsm3ss1q_u32':('sm3ss1',3),'vsm3tt1aq_u32':('sm3tt1a',4),
                      'vsm3tt1bq_u32':('sm3tt1b',4),'vsm3tt2aq_u32':('sm3tt2a',4),
                      'vsm3tt2bq_u32':('sm3tt2b',4),'vsm3partw1q_u32':('sm3partw1',3),
                      'vsm3partw2q_u32':('sm3partw2',3)}
            if name in hardware and name not in self.functions and name not in self.macros and len(args)==hardware[name][1]:
                for arg in args:self.expr(arg,env,depth+1)
                self.events.append((self.root,'crypto_instruction',hardware[name][0],self.site if self.site is not None else node.start_byte))
                return self.fresh()
            if name in {'memcpy','memmove','mutils_memcpy'} and name not in self.functions and name not in self.macros and len(args)>=3:
                base=txt(args[1]).removeprefix('&').removesuffix('[0]')
                size=txt(args[2])
                dest=txt(args[0])
                if self.table_kind(base)=='sha256_iv' and (number(size)==32 or size in {'sizeof('+base+')','sizeof'+base,'sizeof'+dest,'sizeof('+dest+')'}):
                    self.events.append((self.root,'table_read','sha256_iv',self.site if self.site is not None else node.start_byte))
            self.calls.append((self.root,name,[txt(a) for a in args],self.site if self.site is not None else node.start_byte))
            values=[self.expr(n,env,depth+1) for n in args]
            if name in {'pgm_read_dword','pgm_read_byte'} and name not in self.functions and name not in self.macros and len(values)==1:
                if values[0][0]=='constant_pointer':
                    n=values[0][1];self.events.append((self.root,'constant',n,self.site if self.site is not None else node.start_byte))
                    return ('constant',n)
                if values[0][0]=='table_pointer':
                    role=values[0][1];self.events.append((self.root,'table_read',role,self.site if self.site is not None else node.start_byte))
                    return self.fresh([role])
            target=self.macros.get(name) or (self.functions.get(name) if name not in self.ambiguous_functions else None)
            lexical_site=self.lexical_site if self.lexical_site is not None else node.start_byte
            if name in self.macro_versions:
                preceding=[t for t in self.macro_versions[name] if t[2].start_byte<=lexical_site]
                target=preceding[-1] if preceding else self.context_macros.get(name)
            if target and name not in self.macros:
                nodes=list(walk(target[1]))
                if (len(target[1].text)>4096 or
                    any(n.type in {'for_statement','while_statement','do_statement','switch_statement'} for n in nodes) or
                    sum(n.type=='call_expression' for n in nodes)>16):target=None
            if target and self.inline_depth < 8:
                params,body,definition=target
                instantiated=False
                if name in self.macros:
                    template=definition.child_by_field_name('value')
                    if template and b'##' in template.text:
                        expanded=template.text.replace(b'\\\n',b' ').replace(b'\\\r\n',b' ')
                        substitutions={p.encode():self.key(a).encode() for p,a in zip(params,args)}
                        expanded=re.sub(rb'\b[A-Za-z_]\w*\b',
                                        lambda m:substitutions.get(m[0],m[0]),expanded)
                        expanded=re.sub(rb'\s*##\s*',b'',expanded)
                        if b'#' in expanded:return self.fresh()
                        expression=b';' not in expanded and not expanded.strip().startswith(b'do')
                        wrapped=b'int helper(){'+(b'return ' if expression else b'')+expanded+b';}'
                        tree=parser(self.cpp).parse(wrapped)
                        function=next((n for n in walk(tree.root_node) if n.type=='function_definition'),None)
                        if function is None or function.has_error:return self.fresh()
                        body=function.child_by_field_name('body')
                        instantiated=True
                # A macro shares the caller's bindings; a function does not.
                local=dict(env) if instantiated else {**env,**dict(zip(params,values))}
                old_aliases=self.aliases
                self.aliases={} if instantiated else {p:self.key(a).lstrip('&') for p,a in zip(params,args)}
                # Parameters taking constant indices need substitution into
                # array lvalues; value-only parameters retain private bindings.
                pointer_params={p for p in params if re.search(r'\b'+re.escape(p)+r'\s*\[|\*\s*'+re.escape(p)+r'\b',definition.text.decode(errors='replace').split('{',1)[0])}
                if name not in self.macros:
                    self.aliases={p:(str(v[1]) if v[0]=='constant' else self.aliases[p]) for p,v in zip(params,values) if p in pointer_params or v[0]=='constant'}
                if not instantiated:
                    for p,v in zip(params,values):local[self.aliases.get(p,p)]=v
                previous=self.site
                previous_lexical=self.lexical_site
                self.lexical_site=lexical_site if name in self.macros else None
                self.site=previous if previous is not None else node.start_byte
                self.inline_depth+=1
                try:ret=self.statements(body,local,0)
                finally:
                    self.inline_depth-=1
                    self.aliases=old_aliases
                    self.lexical_site=previous_lexical
                self.site=previous
                if name in self.macros:
                    env.update(local)
                elif pointer_params:
                    bases={self.key(a).lstrip('&') for p,a in zip(params,args) if p in pointer_params}
                    env.update({k:v for k,v in local.items() if any(k.startswith(base+'[') for base in bases)})
                if ret is not None:
                    self.record(ret,node); return ret
            # std::rotl/std::rotr are the C++20 standard operation, provided
            # there is no local definition shadowing this exact spelling.
            if name in {'std::rotl','std::rotr'} and len(values)==2 and values[1][0]=='constant':
                count=values[1][1]*(1 if name.endswith('rotl') else -1)
                self.events.append((self.root,'rotate',count%32,node.start_byte))
                return rotate(values[0],count)
            if name in {'__builtin_rotateleft32','__builtin_rotateright32'} and name not in self.functions and name not in self.macros and len(values)==2 and values[1][0]=='constant':
                count=values[1][1]*(1 if name=='__builtin_rotateleft32' else -1)
                self.events.append((self.root,'rotate',count%32,node.start_byte))
                return rotate(values[0],count)
            # Unknown callees may write a pointer variable passed by address.
            # Const table storage itself remains verified; the alias escapes.
            for argument in args:
                if argument.type=='pointer_expression' and txt(argument.child_by_field_name('operator'))=='&':
                    variable=argument.child_by_field_name('argument')
                    if variable is not None and variable.type=='identifier':env.pop(self.key(variable),None)
            self.reset_arrays()
            return self.fresh()
        # Traverse unknown operations so genuine nested calls are still visible;
        # their result is unknown, never guessed from its name.
        for child in node.named_children: self.expr(child,env,depth+1)
        return self.fresh()

    def record(self,value,node):
        from .binary_semantics import tags
        from .linear import role_tags
        site=self.site if self.site is not None else node.start_byte
        round_witness = self.table_rounds.witness(value)
        if round_witness:
            self.events.append((self.root, 'sm4_table_round', round_witness['input_word'], site))
            if round_witness['feedback']:
                self.events.append((self.root, 'sm4_table_feedback', round_witness['input_word'], site))
        if self.arithmetic.rounds.witness(value):
            self.events.append((self.root, 'sha256_round', 'bound_sigma_choice_majority_T1_T2', site))
        for role in roles(value):
            self.events.append((self.root,role,role_tags(value,role),site))
        if value[0]=='lin' and len(value[1])==1:
            (_,r),=value[1]
            if r: self.events.append((self.root,'rotate',r,site))
        if value[0]=='lin' and any(r==7 for _,r in value[1]) and self.arithmetic.quarter(value):
            self.events.append((self.root,'chacha_quarter',None,site))

    def statements(self,node,env,depth=0):
        if not node or depth>32:return None
        if node.type=='ERROR':return None
        if node.type=='return_statement':
            return self.expr(node.named_children[0],env,depth+1) if node.named_children else None
        if node.type=='init_declarator':
            name=self.key(node.child_by_field_name('declarator')).lstrip('*')
            value=self.expr(node.child_by_field_name('value'),env,depth+1)
            env[name]=value;self.record(value,node);return None
        if node.type in {'expression_statement','condition_clause'}:
            for c in node.named_children:self.expr(c,env,depth+1)
            return None
        if node.type=='if_statement':
            self.controlflow['branches']+=1
            condition=node.child_by_field_name('condition')
            if condition:self.expr(condition,env,depth+1)
            before=dict(env);outputs=[]
            for field in ('consequence','alternative'):
                local=dict(before);self.reset_arrays()
                self.statements(node.child_by_field_name(field),local,depth+1)
                outputs.append(local)
            env.clear();env.update({k:v for k,v in outputs[0].items() if outputs[1].get(k)==v})
            self.controlflow['joins']+=1;self.reset_arrays()
            return None
        if node.type in {'for_statement','while_statement','do_statement'}:
            self.controlflow['loops']+=1
            local=dict(env)
            self.statements(node.child_by_field_name('initializer'),local,depth+1)
            body=node.child_by_field_name('body')
            # A loop-carried scalar is symbolic at its header; never substitute
            # the first iteration's constant into all subsequent iterations.
            modified=set()
            loop_nodes=list(walk(body)) if body else []
            update=node.child_by_field_name('update')
            if update:loop_nodes.extend(walk(update))
            for child in loop_nodes:
                if child.type=='assignment_expression':
                    left=child.child_by_field_name('left')
                    if left and left.type=='identifier':modified.add(self.key(left))
                elif child.type=='update_expression':
                    arg=child.child_by_field_name('argument')
                    if arg and arg.type=='identifier':modified.add(self.key(arg))
            from ..source_pointers import loop_ranges,induction_ranges
            pointers=loop_ranges(node,local,self.key)
            indices=induction_ranges(node,local,self.key)
            for key in modified:local[key]=pointers.get(key) or indices.get(key) or self.fresh()
            self.reset_arrays()
            condition=node.child_by_field_name('condition')
            if condition:self.expr(condition,local,depth+1)
            self.statements(body,local,depth+1)
            self.statements(node.child_by_field_name('update'),local,depth+1)
            for key in modified:env.pop(key,None)
            self.reset_arrays()
            return None
        if node.type=='switch_statement':
            for c in node.named_children:
                self.reset_arrays()
                self.statements(c,dict(env),depth+1)
            self.reset_arrays()
            return None
        if node.type in {'binary_expression','assignment_expression','call_expression','number_literal'}:
            self.expr(node,env,depth+1);return None
        result=None
        for c in node.named_children:
            ret=self.statements(c,env,depth+1)
            if ret is not None:result=ret
        return result

    def run(self):
        total=0
        for name,(params,body,node) in self.functions.items():
            if name not in self.entry_functions:continue
            self.root=name
            self.reset_arrays()
            self.node_visits=0
            event_start=len(self.events);call_start=len(self.calls)
            # Parameters shadow global table/type identifiers. Initialize their
            # bindings before interpreting the body, just as local declarations
            # shadow a verified constant array.
            initial={p:self.fresh(['wide'] if p in self.wide_names else []) for p in params if p}
            initial.update(self.bound_initials.get(name,{}))
            try:self.statements(body,initial,0)
            except ValueError:
                self.function_limits.append(name)
                del self.events[event_start:];del self.calls[call_start:]
            self.function_visits[name]=self.node_visits
            total+=self.node_visits
            if total>MAX_TOTAL_NODES:
                self.node_visits=total
                raise ValueError('Source total operation node budget exhausted')
        self.node_visits=total

    def findings(self):
        found=[]
        from ..curve_exchange import source_xhat_helpers
        xhat_helpers=source_xhat_helpers(self)
        self.general_equations=[]
        self.operation_events=list(self.events)
        # Re-visiting an expression during local inlining is not another round.
        self.events=list(dict.fromkeys((f,r,tuple(v) if isinstance(v,list) else v,p) for f,r,v,p in self.events))
        for name,(_,body,definition) in self.functions.items():
            if name not in self.entry_functions or body is None:continue
            # Malformed unrelated macro/preprocessor regions cannot supply a
            # whole-function round witness. Well-formed calls collected outside
            # ERROR nodes may still form an explicit arithmetic equation.
            events=[e for e in self.events if e[0]==name] if not body.has_error else []
            count=Counter(e[1] for e in events)
            rots={e[2] for e in events if e[1]=='rotate'}
            const={e[2] for e in events if e[1]=='constant'}
            witness=[{'role':r,'detail':v,'offset':p} for _,r,v,p in events
                     if r.startswith('sm') or r=='table_read'][:64]
            isa={v for _,r,v,_ in events if r=='crypto_instruction'}
            complete_sm4_rounds=len({p for _,r,v,p in events if r=='crypto_instruction' and v=='sm4e'})>=8
            if any(r == 'sm4_table_feedback' for _, r, v, _ in events):
                found.append(('SM4', name, definition.start_byte,
                              [{'role': r, 'detail': v, 'offset': p} for _, r, v, p in events if r == 'sm4_table_round'],
                              'Repeated exact four-byte SM4 tau+L table transformations with pre-expanded round keys'))
            if {'sm4e','sm4ekey'}<=isa or complete_sm4_rounds:
                found.append(('SM4',name,definition.start_byte,
                              [{'role':r,'detail':v,'offset':p} for _,r,v,p in events if r=='crypto_instruction'],
                              'Actual non-shadowed ACLE SM4 round/key calls or all eight four-round SM4 intrinsic groups'))
            if {'sm3ss1','sm3tt1a','sm3tt1b','sm3tt2a','sm3tt2b','sm3partw1','sm3partw2'}<=isa:
                found.append(('SM3',name,definition.start_byte,
                              [{'role':r,'detail':v,'offset':p} for _,r,v,p in events if r=='crypto_instruction'],
                              'Actual non-shadowed ACLE SM3 schedule and both round families'))
            if (any(e[1]=='sm3_p0' and 'add' in e[2] for e in events) and count['sm3_p1'] and {7,12,19}<=rots
                    and count['add']>=8 and count['xor']>=8
                    and count['and']>=2
                    and (64 in const or count['sm3_p0']>=8)):
                found.append(('SM3',name,definition.start_byte,witness,'Locally resolved P0/P1, SM3 round rotations and arithmetic/round bound'))
            block=[e for e in events if e[1]=='sm4_l' and 'sbox' in e[2]]
            # Key and block operations may be separate definitions in the same
            # translation unit, but must each actually read the verified table.
            keys=[e for e in self.events if e[1]=='sm4_key_l' and 'sbox' in e[2]]
            ck=any(e[1]=='table_read' and e[2]=='ck' for e in self.events)
            if block and keys and ck and (32 in const or len({e[3] for e in events if e[1]=='sm4_l'})>=8):
                found.append(('SM4',name,definition.start_byte,witness,'Full standard S-box and CK are read by block/key operations with dependent L/L-prime'))
            t=Counter(e[2] for e in events if e[1]=='table_read')
            kt=Counter(e[2] for e in self.events if e[1]=='table_read')
            if t['block_table']>=4 and count['xor']>=4 and kt['key_table']>=4 and ck:
                found.append(('SM4',name,definition.start_byte,witness,'Complete standard SM4 L and L-prime tables used by XOR block/key transformations'))
            # OpenSSL BN API: r=e+x(kG), followed by SM2-style s computation,
            # or verification t=r+s, combined point, then r'=e+x and compare.
            calls=[c for c in self.calls if c[0]==name]
            equations=ConventionalEquations(self.functions)
            pointer_bindings=[]
            for assignment in walk(body):
                if assignment.type=='assignment_expression' and txt(assignment.child_by_field_name('operator'))=='=':
                    left=assignment.child_by_field_name('left');right=assignment.child_by_field_name('right')
                elif assignment.type=='init_declarator':
                    left=assignment.child_by_field_name('declarator');right=assignment.child_by_field_name('value')
                else:continue
                if left is not None and left.type=='identifier' and right is not None:
                    pointer_bindings.append((assignment.start_byte,txt(left),txt(right)))
            pointer_bindings.sort();aliases={};binding_index=0
            for init in walk(body):
                if init.type!='init_declarator':continue
                value=init.child_by_field_name('value')
                if value and value.type!='call_expression':
                    expression=txt(value).lstrip('&')
                    variable=txt(init.child_by_field_name('declarator')).lstrip('*')
                    if expression.endswith(('->G','.G')):equations.peer_points['generator:'+variable]=expression.removesuffix('->G').removesuffix('.G')
                if not value or value.type!='call_expression':continue
                accessor=call_name(value);arguments=value.child_by_field_name('arguments')
                if accessor in self.functions or not arguments or not arguments.named_children:continue
                variable=txt(init.child_by_field_name('declarator')).lstrip('*')
                group=txt(arguments.named_children[0])
                if accessor=='EC_GROUP_get0_order':equations.group_orders[group]=variable
                elif accessor=='EC_GROUP_get_mont_data':equations.mont_groups[variable]=group
            for _,operation,arguments,site in calls:
                while binding_index<len(pointer_bindings) and pointer_bindings[binding_index][0]<site:
                    _,variable,value=pointer_bindings[binding_index];binding_index+=1
                    aliases.pop(variable,None)
                    if value.startswith('&'):
                        value=value[1:]
                        while value.startswith('(') and value.endswith(')'):value=value[1:-1]
                        aliases[variable]=value
                def actual(argument):
                    argument=argument.lstrip('&')
                    while argument.startswith('(') and argument.endswith(')'):argument=argument[1:-1]
                    for variable,value in aliases.items():
                        if argument==variable:return value
                        if argument.startswith(variable+'->'):return value+argument[len(variable):]
                    return argument
                actual_args=[actual(a) for a in arguments]
                helper=xhat_helpers.get(operation)
                if helper and len(actual_args)==2:
                    equations.exchange.xhat(actual_args[helper['output_parameter']],actual_args[helper['point_parameter']],site,helper['proof'])
                else:equations.feed(operation,actual_args,site)
            for match in equations.general_matches:
                if match['algorithm']=='SM2':
                    found.append(('SM2',name,definition.start_byte,match['operation_witnesses'],match['equation']));continue
                self.general_equations.append((match['algorithm'],match['offset'],
                    [(w['offset'],'bignum_equation',w) for w in match['operation_witnesses']],match['equation']))
            if equations.matches:
                match=equations.matches[0]
                found.append(('SM2',name,definition.start_byte,match['operation_witnesses'],
                              'Related big-number operations witness '+match['equation']))
        return found

    def general_findings(self):
        found=list(getattr(self,'general_equations',[]))
        events_all=getattr(self,'operation_events',self.events)
        all_constants={v&0xffffffff for _,r,v,_ in events_all if r=='iv_store' and isinstance(v,int)}
        iv=set(SHA256_IV)<=all_constants
        for name,(_,body,definition) in self.functions.items():
            events=[(p,r,v) for f,r,v,p in events_all if f==name]
            used_iv=iv or any(r=='table_read' and v=='sha256_iv' for _,r,v,_ in events_all)
            if name in self.bound_initials:
                used_iv=any(p['bound_root']==name and p['descriptor_iv'] for p in self.linkage_plans)
            found.extend(recognize(events,sha256_variant=used_iv))
            if body.has_error:
                # Individual well-formed calls outside ERROR nodes remain
                # available even when an unrelated conditional block fails.
                eq=ConventionalEquations(self.functions)
                for f,op,args,site in self.calls:
                    if f==name:eq.feed(op,args,site)
                for m in eq.general_matches:
                    found.append((m['algorithm'],m['offset'],
                        [(w['offset'],'bignum_equation',w) for w in m['operation_witnesses']],m['equation']))
        from ..source_state import components
        connected,self.state_components=components(self)
        found.extend(connected)
        return found


def sm2_verify(calls):
    adds=[c for c in calls if c[1] in {'BN_mod_add','BN_mod_add_quick','BN_ModAdd','BN_ModAddQuick'} and len(c[2])>=4]
    points=[c for c in calls if c[1]=='EC_POINT_mul' and len(c[2])>=5]
    for first in adds:
        _,_,a,p=first;t,r,s=a[:3]
        for point in points:
            args=point[2]
            if len({t,r,s})!=3 or point[3]<=p or args[2]!=s or args[4]!=t:continue
            coords=[c for c in calls if c[1] in {'EC_POINT_get_affine_coordinates','EC_POINT_get_affine_coordinates_GFp'}
                    and len(c[2])>=3 and c[2][1]==args[1] and c[3]>point[3]]
            for second in adds:
                if second[3]<=point[3]:continue
                # r and s must be inputs, not a reused unrelated accumulator.
                if second[2][0]!=t:continue
                e,x=second[2][1:3]
                if e in {t,r,s} or not any(c[2][2]=='&'+x or c[2][2]==x for c in coords if c[3]<second[3]):continue
                if second[2][3]!=a[3]:continue
                compares=[c for c in calls if c[1] in {'BN_cmp','BN_Cmp'} and set(c[2][:2])=={t,r} and c[3]>second[3]]
                if compares:return True
    return False


def scan_source_semantics(path,report):
    from ..source import lex_cpp
    from ..text import decode_source
    raw=path.read_bytes()
    if len(raw)>MAX_SOURCE:
        error(report,'guomi_source_semantic','max_source_bytes','Source operation analysis size budget exhausted','partial');return
    text,_=decode_source(raw)
    code,_,_=lex_cpp(text)
    from .source_context import available_code,load_context,attach_context
    contexts,context_record=load_context(path,text)
    analysis=Analysis(available_code(text).encode(),path.suffix.lower() in {'.cpp','.cc','.cxx','.hpp','.hxx'} or path.name.endswith('.cc.inc'),
                      declaration_contexts=[c.raw for c in contexts])
    attach_context(analysis,contexts)
    from ..source_linkage import load_callers,bind
    linked,link_record=load_callers(path,analysis,contexts)
    attach_context(analysis,linked)
    plans=bind(analysis,[*contexts,*linked])
    for i,plan in enumerate(plans):
        root=plan['target']+'$parameter_binding'+str(i)
        analysis.functions[root]=analysis.functions[plan['target']]
        analysis.entry_functions.add(root)
        analysis.bound_initials[root]=plan['initial']
        analysis.linkage_plans.append({**plan,'bound_root':root})
    report['source_parameter_linkage']={**link_record,'bindings':analysis.linkage_plans}
    report['source_operation_context']=context_record
    report['source_declaration_expansions']=analysis.declaration_expansions
    try:analysis.run()
    except ValueError as exc:
        error(report,'guomi_source_semantic','analysis_limit',str(exc),'partial');return
    if analysis.function_limits:
        error(report,'guomi_source_semantic','function_analysis_limit',
              'Per-function node budget exhausted: '+', '.join(analysis.function_limits[:8]),'partial')
    seen=set()
    for algorithm,name,offset,witness,reason in analysis.findings():
        if algorithm in seen:continue
        seen.add(algorithm)
        report['findings'].append(evidence(algorithm,'guomi_source_semantic','source_operation_graph',name,
            line=code.encode()[:offset].count(b'\n')+1,offset=offset,source_role='definition',
            implementation_verification='bounded_standard_operation_graph',operation_witnesses=witness,
            offset_basis='lexed_utf8_source',
            confidence='medium',confidence_reason=reason))
    report['engine_status']['guomi_source_semantic']={'status':'completed','matched_algorithms':sorted(seen),
        'available_definitions':len(analysis.functions),'node_visits':analysis.node_visits,
        'function_limits':analysis.function_limits,'function_node_visits':analysis.function_visits}
    report['source_controlflow_analysis']=analysis.controlflow
    general=emit(report,analysis.general_findings(),'operation_source',source=True,code=analysis.raw)
    report.setdefault('operation_diagnostics', {})['source'] = {
        'event_counts': dict(Counter(r for _, r, _, _ in analysis.events)),
        'table_reads': dict(Counter(v for _, r, v, _ in analysis.events if r == 'table_read')),
        'definitions': [
            {'name': name, 'offset': definition.start_byte, 'parse_error': body.has_error,
             'limited': name in analysis.function_limits,
             'event_counts': dict(Counter(r for f, r, _, _ in analysis.events if f == name))}
            for name, (_, body, definition) in analysis.functions.items()
            if name in analysis.entry_functions and body is not None
        ],
        'stage': 'bounded_lifting_finished',
    }
    report['source_state_components']=getattr(analysis,'state_components',[])
    from ..static_primitives import source_equations
    static_matches,static_summaries,limb_witnesses=source_equations(analysis)
    general.update(emit(report,static_matches,'operation_source',source=True,code=analysis.raw))
    report['static_primitive_summaries']=static_summaries
    report['static_limb_witnesses']=limb_witnesses
    report['engine_status']['operation_source']={'status':'completed','matched_algorithms':sorted(general),
        'available_definitions':len(analysis.functions),'shared_analysis':'guomi_source_semantic'}
    report['coverage_notes'].append('Source operation graphs resolve bounded local header macros/scalar helpers at actual call sites; no full preprocessing. Evidence describes available source operations, not enabled compiled or runtime use.')
