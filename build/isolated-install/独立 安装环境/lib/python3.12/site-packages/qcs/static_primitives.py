"""Name-independent C arithmetic summaries and successful-path equations.

Scalar modulo expressions and one exact square-and-multiply recurrence are
summarised. Limb carry/borrow graphs are reported as primitive evidence only:
generic arithmetic alone never asserts a cryptographic algorithm. Unknown loops,
casts, aliasing and local calls are declined rather than assigned API semantics.
"""
from dataclasses import dataclass
import re
from .guomi.bignum import Value, OPERATIONS
from .operation_bignum import ConventionalEquations


def walk(node):
    if node is None:
        return
    yield node
    for child in node.named_children:
        yield from walk(child)


def text(node):
    return re.sub(r'\s+', '', node.text.decode(errors='replace')) if node else ''


def expression(node, env):
    if node is None or node.has_error:
        return None
    kind = node.type
    if kind == 'identifier':
        return env.get(text(node), ('symbol', text(node)))
    if kind == 'number_literal':
        from .guomi.source_semantics import number
        n = number(text(node))
        return ('integer', n) if n is not None else None
    if kind in {'parenthesized_expression', 'cast_expression'}:
        return expression(node.named_children[-1], env) if node.named_children else None
    if kind == 'binary_expression':
        op = text(node.child_by_field_name('operator'))
        a = expression(node.child_by_field_name('left'), env)
        b = expression(node.child_by_field_name('right'), env)
        if a is None or b is None:
            return None
        return (op, a, b)
    if kind in {'subscript_expression', 'field_expression'}:
        return ('symbol', text(node))
    return None


@dataclass
class Summary:
    kind: str
    parameters: list
    formula: tuple | None
    offset: int
    detail: str
    roles: tuple = ()


def scalar_summary(params, body, definition):
    # Only unsigned scalar input/output types; pointer narrowing and signed
    # overflow do not inherit mathematical modular-expression semantics.
    header = definition.text.decode(errors='replace').split('{', 1)[0]
    if '*' in header or '[' in header or not re.search(r'\b(unsigned|uint(?:32|64)_t|u(?:32|64))\b', header):
        return None
    # A narrowing cast can change the relation before the final remainder.
    if any(n.type=='cast_expression' for n in walk(body)):return None
    if any(n.type in {'if_statement', 'switch_statement', 'for_statement', 'while_statement',
                       'do_statement', 'call_expression'} for n in walk(body)):
        return None
    env = {p: ('parameter', i) for i, p in enumerate(params)}
    result = None
    for node in body.named_children:
        if node.type == 'declaration':
            for init in node.named_children:
                if init.type == 'init_declarator':
                    value = expression(init.child_by_field_name('value'), env)
                    if value is None:
                        return None
                    env[text(init.child_by_field_name('declarator'))] = value
        elif node.type == 'return_statement' and node.named_children:
            result = expression(node.named_children[0], env)
        else:
            return None
    if result is None or result[0] not in {'%', '+', '-', '*'}:
        return None
    return Summary('scalar_modular_expression', params, result, definition.start_byte,
                   'Exact unsigned local return expression; no unresolved calls or control flow')


def power_summary(params, body, definition):
    """Match the complete recurrence, not counts of multiplication/shift."""
    loops = [n for n in body.named_children if n.type == 'while_statement']
    if len(params) != 3 or len(loops) != 1:
        return None
    header = definition.text.decode(errors='replace').split('{', 1)[0]
    if '*' in header or not re.search(r'unsigned|uint(?:32|64)_t', header):
        return None
    loop = loops[0]
    if any(n.type not in {'declaration','while_statement','return_statement','comment'} for n in body.named_children):return None
    if any(n.type in {'cast_expression','call_expression'} for n in walk(body)):return None
    env = {p: ('parameter', i) for i, p in enumerate(params)}
    init = {}
    for node in body.named_children:
        if node.type == 'declaration':
            for n in walk(node):
                if n.type == 'init_declarator':
                    init[text(n.child_by_field_name('declarator'))] = expression(n.child_by_field_name('value'), env)
    returns = [n for n in body.named_children if n.type == 'return_statement']
    if len(returns) != 1 or not returns[0].named_children:
        return None
    accumulator = text(returns[0].named_children[0])
    if init.get(accumulator) != ('integer', 1):
        return None
    if any(p in init for p in params):return None
    condition = expression(loop.child_by_field_name('condition'), env)
    for exp in range(3):
        if condition not in {('parameter', exp), ('>', ('parameter', exp), ('integer', 0))}:
            continue
        for base in range(3):
            mod = 3 - base - exp
            if base == exp or mod not in range(3) or mod in {base, exp}:
                continue
            statements = loop.child_by_field_name('body').named_children
            if len(statements) != 3 or statements[0].type != 'if_statement':
                continue
            branch = statements[0]
            if branch.child_by_field_name('alternative') is not None:
                continue
            if expression(branch.child_by_field_name('condition'), env) != ('&', ('parameter', exp), ('integer', 1)):
                continue
            assignments = [n for n in walk(loop.child_by_field_name('body')) if n.type == 'assignment_expression']
            if len(assignments) != 3:
                continue
            equations = {text(n.child_by_field_name('left')):
                         (text(n.child_by_field_name('operator')), expression(n.child_by_field_name('right'), env))
                         for n in assignments}
            expected = {
                accumulator: ('=', ('%', ('*', ('symbol', accumulator), ('parameter', base)), ('parameter', mod))),
                params[base]: ('=', ('%', ('*', ('parameter', base), ('parameter', base)), ('parameter', mod))),
                params[exp]: ('>>=', ('integer', 1)),
            }
            if equations == expected:
                return Summary('modular_power', params, None, definition.start_byte,
                               'r=1; bit-selected r=r*b mod m; b=b*b mod m; exponent >>=1; return r',
                               (base, exp, mod))
    return None


def limb_facts(params, body, definition):
    """Recover related low/high limb updates without promoting a math helper."""
    facts = []
    for loop in (n for n in walk(body) if n.type == 'for_statement'):
        env = {};updates = [];stores = []
        for node in walk(loop.child_by_field_name('body')):
            if node.type == 'assignment_expression':
                left = node.child_by_field_name('left')
                value = expression(node.child_by_field_name('right'), env)
                operator = text(node.child_by_field_name('operator'))
                key = text(left)
                if operator != '=':
                    value = (operator[:-1], env.get(key, ('symbol', key)), value) if value is not None else None
                if value is None:
                    continue
                env[key] = value
                updates.append((key, value, node.start_byte))
                if left.type == 'subscript_expression':
                    stores.append((key, value))
        for carry, value, offset in updates:
            if value[0] != '>>' or value[2] is None:
                continue
            accumulator = value[1]
            if accumulator is None or accumulator[0] not in {'+', '-'}:
                continue
            # Both the low store and the extracted carry/borrow must be bound
            # to the very same accumulated value in this loop.
            masked = [(key, val) for key, val in stores if val and
                      (val == accumulator or (val[0] == '&' and val[1] == accumulator))]
            if not masked:
                continue
            facts.append({'kind': 'limb_carry' if accumulator[0] == '+' else 'limb_borrow',
                          'offset': offset, 'loop_offset': loop.start_byte, 'carry_variable': carry,
                          'low_stores': [key for key, _ in masked], 'high_shift': value[2],
                          'recurrence': accumulator, 'classification': 'primitive_only'})
    return facts


def inverse_summary(params, body, definition):
    """Extended Euclid with two linked coefficient/remainder recurrences."""
    if len(params)!=2:return None
    loops=[n for n in body.named_children if n.type=='while_statement']
    returns=[n for n in body.named_children if n.type=='return_statement']
    if len(loops)!=1 or len(returns)!=1 or not returns[0].named_children:return None
    if any(n.type not in {'declaration','while_statement','if_statement','return_statement','comment'} for n in body.named_children):return None
    if any(n.type in {'cast_expression','call_expression'} for n in walk(body)):return None
    output=text(returns[0].named_children[0]);init={}
    for n in body.named_children:
        if n.type=='declaration':
            for x in walk(n):
                if x.type=='init_declarator':init[text(x.child_by_field_name('declarator'))]=expression(x.child_by_field_name('value'),{})
    if init.get(output)!=('integer',0):return None
    loop=loops[0];condition=expression(loop.child_by_field_name('condition'),{})
    for a in range(2):
        mod=1-a
        other=[key for key,value in init.items() if value==('integer',1)]
        remainders=[key for key,value in init.items() if value==('symbol',params[mod])]
        new_remainders=[key for key,value in init.items() if value==('symbol',params[a])]
        for nt in other:
            for r in remainders:
                for nr in new_remainders:
                    if condition not in {('symbol',nr),('!=',('symbol',nr),('integer',0))}:continue
                    env={};assignments=[]
                    for n in walk(loop.child_by_field_name('body')):
                        if n.type not in {'init_declarator','assignment_expression'}:continue
                        left=n.child_by_field_name('declarator') if n.type=='init_declarator' else n.child_by_field_name('left')
                        right=n.child_by_field_name('value') if n.type=='init_declarator' else n.child_by_field_name('right')
                        value=expression(right,env)
                        if value is None:return None
                        env[text(left)]=value;assignments.append((text(left),value))
                    quotient=('/',('symbol',r),('symbol',nr))
                    expected={output:('symbol',nt),nt:('-',('symbol',output),('*',quotient,('symbol',nt))),
                              r:('symbol',nr),nr:('-',('symbol',r),('*',quotient,('symbol',nr)))}
                    if not all(env.get(k)==v for k,v in expected.items()):continue
                    # Additional writes in the loop must be quotient or the
                    # two temporary recurrences, never external stores/calls.
                    allowed=set(expected.values())|{quotient}
                    if any(v not in allowed for _,v in assignments):continue
                    if any(n.type in {'call_expression','if_statement','for_statement'} for n in walk(loop.child_by_field_name('body'))):continue
                    corrections=[n for n in body.named_children if n.type=='if_statement']
                    if len(corrections)!=1:continue
                    correction=corrections[0]
                    if expression(correction.child_by_field_name('condition'),{})!=('<',('symbol',output),('integer',0)):continue
                    updates=[n for n in walk(correction.child_by_field_name('consequence')) if n.type=='assignment_expression']
                    if len(updates)!=1:continue
                    u=updates[0]
                    if text(u.child_by_field_name('left'))!=output or text(u.child_by_field_name('operator'))!='+=' or text(u.child_by_field_name('right'))!=params[mod]:continue
                    if correction.child_by_field_name('alternative') is not None:continue
                    return Summary('modular_inverse',params,None,definition.start_byte,
                                   'Extended Euclid quotient plus both linked remainder/coefficient updates and modulus correction', (a,mod))
    return None


def summaries(analysis):
    result = {};facts = []
    for name, (params, body, definition) in analysis.functions.items():
        if body is None or body.has_error or name in analysis.function_limits:
            continue
        summary = None if name in analysis.ambiguous_functions or '@' in name else (scalar_summary(params, body, definition) or power_summary(params, body, definition)
                   or inverse_summary(params,body,definition))
        if summary:
            result[name] = summary
        if name in analysis.entry_functions:
            facts.extend({'function_offset': definition.start_byte, **f} for f in limb_facts(params, body, definition))
    return result, facts


def formula_value(formula, args, eq, site):
    if formula is None:
        return None
    op = formula[0]
    if op == 'parameter':
        return args[formula[1]] if formula[1] < len(args) else None
    if op == 'integer':
        return Value.constant(formula[1])
    if op not in {'+', '-', '*', '%'}:
        return None
    a = formula_value(formula[1], args, eq, site)
    b = formula_value(formula[2], args, eq, site)
    if a is None or b is None:
        return None
    if op == '%':
        mod = b.atom()
        return Value(a.num, a.den, frozenset({mod})) if mod else None
    return a.op(b, {'+': 'add', '-': 'sub', '*': 'mul'}[op])


def source_equations(analysis):
    """Compose exact local scalar summaries; exported names are irrelevant."""
    summary_map, facts = summaries(analysis)
    matches = []
    for name in analysis.entry_functions:
        params, body, definition = analysis.functions[name]
        eq = ConventionalEquations(analysis.functions)
        def evaluate(node, depth=0):
            if node is None or node.has_error or depth > 24:
                return None
            kind = node.type
            if kind in {'identifier', 'field_expression', 'subscript_expression'}:
                return eq.get(text(node))
            if kind == 'number_literal':
                from .guomi.source_semantics import number
                n = number(text(node));return Value.constant(n) if n is not None else None
            if kind in {'parenthesized_expression', 'cast_expression'}:
                return evaluate(node.named_children[-1], depth + 1) if node.named_children else None
            if kind == 'binary_expression':
                a = evaluate(node.child_by_field_name('left'), depth + 1)
                b = evaluate(node.child_by_field_name('right'), depth + 1)
                op = text(node.child_by_field_name('operator'))
                if a is None or b is None:
                    return None
                if op == '%':
                    mod = b.atom()
                    return Value(a.num, a.den, frozenset({mod})) if mod else None
                if op in {'+', '-', '*'}:
                    return a.op(b, {'+': 'add', '-': 'sub', '*': 'mul'}[op])
                return None
            if kind == 'call_expression':
                called = text(node.child_by_field_name('function'))
                summary = summary_map.get(called)
                if summary is None:
                    return None
                argnode = node.child_by_field_name('arguments')
                args = [evaluate(a, depth + 1) for a in argnode.named_children] if argnode else []
                if len(args) != len(summary.parameters) or any(a is None for a in args):
                    return None
                site = node.start_byte
                eq.history.append({'operation': summary.kind, 'arguments': [text(a) for a in argnode.named_children],
                                   'offset': site, 'definition_offset': summary.offset, 'proof': summary.detail})
                if summary.kind == 'modular_power':
                    base, exp, mod = summary.roles
                    modulus = args[mod].atom()
                    if not modulus:
                        return None
                    result = Value.symbol('static-power@' + str(site));result.moduli = frozenset({modulus})
                    eq.powers.append((result, args[base], args[exp], modulus, site))
                    return result
                if summary.kind=='modular_inverse':
                    a,mod=summary.roles;modulus=args[mod].atom()
                    if not modulus:return None
                    eq.inverses.append((args[a],modulus,site))
                    return args[a].inverse(modulus)
                return formula_value(summary.formula, args, eq, site)
            return None
        # Bounded successful-operation order, preserving the same caveat as
        # imported-API equations. We do not assign semantics to generic ECC.
        for node in walk(body):
            if node.type not in {'init_declarator', 'assignment_expression'}:
                continue
            left = node.child_by_field_name('declarator') if node.type == 'init_declarator' else node.child_by_field_name('left')
            right = node.child_by_field_name('value') if node.type == 'init_declarator' else node.child_by_field_name('right')
            if left is None or right is None:
                continue
            try:
                value = evaluate(right)
                if value is None:
                    eq.values[text(left)] = Value.symbol('unknown@' + str(node.start_byte))
                    continue
                eq.values[text(left)] = value
                if value.den=={():1}:
                    atoms=[(monomial[0],coefficient) for monomial,coefficient in value.num.items() if len(monomial)==1]
                    if len(value.num)==2 and len(atoms)==2 and all(c==1 for _,c in atoms) and len(value.moduli)==1:
                        n=next(iter(value.moduli));a,b=[Value.symbol(k) for k,_ in atoms]
                        eq.sums.append((text(left),a,b,value,n,node.start_byte))
                    if len(value.num)==2 and len(atoms)==1 and atoms[0][1]==1 and value.num.get(())==1:
                        eq.ones.append((Value.symbol(atoms[0][0]),value,node.start_byte))
                eq.signature(text(left),value,node.start_byte)
                # CRT recombination is only classified after both powers share
                # an input and the explicit correction modulus is present.
                for m1, c1, e1, p, s1 in eq.powers:
                    for m2, c2, e2, q, s2 in eq.powers:
                        if p == q or not c1.equal(c2):
                            continue
                        for coefficient in value.symbols() - m1.symbols() - m2.symbols():
                            h = m1.op(m2, 'sub').op(Value.symbol(coefficient), 'mul', p)
                            if value.moduli == {p} and value.equal(h):
                                eq.crt_remainders.append((value, m2, q, node.start_byte))
                for h, m2, q, origin in eq.crt_remainders:
                    if origin < node.start_byte and value.equal(m2.op(h.op(Value.symbol(q), 'mul'), 'add')):
                        eq.match('RSA', 'Static square-and-multiply powers and CRT correction/recombination over p,q',
                                 origin, 'static_primitive_crt')
            except (ValueError, TypeError):
                eq.values[text(left)] = Value.symbol('unknown@' + str(node.start_byte))
        matches.extend((m['algorithm'], m['offset'], [(w['offset'], 'static_primitive_equation', w)
                        for w in m['operation_witnesses']], m['equation']) for m in eq.general_matches)
        matches.extend(('SM2',m['offset'],[(w['offset'],'static_primitive_equation',w)
                        for w in m['operation_witnesses']],m['equation']) for m in eq.matches)
    return matches, [{'kind': s.kind, 'definition_offset': s.offset, 'proof': s.detail}
                     for s in summary_map.values()], facts
