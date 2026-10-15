"""Bounded reverse calls and descriptor-bound source table parameters.

Only neighbouring source files are searched. Actual AST calls supply parameters;
two fields of the same descriptor must bind the initializer and update wrapper.
Names and comments supply no algorithm evidence. Context files are provenance,
not additional labelled implementations or independently scanned entry roots.
"""
import hashlib
import re


def initializer(analysis, function):
    """Prove eight position-preserving IV stores through straight local calls."""
    from .guomi.source_semantics import walk, txt, number, call_name
    stores = {}

    def run(name, arguments, depth):
        if depth > 4 or name not in analysis.functions or name in analysis.ambiguous_functions:
            return False
        parameters, body, _ = analysis.functions[name]
        if body is None or body.has_error or len(body.text) > 2048:
            return False
        if any(n.type in {'if_statement', 'for_statement', 'while_statement', 'do_statement', 'switch_statement'} for n in walk(body)):
            return False
        env = dict(zip(parameters, arguments))

        def expr(node):
            if node is None:
                return None
            if node.type in {'cast_expression', 'parenthesized_expression'}:
                return expr(node.named_children[-1])
            if node.type == 'identifier':
                key = txt(node)
                if key in env:
                    return env[key]
                if analysis.tables.get(key) == 'sha256_iv':
                    return ('table', key, 0)
            if node.type == 'subscript_expression':
                base = expr(node.child_by_field_name('argument'))
                index = number(txt(node.child_by_field_name('index')))
                if base and index is not None:
                    return (*base[:2], base[2] + index)
            return None

        for node in walk(body):
            if node.type == 'init_declarator':
                env[txt(node.child_by_field_name('declarator')).lstrip('*')] = expr(node.child_by_field_name('value'))
            elif node.type == 'call_expression':
                args = node.child_by_field_name('arguments')
                values = [expr(a) for a in args.named_children] if args else []
                if not run(call_name(node), values, depth + 1):
                    return False
            elif node.type == 'assignment_expression':
                if txt(node.child_by_field_name('operator')) != '=':
                    return False
                left = expr(node.child_by_field_name('left'))
                right = expr(node.child_by_field_name('right'))
                if not left or left[0] != 'state' or not right or right[0] != 'table':
                    return False
                stores[left[2]] = right[2]
        return True

    return run(function, [('state', 'argument0', 0)], 0) and stores == {i: i for i in range(8)}


def load_callers(path, analysis, contexts):
    from .guomi.source_context import available_code
    from .guomi.source_semantics import Analysis, walk, call_name, txt
    roots = {name.split('@')[0] for name in analysis.entry_functions}
    names = set(roots); selected = []; records = []; size = 0
    candidates = sorted(p for p in path.parent.iterdir()
                        if p.is_file() and not p.is_symlink() and p != path and
                        p.suffix.lower() in {'.c', '.cc', '.cpp', '.h', '.hpp', '.inc'})
    limited = len(candidates) > 128
    remaining = candidates[:128]
    for _ in range(2):
        pending = []
        for candidate in remaining:
            if candidate.stat().st_size > 256 * 1024 or size + candidate.stat().st_size > 4 * 1024 * 1024:
                limited = True; continue
            raw = candidate.read_bytes()
            code = available_code(raw.decode(errors='replace'))
            if not any(re.search(r'\b' + re.escape(n) + r'\s*(?:\(|[,;}])', code) for n in names):
                pending.append(candidate); continue
            context = Analysis(code.encode(), analysis.cpp,
                               declaration_contexts=[c.raw for c in [*contexts, *selected]])
            actual = {name for name, (_, body, _) in context.functions.items() if body is not None and
                      any(n.type == 'call_expression' and call_name(n) in names or
                          n.type == 'assignment_expression' and txt(n.child_by_field_name('right')) in names
                          for n in walk(body))}
            if not actual:
                pending.append(candidate); continue
            selected.append(context); names.update(actual); size += len(raw)
            records.append({'path': str(candidate), 'sha256': hashlib.sha256(raw).hexdigest(),
                            'bytes': len(raw), 'relationship': 'actual reverse call or descriptor assignment'})
        remaining = pending
    return selected, {'files': records, 'limited': limited, 'bytes': size}


def bind(analysis, contexts):
    from .guomi.source_semantics import walk, txt, call_name
    roots = set(analysis.entry_functions); plans = []; descriptors = []
    # The descriptor fields must be assigned in one straight compound block.
    for context in contexts:
        for node in walk(context.tree.root_node):
            if node.type != 'compound_statement':
                continue
            fields = {}
            for statement in node.named_children:
                if statement.type != 'expression_statement' or not statement.named_children:
                    continue
                assignment = statement.named_children[0]
                if assignment.type != 'assignment_expression' or txt(assignment.child_by_field_name('operator')) != '=':
                    continue
                left = assignment.child_by_field_name('left'); target = txt(assignment.child_by_field_name('right'))
                if left.type == 'field_expression' and target in analysis.functions:
                    owner = txt(left.child_by_field_name('argument'))
                    field = txt(left.child_by_field_name('field'))
                    fields.setdefault(owner, {})[field] = target
            for owner, assigned in fields.items():
                descriptors.append((owner, set(assigned.values())))
    for context in contexts:
        for caller, (parameters, body, _) in context.functions.items():
            if body is None or caller in analysis.ambiguous_functions:
                continue
            # A local variable/parameter shadows a same-spelled global table.
            shadowed = set(parameters)
            for node in walk(body):
                if node.type == 'init_declarator':
                    shadowed.add(txt(node.child_by_field_name('declarator')).lstrip('*'))
            for node in walk(body):
                if node.type != 'call_expression':
                    continue
                target = call_name(node)
                variants = sorted(n for n in roots if n.split('@')[0] == target)
                args = node.child_by_field_name('arguments')
                args = list(args.named_children) if args else []
                if not parameters or not args:
                    continue
                state=args[0]
                while state.type in {'cast_expression','parenthesized_expression'}:
                    state=state.named_children[-1]
                if state.type!='identifier' or txt(state)!=parameters[0]:
                    continue
                values = {}
                for i, arg in enumerate(args):
                    while arg.type in {'cast_expression', 'parenthesized_expression'}:
                        arg = arg.named_children[-1]
                    key = txt(arg)
                    if arg.type == 'identifier' and key not in shadowed and key in context.table_sizes:
                        role = context.tables.get(key)
                        # Conflicting definitions across the provided context
                        # cannot donate a parameter to another translation unit.
                        if role and analysis.tables.get(key) == role:
                            values[i] = ('table_pointer', role, 0, 0, context.table_sizes[key])
                if not values:
                    continue
                linked = [(owner, init) for owner, members in descriptors if caller in members
                          for init in sorted(members - {caller}) if initializer(analysis, init)]
                for variant in variants:
                    params, _, _ = analysis.functions[variant]
                    initial = {params[i]: v for i, v in values.items() if i < len(params)}
                    if not initial:
                        continue
                    plans.append({'target': variant, 'caller': caller, 'initial': initial,
                                  'call_offset': node.start_byte,
                                  'descriptor_iv': linked[0] if linked else None})
                    if len(plans) >= 64:
                        return plans
    return plans
