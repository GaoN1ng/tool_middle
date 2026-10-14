"""Static, name-free source/ELF features for an experimental RF baseline.

Symbols/DWARF are deliberately absent from ELF inference. Function regions
come from unwind frames or direct-call/section boundaries. The fallback is
bounded and does not claim complete stripped-function recovery.
"""
from collections import Counter
from functools import lru_cache
from pathlib import Path
import hashlib
import math
import re

SCHEMA = 'rf-static-features-1'
OPS = ['move', 'load', 'store', 'add', 'sub', 'carry', 'mul', 'div', 'xor',
       'and', 'or', 'not', 'shift', 'rotate', 'compare', 'branch', 'call',
       'return', 'select', 'vector', 'crypto', 'other']
SMALL = [1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 16, 17, 18,
         19, 20, 22, 23, 24, 25, 26, 27, 28, 30, 31, 32, 48, 56, 60, 64,
         80, 96, 128, 255, 256]
STANDARD = {
    'sha1': {0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6},
    'sha256': {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x6a09e667, 0xbb67ae85},
    'sm3': {0x7380166f, 0x4914b2b9, 0x79cc4519, 0x7a879d8a},
    'sm4': {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc, 0x00070e15},
    'md5': {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee},
    'chacha': {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574},
}


def category(m):
    m = m.lower().split('.')[0]
    if any(x in m for x in ['aesenc', 'aesdec', 'aese', 'aesd', 'sha256', 'sha1', 'sm3', 'sm4']): return 'crypto'
    if m.startswith(('v', 'p')) and any(x in m for x in ['xor', 'add', 'sub', 'shuf', 'and', 'or', 'srl', 'sll']): return 'vector'
    if m in {'adc', 'adcs', 'sbc', 'sbcs', 'sbb', 'adcx', 'adox'}: return 'carry'
    if 'ror' in m or 'rol' in m or m in {'extr', 'shrd', 'shld'}: return 'rotate'
    if m in {'xor', 'eor', 'eors', 'eon'}: return 'xor'
    if m in {'and', 'ands', 'bic', 'bics'}: return 'and'
    if m in {'or', 'orr', 'orrs', 'orn'}: return 'or'
    if m in {'not', 'mvn', 'mvns'}: return 'not'
    if m.startswith(('shl', 'shr', 'sar', 'sal', 'lsl', 'lsr', 'asr', 'ushr')): return 'shift'
    if m.startswith(('add', 'inc')): return 'add'
    if m.startswith(('sub', 'dec', 'neg')): return 'sub'
    if 'mul' in m or m in {'mla', 'mls', 'madd', 'msub'}: return 'mul'
    if 'div' in m or m in {'rem', 'mod'}: return 'div'
    if m.startswith(('cmp', 'test', 'tst', 'cmn')): return 'compare'
    if m.startswith(('cmov', 'csel', 'csinc', 'cset', 'set')): return 'select'
    if m.startswith(('ldr', 'ldur', 'ldp', 'ldm')): return 'load'
    if m.startswith(('str', 'stur', 'stp', 'stm')): return 'store'
    if m.startswith(('mov', 'lea', 'adr')) or m in {'push', 'pop', 'xchg', 'bswap', 'rev', 'rev32', 'rev16'}: return 'move'
    return 'other'


def finish_features(ops, numbers, metrics):
    n = max(1, len(ops))
    c = Counter(ops)
    f = {'stat:log_operations': math.log1p(len(ops))}
    f.update({'stat:op_' + k: c[k] / n for k in OPS})
    pairs = Counter(zip(ops, ops[1:]))
    # Generic operation transitions, never mnemonic or register spellings.
    for a in OPS:
        for b in OPS:
            if pairs[a, b]: f['stat:pair_' + a + '_' + b] = pairs[a, b] / n
    number_count = Counter(v & 0xffffffff for v in numbers)
    for v in SMALL:
        f['value:small_' + str(v)] = min(number_count[v], 32) / n
    for name, values in STANDARD.items():
        f['value:standard_' + name] = min(sum(number_count[v] for v in values), 32) / n
    for k, v in metrics.items(): f['structure:' + k] = float(v)
    return {k: v for k, v in f.items() if v}


@lru_cache(maxsize=2)
def disassembler(domain):
    import capstone as cs
    if domain == 'x86_64': d = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    elif domain == 'aarch64': d = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_ARM)
    else: raise ValueError('RF binary domain unsupported: ' + domain)
    d.detail = True
    return d


def binary_body(raw, address, domain):
    import capstone as cs
    ins = list(disassembler(domain).disasm(raw, address))
    ops, numbers, calls = [], [], []
    starts = {address}
    branches = loops = indirect = loads = stores = indexed = stack = 0
    for i in ins:
        cat = category(i.mnemonic)
        if i.group(cs.CS_GRP_CALL):
            cat = 'call'
            if i.operands and i.operands[-1].type == 2: calls.append(i.operands[-1].imm)
            else: indirect += 1
        elif i.group(cs.CS_GRP_RET): cat = 'return'
        elif i.group(cs.CS_GRP_JUMP):
            cat = 'branch'; branches += 1; starts.add(i.address + i.size)
            if i.operands and i.operands[-1].type == 2:
                dest = i.operands[-1].imm
                if address <= dest < address + len(raw):
                    starts.add(dest); loops += dest <= i.address
            else: indirect += 1
        for j, operand in enumerate(i.operands):
            if operand.type == 2 and cat not in {'branch', 'call'}:
                numbers.append(int(operand.imm))
            if operand.type == 3:
                mem = operand.mem
                base = i.reg_name(mem.base) if mem.base else ''
                index = getattr(mem, 'index', 0)
                stack += base in {'rsp', 'rbp', 'sp', 'x29'}
                indexed += bool(index)
                access = getattr(operand, 'access', 0)
                read = bool(access & cs.CS_AC_READ) or (not access and (j > 0 or cat == 'load'))
                write = bool(access & cs.CS_AC_WRITE) or (not access and j == 0 and cat == 'store')
                loads += read; stores += write
        ops.append(cat)
    n = max(1, len(ins))
    metrics = {'blocks_log': math.log1p(len(starts)), 'branches': branches / n,
               'back_edges': loops / n, 'calls': len(calls) / n, 'indirect': indirect / n,
               'memory_loads': loads / n, 'memory_stores': stores / n,
               'indexed_memory': indexed / n, 'stack_memory': stack / n,
               'decode_fraction': sum(i.size for i in ins) / max(1, len(raw))}
    return finish_features(ops, numbers, metrics), calls


def elf_functions(path):
    from elftools.elf.elffile import ELFFile
    from elftools.dwarf.callframe import FDE
    with Path(path).open('rb') as stream:
        elf = ELFFile(stream)
        domain = {'EM_X86_64': 'x86_64', 'EM_AARCH64': 'aarch64'}.get(elf['e_machine'])
        if not domain: return [], {'status': 'unsupported', 'reason': str(elf['e_machine'])}
        sections = [(s['sh_addr'], s.data()) for s in elf.iter_sections()
                    if s['sh_flags'] & 4 and s['sh_size'] and s.name not in {'.plt', '.plt.got', '.iplt'}]
        bounds = {}
        if elf.get_section_by_name('.eh_frame'):
            try:
                for fde in elf.get_dwarf_info().EH_CFI_entries():
                    if isinstance(fde, FDE): bounds[fde['initial_location']] = fde['address_range']
            except Exception: pass
        method = 'unwind_frames'
        if not bounds:
            method = 'bounded_direct_call_fallback'
            for base, raw in sections:
                roots = {base}
                for i in disassembler(domain).disasm(raw, base):
                    import capstone as cs
                    if i.group(cs.CS_GRP_CALL) and i.operands and i.operands[-1].type == 2:
                        if base <= i.operands[-1].imm < base + len(raw): roots.add(i.operands[-1].imm)
                ordered = sorted(roots)
                for a, end in zip(ordered, ordered[1:] + [base + len(raw)]): bounds[a] = end - a
        result = []
        omitted = 0
        for a, size in sorted(bounds.items()):
            if not 1 <= size <= 200000:
                omitted += 1; continue
            raw = next((data[a-base:a-base+size] for base, data in sections
                        if base <= a and a + size <= base + len(data)), None)
            if raw is None: continue
            f, calls = binary_body(raw, a, domain)
            if not f.get('stat:log_operations', 0):
                omitted += 1
                continue
            result.append({'offset': a, 'size': size, 'features': f, 'calls': calls,
                           'body_sha256': hashlib.sha256(raw).hexdigest()})
        link_context(result)
        return result, {'status': 'completed' if not omitted else 'partial', 'domain': domain,
                        'boundary_method': method, 'functions': len(result), 'omitted_functions': omitted}


def link_context(functions):
    lookup = {r['offset']: r for r in functions}
    for r in functions:
        neighborhood = []
        seen = {r['offset']}
        todo = list(r['calls'])
        for _ in range(2):
            next_calls = []
            for target in todo:
                if target in seen or target not in lookup: continue
                seen.add(target); neighbor = lookup[target]
                neighborhood.append(neighbor['features']); next_calls.extend(neighbor['calls'])
                if len(neighborhood) >= 24: break
            todo = next_calls
            if len(neighborhood) >= 24: break
        # Include self in pooled features; names never identify callees.
        pool = [r['features']] + neighborhood
        extra = {'context:neighbors_log': math.log1p(len(neighborhood))}
        for key in set().union(*(p.keys() for p in pool)):
            if key.startswith('context:'): continue
            extra['context:max:' + key] = max(p.get(key, 0) for p in pool)
            extra['context:mean:' + key] = sum(p.get(key, 0) for p in pool) / len(pool)
        r['features'].update({k: v for k, v in extra.items() if v})


def source_functions(path):
    from qcs.guomi.source_semantics import parser
    from qcs.text import decode_source
    p = Path(path)
    text, encoding = decode_source(p.read_bytes())
    raw = text.encode('utf-8')
    tree = parser(p.suffix.lower() in {'.cpp', '.cc', '.cxx', '.hpp'}).parse(raw)
    functions = []
    def descendants(node):
        yield node
        for child in node.named_children: yield from descendants(child)
    definitions = [n for n in descendants(tree.root_node) if n.type == 'function_definition']
    for node in definitions:
        decl = node.child_by_field_name('declarator')
        target = decl
        while target and target.type not in {'identifier', 'field_identifier', 'qualified_identifier', 'operator_name'}:
            next_target = target.child_by_field_name('declarator') or target.child_by_field_name('name')
            if not next_target: break
            target = next_target
        label_key = raw[target.start_byte:target.end_byte].decode() if target else ''
        body = node.child_by_field_name('body')
        if body is None: continue
        ops, numbers, calls = [], [], []
        counters = Counter()
        opmap = {'+': 'add', '-': 'sub', '*': 'mul', '/': 'div', '%': 'div', '^': 'xor',
                 '&': 'and', '|': 'or', '~': 'not', '<<': 'shift', '>>': 'shift',
                 '+=': 'add', '-=': 'sub', '^=': 'xor', '&=': 'and', '|=': 'or',
                 '==': 'compare', '!=': 'compare', '<': 'compare', '>': 'compare',
                 '<=': 'compare', '>=': 'compare', '++': 'add', '--': 'sub'}
        for n in descendants(body):
            if n.type in {'binary_expression', 'unary_expression', 'update_expression', 'assignment_expression'}:
                op = n.child_by_field_name('operator')
                token = raw[op.start_byte:op.end_byte].decode() if op else ''
                if token in opmap: ops.append(opmap[token])
                elif n.type == 'assignment_expression': ops.append('move')
            elif n.type == 'call_expression':
                ops.append('call'); fn = n.child_by_field_name('function')
                if fn and fn.type in {'identifier', 'field_identifier'}:
                    calls.append(raw[fn.start_byte:fn.end_byte].decode())
            elif n.type == 'return_statement': ops.append('return')
            elif n.type in {'if_statement', 'switch_statement', 'conditional_expression'}:
                ops.append('branch'); counters['branches'] += 1
            elif n.type in {'for_statement', 'while_statement', 'do_statement'}:
                ops.append('branch'); counters['loops'] += 1
            elif n.type == 'subscript_expression': counters['indexed_memory'] += 1; ops.append('load')
            elif n.type in {'pointer_expression', 'field_expression'}: counters['pointer_memory'] += 1
            elif n.type == 'number_literal':
                token = raw[n.start_byte:n.end_byte].decode()
                try: numbers.append(int(re.sub(r'[uUlL]+$', '', token), 0))
                except ValueError: pass
        n = max(1, len(ops))
        f = finish_features(ops, numbers, {'blocks_log': math.log1p(counters['branches'] + counters['loops'] + 1),
            'branches': counters['branches'] / n, 'back_edges': counters['loops'] / n,
            'calls': len(calls) / n, 'indexed_memory': counters['indexed_memory'] / n,
            'pointer_memory': counters['pointer_memory'] / n})
        functions.append({'offset': node.start_byte, 'size': node.end_byte-node.start_byte,
                          'label_key': label_key, 'features': f, 'calls': calls,
                          'body_sha256': hashlib.sha256(raw[body.start_byte:body.end_byte]).hexdigest()})
    # Names are temporary bindings for actual local edges, never feature values.
    names = {}
    for r in functions: names.setdefault(r['label_key'], []).append(r['offset'])
    for r in functions:
        r['calls'] = [names[c][0] for c in r['calls'] if c in names and len(names[c]) == 1]
    link_context(functions)
    return functions, {'status': 'partial' if tree.root_node.has_error else 'completed',
                       'encoding': encoding, 'functions': len(functions), 'boundary_method': 'source_ast',
                       'limitations': 'Preprocessor branches/macros not fully expanded; no names enter feature vectors'}


def extract(path, kind):
    if kind == 'source' and Path(path).suffix.lower() not in {'.c', '.h', '.cpp', '.cc', '.cxx', '.hpp'}:
        return [], {'status': 'unsupported', 'reason': 'First RF source extractor supports C/C++ only'}
    return source_functions(path) if kind == 'source' else elf_functions(path)


def feature_view(features, view):
    if view == 'statistics': return {k: v for k, v in features.items() if k.startswith(('stat:', 'value:'))}
    if view == 'structure': return {k: v for k, v in features.items() if not k.startswith('context:')}
    if view == 'context': return dict(features)
    raise ValueError(view)
