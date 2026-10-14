"""Bounded CFG interpretation with conservative joins and loop widening.

Only direct branches are followed. Indirect edges terminate analysis. Changed
facts are discarded at joins; two loop revisits widen unstable facts to unknown.
No target code is executed, and this is not a feasibility proof.
"""
from collections import deque
import copy
import time

MAPS = ('regs', 'memory', 'addresses', 'address_memory', 'array_addresses',
        'array_memory', 'stack_offsets')
ARRAY_MAPS = ('loads', 'cells', 'masks')
ARRAY_LISTS = ('stores', 'swaps')


def snapshot(lift):
    result = {name: dict(getattr(lift, name)) for name in MAPS}
    result['arrays'] = {name: dict(getattr(lift.arrays, name)) for name in ARRAY_MAPS}
    result['arrays'].update({name: list(getattr(lift.arrays, name)) for name in ARRAY_LISTS})
    result['arrays']['outputs'] = set(lift.arrays.outputs)
    return result


def restore(lift, state):
    for name in MAPS:
        setattr(lift, name, dict(state[name]))
    for name in ARRAY_MAPS:
        setattr(lift.arrays, name, dict(state['arrays'][name]))
    for name in ARRAY_LISTS:
        setattr(lift.arrays, name, list(state['arrays'][name]))
    lift.arrays.outputs = set(state['arrays']['outputs'])


def intersect(left, right):
    result = {}
    for name in MAPS:
        result[name] = {k: v for k, v in left[name].items() if right[name].get(k) == v}
    result['arrays'] = {}
    for name in ARRAY_MAPS:
        result['arrays'][name] = {k: v for k, v in left['arrays'][name].items()
                                 if right['arrays'][name].get(k) == v}
    for name in ARRAY_LISTS:
        result['arrays'][name] = [v for v in left['arrays'][name] if v in right['arrays'][name]]
    result['arrays']['outputs'] = left['arrays']['outputs'] & right['arrays']['outputs']
    return result


def terminal(ins, domain):
    import capstone as cs
    if ins.id and ins.group(cs.CS_GRP_RET):
        return True
    if domain in {'arm', 'thumb'}:
        m = ins.mnemonic.split('.')[0]
        return ((m == 'bx' and ins.op_str == 'lr') or
                (m in {'pop', 'ldm', 'ldmia'} and any(o.type == 1 and ins.reg_name(o.reg) == 'pc'
                                                    for o in ins.operands)))
    return False


def analyze(lift, instructions, deadline, *, max_steps=80000):
    """Interpret code entries and calls, retaining each function's own state.

    MIPS delay slots require another transfer model and are excluded here.
    Roots use addresses only, never function identifiers or symbols.
    """
    import capstone as cs
    if lift.domain not in {'x86_64', 'pe_x86_64', 'aarch64', 'arm', 'thumb'}:
        return {'status': 'unsupported', 'steps': 0, 'blocks': 0, 'loop_edges': 0}
    ops = {i.address: i for i in instructions if i.id}
    if not ops:
        return {'status': 'completed', 'steps': 0, 'blocks': 0, 'loop_edges': 0}
    roots = {min(ops)}
    starts = set(roots)
    edges = {}
    for at, ins in ops.items():
        next_at = at + ins.size
        if terminal(ins, lift.domain):
            edges[at] = []
            if next_at in ops:
                roots.add(next_at)
            continue
        if ins.group(cs.CS_GRP_CALL):
            if ins.operands and ins.operands[-1].type == 2:
                target = ins.operands[-1].imm & (~1 if lift.domain == 'thumb' else -1)
                if target in ops:
                    roots.add(target)
            continue
        if ins.group(cs.CS_GRP_JUMP):
            dest = ins.operands[-1].imm if ins.operands and ins.operands[-1].type == 2 else None
            unconditional = ins.mnemonic in {'jmp', 'b', 'b.w', 'bx', 'br'}
            succ = ([dest] if dest in ops else []) + ([] if unconditional else [next_at] if next_at in ops else [])
            edges[at] = list(dict.fromkeys(succ))
            starts.update(succ)
            if next_at in ops:
                starts.add(next_at)
    starts.update(roots)
    blocks = {}
    for root in sorted(starts):
        body = []
        at = root
        while at in ops:
            ins = ops[at]
            body.append(ins)
            next_at = at + ins.size
            if at in edges or next_at in starts or next_at not in ops:
                successors = edges.get(at, [next_at] if next_at in ops else [])
                blocks[root] = (body, successors)
                break
            at = next_at
    incoming = {}
    queue = deque()
    blank = snapshot(lift)
    for name in MAPS:
        blank[name] = {}
    blank['stack_offsets'] = {'rsp': 0} if 'x86' in lift.domain else {'sp': 0}
    blank['arrays'] = {**{name: {} for name in ARRAY_MAPS}, **{name: [] for name in ARRAY_LISTS}, 'outputs': set()}
    for root in sorted(roots):
        incoming[root] = copy.deepcopy(blank)
        queue.append(root)
    visits = {}
    steps = loops = joins = widened = 0
    lift.cfg_mode = True
    while queue and steps < max_steps:
        root = queue.popleft()
        if root not in blocks:
            continue
        visits[root] = visits.get(root, 0) + 1
        if visits[root] > 4:
            widened += 1
            continue
        restore(lift, incoming[root])
        body, successors = blocks[root]
        for ins in body:
            steps += 1
            if steps % 256 == 0 and time.monotonic() > deadline:
                lift.cfg_mode = False
                return {'status': 'limited', 'steps': steps, 'blocks': len(blocks), 'loop_edges': loops}
            if ins.address in edges and ins.group(cs.CS_GRP_JUMP):
                # Branches themselves cannot create dataflow facts.
                continue
            if terminal(ins, lift.domain):
                continue
            lift.stable_site = ins.address
            lift.stable_counter = 0
            lift.step(ins)
        output = snapshot(lift)
        for dest in successors:
            if dest <= root:
                loops += 1
            if dest not in incoming:
                incoming[dest] = output
                queue.append(dest)
            else:
                joined = intersect(incoming[dest], output)
                joins += 1
                if joined != incoming[dest]:
                    incoming[dest] = joined
                    queue.append(dest)
    lift.cfg_mode = False
    lift.stable_site = None
    return {'status': 'limited' if queue else 'completed', 'steps': steps,
            'blocks': len(blocks), 'loop_edges': loops, 'joins': joins,
            'widened_blocks': widened, 'entry_count': len(roots)}
