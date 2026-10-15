"""Bounded CFG interpretation with conservative joins and loop widening.

Only direct branches are followed. Indirect edges terminate analysis. Changed
facts are discarded at joins; two loop revisits widen unstable facts to unknown.
No target code is executed, and this is not a feasibility proof.
"""
from collections import deque
import copy
import time

MAPS = ('regs', 'memory', 'addresses', 'address_memory', 'array_addresses',
        'array_memory', 'stack_offsets', 'mips_lui_sites', 'import_registers')
MAPS=(*MAPS,'frame_memory')
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


def mips_transfer(ins):
    """Classify classic MIPS32 transfers, including Capstone's missing groups.

    Branch-likely and conditional-link forms require edge-specific effects;
    decline them rather than executing their slot on the wrong edge.
    """
    m=ins.mnemonic
    if m in {'jal','jalr','bal'}:return 'call'
    if m=='jr':return 'return' if ins.op_str=='$ra' else 'indirect'
    if m in {'j','b'}:return 'direct'
    if m in {'beq','bne','beqz','bnez','bgtz','blez','bltz','bgez'}:return 'conditional'
    if m.startswith(('b','j')) and m not in {'break','bitswap'}:return 'unsupported'
    return None


def analyze(lift, instructions, deadline, *, max_steps=80000, max_total_steps=1_000_000,
            initial_iteration=False, block_outputs=None, entry_outputs=None):
    """Interpret code entries and calls, retaining each function's own state.

    Roots use addresses only, never function identifiers or symbols.
    """
    import capstone as cs
    mips=lift.domain in {'mipsel','mips_be'}
    if lift.domain not in {'x86_64', 'pe_x86_64', 'aarch64', 'arm', 'thumb','mipsel','mips_be'}:
        return {'status': 'unsupported', 'steps': 0, 'blocks': 0, 'loop_edges': 0}
    ops = {i.address: i for i in instructions if i.id}
    if not ops:
        return {'status': 'completed', 'steps': 0, 'blocks': 0, 'loop_edges': 0}
    roots = {min(ops)}
    function_entries=set(roots)
    starts = set(roots)
    edges = {}
    transfers={}
    declined=0
    for at, ins in ops.items():
        next_at = at + ins.size
        if mips:
            transfer=mips_transfer(ins)
            if not transfer:
                # A verified o32 PIC prologue supplies a stripped entry root.
                # Require both real instructions and the ELF-derived gp value.
                following=ops.get(next_at)
                if (lift.mips_gp is not None and ins.mnemonic=='lui' and len(ins.operands)==2 and
                    following and following.mnemonic=='addiu' and len(following.operands)==3 and
                    ins.operands[0].reg==following.operands[0].reg==following.operands[1].reg and
                    ((ins.operands[1].imm<<16)+following.operands[2].imm+at)&0xffffffff==lift.mips_gp):
                    roots.add(at)
                    function_entries.add(at)
                continue
            transfers[at]=transfer
            after=at+8
            dest=ins.operands[-1].imm if ins.operands and ins.operands[-1].type==2 else None
            if transfer=='call':
                if dest in ops:roots.add(dest);function_entries.add(dest)
                successors=[after] if after in ops else []
            elif transfer in {'direct','conditional'}:
                successors=([dest] if dest in ops else [])+([after] if transfer=='conditional' and after in ops else [])
            else:
                successors=[]
                if transfer=='return' and after in ops:roots.add(after)
            if transfer=='unsupported' or next_at not in ops or mips_transfer(ops[next_at]):
                # Invalid/missing/unsupported slots cannot carry facts onward.
                successors=[];declined+=1
                transfers[at]='unsupported'
            edges[at]=list(dict.fromkeys(successors))
            starts.update(successors)
            continue
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
                    function_entries.add(target)
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
                if mips and at in transfers and transfers[at]!='unsupported':
                    body.append(ops[next_at])
                successors = edges.get(at, [next_at] if next_at in ops else [])
                blocks[root] = (body, successors)
                break
            at = next_at
    # An early RET's following block is often a reachable continuation of the
    # same function. Treating it as another blank entry destroys its real
    # caller/stack facts. Direct call targets and verified PIC prologues are
    # actual entries; no fallthrough state is joined into those invocations.
    incoming_edges={d for _,successors in blocks.values() for d in successors}
    roots={r for r in roots if r in function_entries or r not in incoming_edges}
    blocks={r:(body,[d for d in successors if d not in function_entries])
            for r,(body,successors) in blocks.items()}
    prefix_excluded=set();prefix_inputs={}
    prefix_backedges=[]
    if initial_iteration:
        # A loop's entry iteration has useful facts which are correctly lost
        # by an invariant join (e.g. a K pointer advanced on the back edge).
        # Recognize natural loops using dominance, not address order alone.
        # This separate pass describes only prefixes before a back edge; no
        # facts from that truncated execution may escape a loop to later code.
        predecessors={r:set() for r in blocks}
        for r,(_,successors) in blocks.items():
            for d in successors:
                if d in predecessors:predecessors[d].add(r)
        reachable=set();pending=list(roots)
        while pending:
            r=pending.pop()
            if r in reachable or r not in blocks:continue
            reachable.add(r);pending.extend(blocks[r][1])
        without_header={}
        for r,(_,successors) in blocks.items():
            for d in successors:
                if d>r or r not in reachable:continue
                if d not in without_header:
                    seen=set();pending=list(roots-{d})
                    while pending:
                        p=pending.pop()
                        if p==d or p in seen or p not in blocks:continue
                        seen.add(p);pending.extend(blocks[p][1])
                    without_header[d]=seen
                if r not in without_header[d]:prefix_backedges.append((r,d))
        loops={}
        for tail,header in prefix_backedges:
            members={header,tail};pending=[tail] if tail!=header else []
            while pending:
                r=pending.pop()
                for p in predecessors[r]:
                    if p not in members:members.add(p);pending.append(p)
            loops.setdefault(header,set()).update(members)
        # Seed each innermost loop from the invariant pass's converged actual
        # preheaders. We never propagate a truncated inner loop to its exit.
        selected={h:m for h,m in loops.items() if not any(k!=h and k in m for k in loops)}
        allowed=set()
        for header,members in selected.items():
            external=predecessors[header]-members
            if not external or not entry_outputs or any(p not in entry_outputs for p in external):continue
            states=[entry_outputs[p] for p in external]
            state=copy.deepcopy(states[0])
            for other in states[1:]:state=intersect(state,other)
            prefix_inputs[header]=state;allowed.update(members)
        prefix_excluded=set(blocks)-allowed
        for r,d in prefix_backedges:
            body,successors=blocks[r];blocks[r]=(body,[x for x in successors if x!=d])
        blocks={r:(body,[d for d in successors if d in allowed]) for r,(body,successors) in blocks.items()}
    # Calls do not connect caller/callee state here. Weak components of real
    # intra-function edges share a local budget; compiler runtime functions
    # cannot consume a later independent function's entire allowance.
    parents={root:root for root in blocks}
    def component(root):
        while parents[root]!=root:
            parents[root]=parents[parents[root]];root=parents[root]
        return root
    for root,(_,successors) in blocks.items():
        for dest in successors:
            if dest in parents:parents[component(dest)]=component(root)
    component_ids={root:component(root) for root in blocks}
    component_steps={};limited_components=set()
    incoming = {}
    queue = deque()
    blank = snapshot(lift)
    for name in MAPS:
        blank[name] = {}
    blank['stack_offsets'] = {'rsp': 0} if 'x86' in lift.domain else {'sp': 0}
    blank['arrays'] = {**{name: {} for name in ARRAY_MAPS}, **{name: [] for name in ARRAY_LISTS}, 'outputs': set()}
    for root in sorted(prefix_inputs if initial_iteration else roots):
        incoming[root] = copy.deepcopy(prefix_inputs[root] if initial_iteration else blank)
        queue.append(root)
    visits = {}
    steps = loops = joins = widened = 0
    lift.cfg_mode = True
    event_start=len(lift.events)
    helper_start=len(lift.helper_calls)
    def execute(body):
        nonlocal steps
        deferred_call=None
        for ins in body:
            steps += 1
            if steps>max_total_steps:return False
            if steps % 256 == 0 and time.monotonic() > deadline:
                return False
            if mips and ins.address in transfers:
                if transfers[ins.address]=='call':
                    lift.regs['ra']=('constant',ins.address+8)
                if transfers[ins.address] in {'call','indirect'}:
                    deferred_call=ins
                continue
            if ins.address in edges and ins.group(cs.CS_GRP_JUMP):continue
            if terminal(ins, lift.domain):continue
            lift.stable_site=ins.address
            lift.stable_counter=0
            lift.step(ins)
        if deferred_call is not None:
            lift.stable_site=deferred_call.address
            lift.stable_counter=0
            lift.step(deferred_call)
        return True
    timed_out=False
    unstable=set()
    while queue and steps < max_total_steps:
        root = queue.popleft()
        if root not in blocks:
            continue
        group=component_ids[root]
        if component_steps.get(group,0)>=max_steps:
            unstable.add(root);limited_components.add(group);continue
        visits[root] = visits.get(root, 0) + 1
        # Every join below is an intersection: its facts can only disappear.
        # Erasing *all* facts at the fifth visit also erased invariant SP/frame
        # offsets and table pointers. Allow the finite descending chain to
        # converge. A genuine budget cutoff taints successors and is never
        # replayed as evidence.
        if visits[root] > 64:
            widened += 1
            unstable.add(root)
            continue
        restore(lift, incoming[root])
        body, successors = blocks[root]
        before_steps=steps
        if not execute(body):
            timed_out=True;unstable.add(root);break
        component_steps[group]=component_steps.get(group,0)+steps-before_steps
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
    # Iteration can visit a join before its other predecessor arrives. Such
    # provisional facts must never become permanent algorithm evidence. Replay
    # only converged block inputs, discarding every exploratory event first.
    del lift.events[event_start:]
    del lift.helper_calls[helper_start:]
    replayed=0
    # An unstable loop invalidates its reachable successors, not independent
    # functions elsewhere in the section. Pending work at a budget cutoff has
    # the same treatment; do not replay any join depending on an unfinished edge.
    tainted=set(unstable)|set(queue)
    pending=list(tainted)
    while pending:
        at=pending.pop()
        for dest in blocks.get(at,([],[]))[1]:
            if dest not in tainted:tainted.add(dest);pending.append(dest)
    fixed_point_steps=steps
    replay_steps={}
    for root in sorted(incoming):
        if root not in blocks or root in tainted or root in prefix_excluded:continue
        group=component_ids[root]
        if replay_steps.get(group,0)>=max_steps:
            limited_components.add(group);continue
        restore(lift,incoming[root])
        before=len(lift.events);before_helpers=len(lift.helper_calls)
        before_steps=steps
        if not execute(blocks[root][0]):
            del lift.events[before:];del lift.helper_calls[before_helpers:]
            timed_out=True;break
        if block_outputs is not None:block_outputs[root]=snapshot(lift)
        replayed+=1
        replay_steps[group]=replay_steps.get(group,0)+steps-before_steps
    lift.cfg_mode = False
    lift.stable_site = None
    return {'status': 'limited' if queue or declined or timed_out or widened or limited_components else 'completed', 'steps': steps,
            'blocks': len(blocks), 'loop_edges': loops, 'joins': joins,
            'widened_blocks': widened, 'entry_count': len(roots),
            'declined_transfers':declined,'replayed_blocks':replayed,
            'unstable_reachable_blocks':len(tainted),'fixed_point_steps':fixed_point_steps,
            'component_count':len(set(component_ids.values())),
            'limited_components':len(limited_components),
            'step_budget_per_component_per_phase':max_steps,'total_step_budget':max_total_steps}
