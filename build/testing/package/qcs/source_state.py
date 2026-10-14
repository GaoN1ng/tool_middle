"""Bound source call/state components, without merging an entire file.

A wrapper must call actual local definitions with the same first state argument.
Recursive expansion follows only calls forwarding that parameter unchanged. The
bounded component keeps original operation/call offsets for review. Alias-based
forwarding or other argument conventions are intentionally not guessed.
"""
from collections import defaultdict
from .operations import recognize
from .operation_tables import SHA256_IV


def canonical(value):
    value=value.strip().lstrip('&')
    while value.startswith('(') and value.endswith(')'):value=value[1:-1]
    return value


def components(analysis):
    by_root=defaultdict(list);events=defaultdict(list)
    for root,target,args,site in analysis.calls:by_root[root].append((target,args,site))
    for root,role,value,site in analysis.operation_events:events[root].append((site,role,value))
    records=[];matches=[];examined=set()
    def expand(target,visited,depth):
        if target in visited or depth>6 or len(visited)>=32:return
        visited.add(target);parameters,body,_=analysis.functions[target]
        if not parameters or body is None or target in analysis.function_limits:return
        state=parameters[0]
        for child,args,site in by_root.get(target,[]):
            if child in analysis.functions and child not in analysis.ambiguous_functions and args and canonical(args[0])==state:
                expand(child,visited,depth+1)
    for wrapper,calls in by_root.items():
        grouped=defaultdict(list)
        for target,args,site in calls:
            if target in analysis.functions and target not in analysis.ambiguous_functions and args and analysis.functions[target][0]:
                grouped[canonical(args[0])].append((target,site))
        for state,roots in grouped.items():
            visited=set()
            for target,_ in roots:expand(target,visited,0)
            if len(visited)<2:continue
            identity=tuple(sorted(visited))
            if identity in examined:continue
            examined.add(identity)
            related=[event for target in visited for event in events[target]]
            iv=set(SHA256_IV)<={v for _,r,v in related if r=='iv_store'} or any(r=='table_read' and v=='sha256_iv' for _,r,v in related)
            found=recognize(related,sha256_variant=iv)
            matches.extend(found)
            if found:
                records.append({'wrapper':wrapper,'bound_state_argument':state,'definitions':sorted(visited),
                                'actual_calls':[{'target':target,'offset':site} for target,site in roots],
                                'algorithms':sorted({m[0] for m in found}),
                                'method':'actual local calls forwarding one bound state argument'})
    return matches,records
