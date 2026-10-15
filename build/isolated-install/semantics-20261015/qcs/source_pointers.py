"""Finite ranges for pointers into verified source constant arrays.

Only canonical ascending for-loops with constant start/limit/strides retain a
pointer across the loop header. Unknown writes, calls through pointer-to-pointer
arguments, and unbounded offsets do not supply table-read evidence.
"""


def advance(value, delta):
    if value[0]!='table_pointer' or len(value)!=5:return None
    _,role,low,high,size=value
    low+=delta;high+=delta
    return ('table_pointer',role,low,high,size) if 0<=low<=high<=size else None


def induction_ranges(node, env, key):
    """A directly incremented finite index with no body writes or escape."""
    from .guomi.source_semantics import txt, number, walk
    if node.type!='for_statement':return {}
    condition=node.child_by_field_name('condition');update=node.child_by_field_name('update')
    if condition is None or condition.type!='binary_expression' or update is None:return {}
    left=condition.child_by_field_name('left');right=condition.child_by_field_name('right')
    if left is None or left.type!='identifier':return {}
    name=key(left);start=env.get(name);limit=number(txt(right))
    if limit is None and env.get(key(right),('',))[0]=='constant':limit=env[key(right)][1]
    op=txt(condition.child_by_field_name('operator'))
    if not start or start[0]!='constant' or limit is None or op not in {'<','<='}:return {}
    if update.type!='update_expression' or txt(update.child_by_field_name('operator'))!='++' or key(update.child_by_field_name('argument'))!=name:return {}
    for child in walk(node.child_by_field_name('body')):
        if child.type in {'assignment_expression','update_expression'}:
            target=child.child_by_field_name('left') or child.child_by_field_name('argument')
            if target is not None and target.type=='identifier' and key(target)==name:return {}
        if child.type=='pointer_expression' and txt(child).startswith('&') and key(child.child_by_field_name('argument'))==name:return {}
    end=limit-(op=='<')
    return {name:('index_range',start[1],end)} if 0<=start[1]<=end<4096 else {}


def loop_ranges(node, env, key):
    from .guomi.source_semantics import txt, walk
    condition=node.child_by_field_name('condition')
    update=node.child_by_field_name('update')
    body=node.child_by_field_name('body')
    if node.type!='for_statement' or condition is None or update is None:return {}
    while condition.type=='parenthesized_expression' and condition.named_children:
        condition=condition.named_children[0]
    if condition.type!='binary_expression':return {}
    induction=condition.child_by_field_name('left')
    if induction is None or induction.type!='identifier':return {}
    name=key(induction);initial=env.get(name)
    bound=env.get(txt(condition.child_by_field_name('right')))
    from .guomi.source_semantics import number
    if bound is None:
        n=number(txt(condition.child_by_field_name('right')))
        bound=('constant',n) if n is not None else None
    comparison=txt(condition.child_by_field_name('operator'))
    if not initial or initial[0]!='constant' or not bound or bound[0]!='constant' or comparison not in {'<','<='}:return {}
    changes={};conflicts=set()
    for child in walk(update):
        delta=None;target=None
        if child.type=='assignment_expression':
            target=child.child_by_field_name('left')
            operation=txt(child.child_by_field_name('operator'))
            n=number(txt(child.child_by_field_name('right')))
            if n is not None and operation in {'+=','-='}:delta=n if operation=='+=' else -n
        elif child.type=='update_expression':
            target=child.child_by_field_name('argument')
            operation=txt(child.child_by_field_name('operator'))
            if operation in {'++','--'}:delta=1 if operation=='++' else -1
        if target is None or target.type!='identifier' or delta is None:continue
        target=key(target)
        if target in changes:conflicts.add(target)
        changes[target]=delta
    if name in conflicts or changes.get(name,0)<=0:return {}
    step=changes[name];distance=bound[1]-initial[1]+(comparison=='<=')
    iterations=(distance+step-1)//step
    if not 1<=iterations<=4096:return {}
    # Any write in the body to the induction or pointer variable invalidates
    # the derived range; an address escape can write the variable indirectly.
    for child in walk(body):
        target=None
        if child.type=='assignment_expression':target=child.child_by_field_name('left')
        elif child.type=='update_expression':target=child.child_by_field_name('argument')
        elif child.type=='pointer_expression' and txt(child).startswith('&'):
            target=child.child_by_field_name('argument')
        if target is not None and target.type=='identifier':conflicts.add(key(target))
    if name in conflicts:return {}
    result={}
    for target,delta in changes.items():
        value=env.get(target)
        if target in conflicts or not value or value[0]!='table_pointer' or len(value)!=5:continue
        end=advance(value,delta*(iterations-1))
        if end is not None:
            result[target]=('table_pointer',value[1],min(value[2],end[2]),max(value[3],end[3]),value[4])
    return result
