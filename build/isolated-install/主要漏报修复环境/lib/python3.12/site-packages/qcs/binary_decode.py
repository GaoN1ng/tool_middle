"""Recover Thumb instruction starts from actual direct control transfers.

Literal pools in a code section can desynchronise a linear variable-width
decoder. A decoded immediate branch/call supplies an address, never a name.
Recovery is bounded and is used for CFG interpretation only.
"""

def control_instructions(dis, data, base, *, domain, entries=()):
    import capstone as cs
    from .guomi.binary_semantics import decode
    initial=list(decode(dis,data,base))
    if domain!='thumb':return initial
    operations={i.address:i for i in initial};queue=list(initial);recovered=set();count=0
    # Independently recorded unwind entries are also valid decoding anchors.
    # A literal pool may hide an entire function before any decoded call.
    for entry in entries:
        entry &= ~1
        if not base<=entry<base+len(data) or entry in operations:continue
        for child in dis.disasm(data[entry-base:entry-base+256],entry,count=64):
            if not child.id or child.address in operations:break
            operations[child.address]=child;queue.append(child);count+=1
            if child.group(cs.CS_GRP_RET) or child.group(cs.CS_GRP_JUMP):break
    while queue and count<8192:
        ins=queue.pop()
        if not ins.id or not (ins.group(cs.CS_GRP_JUMP) or ins.group(cs.CS_GRP_CALL)):continue
        if not ins.operands or ins.operands[-1].type!=2:continue
        # BLX immediate switches to ARM and is not a Thumb decoding anchor.
        if ins.mnemonic=='blx':continue
        dest=ins.operands[-1].imm&~1
        if not base<=dest<base+len(data) or dest in operations or dest in recovered:continue
        recovered.add(dest);at=dest
        for child in dis.disasm(data[dest-base:dest-base+256],dest,count=64):
            if child.address in operations:break
            if not child.id:break
            operations[child.address]=child;queue.append(child);count+=1
            at=child.address+child.size
            if child.group(cs.CS_GRP_RET) or child.group(cs.CS_GRP_JUMP):break
    return [operations[a] for a in sorted(operations)]
