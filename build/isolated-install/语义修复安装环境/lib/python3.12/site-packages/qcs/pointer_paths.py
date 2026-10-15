"""Bounded path-specific imported arithmetic over unwind-defined functions.

Unwind ranges supply addresses only, never symbols. Each branch alternative has
private pointer/equation state; evidence cannot join incompatible predecessors.
Loops stop before revisiting an instruction. No target code is executed.
"""
import copy
import time
from bisect import bisect_left


def unwind_ranges(path):
    from elftools.elf.elffile import ELFFile
    from elftools.dwarf.callframe import FDE
    with path.open('rb') as stream:
        elf=ELFFile(stream)
        if elf.get_section_by_name('.eh_frame') is None:return []
        return sorted({(entry['initial_location'],entry['address_range'])
                       for entry in elf.get_dwarf_info().EH_CFI_entries() if isinstance(entry,FDE)
                       and 0<entry['address_range']<=128*1024})


def analyze(lift, instructions, ranges, deadline, *, max_paths=128, max_steps=100000):
    import capstone as cs
    from .controlflow import terminal,mips_transfer
    operations={i.address:i for i in instructions if i.id};matches=[];records=[]
    addresses=sorted(operations)
    mips=lift.domain in {'mipsel','mips_be'}
    steps=0
    maps=('regs','memory','equations','frame','lui_sites','coordinate_words','high_bit_words','xhat_buffers')
    def state():return copy.deepcopy(tuple(getattr(lift,n) for n in maps))
    def restore(value):
        for name,item in zip(maps,copy.deepcopy(value)):setattr(lift,name,item)
        lift.matches=[]
    blank=state()
    for start,size in ranges:
        if start not in operations:continue
        # Avoid exploring library stubs or arithmetic-free functions.
        body=[operations[a] for a in addresses[bisect_left(addresses,start):bisect_left(addresses,start+size)]]
        if not any((i.group(cs.CS_GRP_CALL) or (mips and i.mnemonic in {'jal','jalr'})) for i in body):continue
        restore(blank);pending=[(start,state(),frozenset())];paths=0;limited=False
        while pending:
            if paths>=max_paths or steps>=max_steps or time.monotonic()>deadline:limited=True;break
            at,saved,visited=pending.pop();restore(saved);paths+=1;visited=set(visited)
            while start<=at<start+size and at in operations and at not in visited:
                if steps>=max_steps or time.monotonic()>deadline:limited=True;break
                visited.add(at);ins=operations[at];steps+=1;next_at=at+ins.size
                transfer=mips_transfer(ins) if mips else None
                if transfer=='unsupported':break
                if mips and transfer:
                    slot=operations.get(next_at)
                    if slot is None or mips_transfer(slot):break
                    lift.step(slot);next_at=at+8
                if terminal(ins,lift.domain) or transfer=='return':
                    matches.extend(lift.equations.matches+lift.equations.general_matches);break
                call=ins.group(cs.CS_GRP_CALL) or transfer=='call'
                if call:
                    lift.step(ins);matches.extend(lift.matches);lift.matches=[]
                elif ins.group(cs.CS_GRP_JUMP) or transfer:
                    dest=ins.operands[-1].imm if ins.operands and ins.operands[-1].type==2 else None
                    if dest is not None and lift.domain=='thumb':dest&=~1
                    unconditional=ins.mnemonic in {'jmp','b','b.w','bx','br','j'} or transfer=='direct'
                    if unconditional:
                        if dest is None or not start<=dest<start+size:
                            lift.step(ins);matches.extend(lift.matches+lift.equations.matches+lift.equations.general_matches);break
                        next_at=dest
                    elif dest is not None and start<=dest<start+size and dest not in visited:
                        pending.append((dest,state(),frozenset(visited)))
                else:lift.step(ins)
                at=next_at
            matches.extend(lift.equations.matches+lift.equations.general_matches)
        records.append({'address':start,'bytes':size,'explored_paths':paths,'limited':limited})
    return matches,records
