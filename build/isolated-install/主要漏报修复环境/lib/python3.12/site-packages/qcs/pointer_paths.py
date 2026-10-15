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
        ranges=set()
        if elf.get_section_by_name('.eh_frame') is not None:
            ranges.update((entry['initial_location'],entry['address_range'])
                       for entry in elf.get_dwarf_info().EH_CFI_entries() if isinstance(entry,FDE)
                       and 0<entry['address_range']<=128*1024)
        section=elf.get_section_by_name('.ARM.exidx')
        if section is not None:
            raw=section.data();base=section['sh_addr'];starts=[]
            for offset in range(0,len(raw)-7,8):
                word=int.from_bytes(raw[offset:offset+4],'little' if elf.little_endian else 'big')&0x7fffffff
                displacement=word-(1<<31) if word&(1<<30) else word
                starts.append((base+offset+displacement)&~1)
            # EHABI entries are sorted by code address. The final sentinel
            # bounds the preceding function; never use data as code.
            for start,end in zip(starts,starts[1:]):
                if 0<end-start<=128*1024:ranges.add((start,end-start))
        return sorted(ranges)


def mips_pic_ranges(instructions,regions,gp):
    """Recover PIC entries only from a complete ABI GP setup equation.

    The LUI/ADDIU/add-with-t9 prologue must compute the ELF's actual GOT GP
    from its own entry address. No symbol names or return-position guesses.
    """
    if gp is None:return []
    starts=[]
    for n,ins in enumerate(instructions):
        if not ins.id:continue
        ops=ins.operands
        if ins.mnemonic!='lui' or len(ops)!=2:continue
        reg=ins.reg_name(ops[0].reg);value=(ops[1].imm<<16)&0xffffffff
        for following in instructions[n+1:n+32]:
            if not following.id:break
            o=following.operands;m=following.mnemonic
            if m=='addiu' and len(o)==3 and all(x.type==1 for x in o[:2]) and o[2].type==2 and following.reg_name(o[0].reg)==following.reg_name(o[1].reg)==reg:
                value=(value+o[2].imm)&0xffffffff
            elif m=='addu' and len(o)==3 and all(x.type==1 for x in o):
                sources={following.reg_name(x.reg) for x in o[1:]}
                if sources=={reg,'t9'} and (value+ins.address)&0xffffffff==gp:
                    starts.append(ins.address);break
            try:_,written=following.regs_access()
            except Exception:written=[]
            if m!='addiu' and any(following.reg_name(r)==reg for r in written):break
    starts=sorted(set(starts));ranges=[]
    for n,start in enumerate(starts):
        end=next((base+len(raw) for base,_,raw,flags in regions if flags&1 and base<=start<base+len(raw)),start)
        if n+1<len(starts):end=min(end,starts[n+1])
        if 0<end-start<=128*1024:ranges.append((start,end-start))
    return ranges


def analyze(lift, instructions, ranges, deadline, *, max_paths=128, max_steps=100000, helper_summaries=None):
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
                if ins.mnemonic.split('.')[0] in {'ud1','ud2','udf','trap','brk','hlt','break'}:break
                transfer=mips_transfer(ins) if mips else None
                if transfer=='unsupported':break
                if mips and transfer:
                    slot=operations.get(next_at)
                    if slot is None or mips_transfer(slot):break
                    lift.step(slot);next_at=at+8
                if terminal(ins,lift.domain) or transfer=='return':
                    if helper_summaries is not None:
                        from .curve_exchange import APIS
                        # A helper summary requires actual coordinate extraction
                        # and complete stores, with no other point/scalar math.
                        history=lift.equations.exchange.history
                        if not any(w['operation'] in APIS-{'sm2_z256_point_get_xy'} for w in history):
                            registers=(['rdi','rsi','rdx','rcx','r8','r9'] if lift.domain=='x86_64' else
                                       ['a'+str(i) for i in range(4)] if mips else
                                       ['r'+str(i) for i in range(4)] if lift.domain in {'arm','thumb'} else
                                       ['x'+str(i) for i in range(8)])
                            for out,point in lift.equations.exchange.xhats.items():
                                for p,reg in enumerate(registers):
                                    if point not in {'input:0:'+reg,'input:0:'+reg+'[0]'}:continue
                                    for q,dreg in enumerate(registers):
                                        if p!=q and out in {'input:0:'+dreg,'input:0:'+dreg+'[0]'}:
                                            helper_summaries[start]=(p,q)
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
                        condition=None;m=ins.mnemonic.split('.')[0]
                        if m in {'cbz','cbnz','beqz','bnez','tbz','tbnz'} and ins.operands[0].type==1:
                            value=lift.value(ins,ins.operands[0])
                            if value.lstrip('-').isdigit():
                                n=int(value)
                                if m in {'tbz','tbnz'} and len(ins.operands)>=3 and ins.operands[1].type==2:n=(n>>ins.operands[1].imm)&1
                                condition=(n==0) if m in {'cbz','beqz','tbz'} else (n!=0)
                        if condition is not False:pending.append((dest,state(),frozenset(visited)))
                        if condition is True:break
                else:lift.step(ins)
                at=next_at
            matches.extend(lift.equations.matches+lift.equations.general_matches)
        records.append({'address':start,'bytes':size,'explored_paths':paths,'limited':limited})
    return matches,records
