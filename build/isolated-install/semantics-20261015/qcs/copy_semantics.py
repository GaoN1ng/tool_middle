"""Bounded byte-provenance interpreter for small static MIPS copy callees.

This proves a concrete call's byte transfer, not a function-name signature or a
general memcpy specification. Source and destination are disjoint abstract
regions. Every destination byte must contain the corresponding source token;
unknown instructions, addresses, calls and nonlocal writes reject the proof.
"""


def mips_copy(instructions, length, *, max_steps=8192):
    if not 1 <= length <= 256:
        return False
    ops = {i.address: i for i in instructions if i.id}
    if not ops:
        return False
    source, destination, frame = 0x200000, 0x400000, 0x800000
    regs = {'zero': 0, 'a0': destination, 'a1': source, 'a2': length,
            'sp': frame, 'ra': -1, 'fp': frame + 0x800}
    memory = {}; reads = set()

    def value(ins, op):
        if op.type == 2:
            return op.imm
        if op.type == 1:
            return regs.get(ins.reg_name(op.reg))
        return None

    def step(ins):
        m = ins.mnemonic; a = ins.operands
        if m == 'nop':
            return True
        if m in {'move', 'li', 'addiu', 'addi', 'addu', 'subu'} and len(a) >= 2:
            x = value(ins, a[1])
            if x is None:
                return False
            if len(a) == 3:
                y = value(ins, a[2])
                if not isinstance(x, int) or not isinstance(y, int):
                    return False
                x = x - y if m == 'subu' else x + y
            regs[ins.reg_name(a[0].reg)] = x
            return True
        if m in {'lbu', 'lw', 'sb', 'sw'} and len(a) == 2 and a[1].type == 3:
            base = regs.get(ins.reg_name(a[1].mem.base))
            if not isinstance(base, int):
                return False
            at = base + a[1].mem.disp
            if m == 'lbu' and source <= at < source + length:
                regs[ins.reg_name(a[0].reg)] = ('source-byte', at - source)
                reads.add(at - source)
            elif m == 'sb' and destination <= at < destination + length:
                memory[at] = value(ins, a[0])
            elif frame - 4096 <= at < frame and at % 4 == 0 and m in {'lw', 'sw'}:
                if m == 'sw':
                    memory[at] = value(ins, a[0])
                elif at in memory:
                    regs[ins.reg_name(a[0].reg)] = memory[at]
                else:
                    return False
            else:
                return False
            return True
        return False

    at = min(ops)
    for _ in range(max_steps):
        ins = ops.get(at)
        if ins is None:
            return False
        m = ins.mnemonic; a = ins.operands
        if m == 'jr' and ins.op_str == '$ra':
            slot = ops.get(at + 4)
            return bool(slot and step(slot) and len(reads) == length and
                        all(memory.get(destination + i) == ('source-byte', i) for i in range(length)))
        if m in {'beqz', 'bnez', 'beq', 'bne', 'b'}:
            target = a[-1].imm if a and a[-1].type == 2 else None
            if target is None:
                return False
            take = True
            if m != 'b':
                x = value(ins, a[0]); y = value(ins, a[1]) if len(a) == 3 else 0
                if not isinstance(x, int) or not isinstance(y, int):
                    return False
                take = (x == y) if m in {'beq', 'beqz'} else (x != y)
            slot = ops.get(at + 4)
            if slot is None or not step(slot):
                return False
            at = target if take else at + 8
        else:
            if not step(ins):
                return False
            at += ins.size
    return False
