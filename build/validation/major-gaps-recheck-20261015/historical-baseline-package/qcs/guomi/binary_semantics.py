"""Local standard-operation evidence in executable ELF/PE ranges.

SM3 requires both distinct linear maps and round arithmetic in one bounded code
neighbourhood. SM4 additionally requires actual reads from complete, verified
standard substitution/linear tables. This never promotes a table by itself.
Supported lifting is deliberately limited; unsupported instructions invalidate
their destinations, and joins/calls discard the register/memory state.
"""
from collections import Counter
from bisect import bisect_left, bisect_right
import json
from pathlib import Path
import time

from .linear import leaf, rotate, shift, xor, merge_shifts, roles, bits, truncate, role_tags
from ..model import evidence, error, sha256

STANDARD = Path(__file__).with_name('standard.json')
DATA = json.loads(STANDARD.read_text(encoding="utf-8"))
MAX_CODE = 16 * 1024 * 1024
MAX_INSTRUCTIONS = 1_000_000
WINDOW = 8192


def rol(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xffffffff if n else x


def table_patterns():
    sbox = DATA['sm4_sbox']
    yield 'sbox', bytes(sbox)
    for endian in ('little', 'big'):
        yield 'ck', b''.join(x.to_bytes(4, endian) for x in DATA['sm4_ck'])
        for role, rotations in [('block_table', (0, 2, 10, 18, 24)),
                                ('key_table', (0, 13, 23))]:
            for byte_position in (0, 8, 16, 24):
                values = []
                for x in sbox:
                    v = 0
                    for n in rotations:
                        v ^= rol(x << byte_position, n)
                    values.append(v)
                yield role, b''.join(x.to_bytes(4, endian) for x in values)


def locate_tables(regions):
    result = []
    for base, offset, data, flags in regions:
        if flags & 1 or not isinstance(data, bytes):
            continue
        for kind, raw in table_patterns():
            start = 0
            while (at := data.find(raw, start)) >= 0:
                result.append({'kind': kind, 'address': base + at, 'offset': offset + at, 'length': len(raw)})
                start = at + len(raw)
    return result


def tags(value):
    if value[0] == 'lin':
        return set(t for identity, _ in value[1] for t in identity[1])
    if value[0] in {'shift', 'rot'}:
        return tags(value[1])
    if value[0]=='bits':return {t for atoms in value[1] for identity,_ in atoms for t in identity[1]}
    return set()


def disassembler(domain):
    import capstone as cs
    mapping = {'x86_64': (cs.CS_ARCH_X86, cs.CS_MODE_64),
               'pe_x86_64': (cs.CS_ARCH_X86, cs.CS_MODE_64),
               'aarch64': (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM),
               'arm': (cs.CS_ARCH_ARM, cs.CS_MODE_ARM),
               'thumb': (cs.CS_ARCH_ARM, cs.CS_MODE_THUMB),
               'mipsel': (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32 | cs.CS_MODE_LITTLE_ENDIAN),
               'mips_be': (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32 | cs.CS_MODE_BIG_ENDIAN)}
    if domain not in mapping:
        return None
    dis = cs.Cs(*mapping[domain]); dis.detail = True; dis.skipdata = True
    return dis


def decode(dis, data, base):
    """Work around Capstone 5's truncated x86 UD1 operand decoding.

    Clang's checked builds emit UD1 with a ModRM/displacement. Capstone 5
    consumes only the opcode, decoding its operand bytes as bogus instructions.
    Skip the documented operand encoding and restart at the next instruction.
    """
    at=0
    while at<len(data):
        restart=False;consumed=at
        # Capstone materialises its entire requested block in C. Small batches
        # prevent quadratic decoding when many checked-build traps restart it.
        for ins in dis.disasm(data[at:at+4096],base+at,count=128):
            consumed=ins.address-base+ins.size
            yield ins
            if ins.mnemonic=='ud1' and dis.arch==3:
                end=ins.address-base+ins.size
                if end>=len(data):return
                modrm=data[end];mod=modrm>>6;rm=modrm&7;end+=1
                if mod!=3 and rm==4:
                    if end>=len(data):return
                    sib=data[end];end+=1
                    if mod==0 and sib&7==5:end+=4
                elif mod==0 and rm==5:end+=4
                if mod==1:end+=1
                elif mod==2:end+=4
                at=end;restart=True;break
        if not restart:
            if consumed<=at:return
            at=consumed


class Lift:
    def __init__(self, domain, tables, regions, *, helper_depth=0, helper_budget=None, helper_cache=None):
        self.domain, self.tables, self.regions = domain, tables, regions
        self.regs, self.memory, self.addresses = {}, {}, {}
        self.address_memory={}
        self.events = []
        self.serial = 0
        self.helper_depth=helper_depth
        self.helper_budget=helper_budget if helper_budget is not None else [0]
        self.helper_calls=[]
        self.helper_cache={} if helper_cache is None else helper_cache
        from ..operations import Arithmetic
        self.arithmetic=Arithmetic()
        from ..operation_arrays import Arrays
        self.arrays=Arrays(self.arithmetic)
        self.array_addresses={}
        self.array_memory={}
        self.guard_cache={}
        self.stack_offsets={'rsp':0} if 'x86' in domain else {'sp':0}
        self.cfg_mode=False
        self.stable_site=None
        self.stable_counter=0

    def guard_successor(self, ins):
        """Prove a conditional edge terminates in a side-effect-free trap.

        This is bounded successful-path exploration, not an arbitrary CFG join.
        Only NOPs and direct unconditional jumps may precede UD1/UD2/BRK/UDF.
        A store, call, arithmetic instruction, return or another condition makes
        the edge unknown. MIPS delay-slot branches are deliberately excluded.
        """
        import capstone as cs
        if self.domain not in {'x86_64','pe_x86_64','aarch64','arm','thumb'}:
            return None
        if not ins.id or not ins.group(cs.CS_GRP_JUMP) or ins.group(cs.CS_GRP_CALL):return None
        mnemonic=ins.mnemonic
        if mnemonic in {'jmp','b','b.w','bx','br'}:return None
        if not ins.operands or ins.operands[-1].type!=2:return None
        destination=ins.operands[-1].imm
        fallthrough=ins.address+ins.size
        def edge(start):
            if start in self.guard_cache:return self.guard_cache[start]
            at=start;seen=set();result=(False,start)
            for _ in range(4):
                if at in seen:break
                seen.add(at)
                raw=self.read_virtual(at,16)
                if not raw:break
                op=next(decode(disassembler(self.domain),raw,at),None)
                if op is None or not op.id:break
                if op.mnemonic in {'ud1','ud2','brk','udf'} or (self.domain in {'arm','thumb'} and op.mnemonic=='trap'):
                    result=(True,at);break
                if op.mnemonic in {'nop','hint'} and (op.mnemonic=='nop' or op.op_str in {'#0',''}):
                    at=op.address+op.size;result=(False,at);continue
                if op.mnemonic in {'jmp','b','b.w'} and len(op.operands)==1 and op.operands[0].type==2:
                    target=op.operands[0].imm
                    if abs(target-start)>256:break
                    at=target;result=(False,at);continue
                result=(False,at);break
            self.guard_cache[start]=result
            return result
        left,right=edge(fallthrough),edge(destination)
        if left[0]==right[0]:return None
        successful=right[1] if left[0] else left[1]
        # Streaming exploration must not revisit instructions or silently skip
        # an unbounded region. The successful edge starts at its actual code.
        if fallthrough<=successful<=fallthrough+256:return successful
        return None

    def successful_instructions(self, dis, data, base):
        resume=base
        for ins in decode(dis,data,base):
            if ins.address<resume:continue
            if (self.domain in {'x86_64','pe_x86_64','aarch64','arm','thumb'} and
                ins.id and ins.mnemonic in {'jmp','b','b.w'} and len(ins.operands)==1 and
                ins.operands[0].type==2 and ins.operands[0].imm==ins.address+ins.size):
                # A branch to the next instruction has no alternative path.
                continue
            successor=self.guard_successor(ins)
            if successor is not None:
                self.events.append((ins.address,'proved_trap_guard',successor))
                resume=successor
                continue
            yield ins

    def array_address(self,ins,op):
        if self.domain not in {'x86_64','pe_x86_64','arm','thumb','aarch64'} or op.type!=3:return None
        mem=op.mem
        if not mem.base or ins.reg_name(mem.base)=='rip':return None
        base=self.key(ins,mem.base)
        if base in {'rsp','rbp','sp','fp','r11'}:return None
        if mem.index:
            if self.domain in {'x86_64','pe_x86_64'}:scale=mem.scale
            elif self.domain in {'arm','thumb','aarch64'}:
                sh=getattr(op,'shift',None);scale=1<<(sh.value if sh else 0)
                if sh and sh.value and sh.type not in {1,2}:return None
            else:return None
            if scale in {1,4}:return ((self.reg(ins,mem.base),mem.disp,scale),self.reg(ins,mem.index))
        if base in self.array_addresses and not mem.index and mem.disp==0:
            return self.array_addresses[base]
        return None

    def computed_array_address(self,ins,m,ops):
        """Normalize real base+index addressing, including ARM ADD+LDRB."""
        if m in {'mov','ldr','ldur'} and len(ops)==2:
            if ops[1].type==1:return self.array_addresses.get(self.key(ins,ops[1].reg))
            if ops[1].type==3:return self.array_memory.get(self.mem_key(ins,ops[1]))
        if m=='lea' and len(ops)==2:return self.array_address(ins,ops[1])
        if self.domain in {'x86_64','pe_x86_64'} and m=='add' and len(ops)==2 and all(o.type==1 for o in ops) and ops[0].size==8:
            if self.key(ins,ops[0].reg) in {'rsp','rbp'}:return None
            return ((self.reg(ins,ops[0].reg),0,1),self.reg(ins,ops[1].reg))
        if self.domain not in {'arm','thumb','aarch64'} or m!='add' or len(ops)!=3:return None
        if not all(o.type==1 for o in ops):return None
        base=self.key(ins,ops[1].reg)
        if base in {'sp','fp','r11'} or base in self.addresses:return None
        sh=getattr(ops[2],'shift',None);scale=1<<(sh.value if sh else 0)
        if sh and sh.value and sh.type not in {1,2}:return None
        if scale not in {1,4}:return None
        return ((self.reg(ins,ops[1].reg),0,scale),self.reg(ins,ops[2].reg))

    def new(self, source_tags=()):
        if self.stable_site is not None:
            self.stable_counter+=1
            return leaf((('cfg',self.stable_site,self.stable_counter),tuple(sorted(source_tags))))
        self.serial += 1
        return leaf((self.serial, tuple(sorted(source_tags))))

    def key(self, ins, reg):
        name = ins.reg_name(reg)
        if self.domain in {'x86_64', 'pe_x86_64'}:
            aliases = {'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
                       'esi': 'rsi', 'edi': 'rdi', 'ebp': 'rbp', 'esp': 'rsp'}
            aliases.update({'al':'rax','ah':'rax','bl':'rbx','bh':'rbx','cl':'rcx','ch':'rcx','dl':'rdx','dh':'rdx',
                            'sil':'rsi','dil':'rdi','bpl':'rbp','spl':'rsp'})
            name = aliases.get(name, name)
            if name.startswith('r') and name.endswith('d'):
                name = name[:-1]
            if name.startswith('r') and name.endswith('b') and name[1:-1].isdigit():name=name[:-1]
        if self.domain == 'aarch64' and name.startswith('w'):
            name = 'x' + name[1:]
        return name

    def reg(self, ins, reg):
        k = self.key(ins, reg)
        if k not in self.regs:
            self.regs[k] = self.new()
        return self.regs[k]

    def read_virtual(self, address, size):
        from ..function_signatures import read_virtual
        return read_virtual(self.regions, address, size)

    def mem_key(self, ins, op):
        m = op.mem
        base = self.key(ins, m.base) if m.base else ''
        index = self.key(ins, getattr(m, 'index', 0)) if getattr(m, 'index', 0) else ''
        # Only frame-local spills are propagated. Other memory can alias.
        if base in self.stack_offsets and not index:return ('frame',self.stack_offsets[base]+m.disp)
        if base in {'rsp','rbp','sp','fp','r11'} and not index:return (base,m.disp)
        # Consecutive aligned state-word accesses through the very same
        # unchanged pointer can be related. Distinct pointer writes invalidate
        # these cells because their alias relation is unknown.
        if base and not index and m.disp%4==0 and abs(m.disp)<=4096 and getattr(op,'size',4) in {0,4}:
            return ('data',self.reg(ins,m.base),m.disp)
        return None

    def mem_address(self, ins, op):
        m = op.mem
        base = self.key(ins, m.base) if m.base else ''
        if base == 'rip':
            return ins.address + ins.size + m.disp
        if base in self.addresses:
            return self.addresses[base] + m.disp
        index = getattr(m, 'index', 0)
        if index and self.key(ins, index) in self.addresses and getattr(m, 'scale', 1) == 1:
            return self.addresses[self.key(ins, index)] + m.disp
        if base == 'pc':
            return ((ins.address + (4 if self.domain == 'thumb' else 8)) & ~3) + m.disp
        if not base:
            return m.disp
        return None

    def table_at(self, address):
        if address is None:
            return None
        return next((t for t in self.tables if t['address'] <= address < t['address'] + t['length']), None)

    def operand(self, ins, op):
        import capstone as cs
        # Operand type 1=register, 2=immediate, 3=memory in all supported backends.
        if op.type == 1:
            value = self.reg(ins, op.reg)
            if self.domain in {'x86_64','pe_x86_64'} and getattr(op,'size',0)==1:
                start=8 if ins.reg_name(op.reg) in {'ah','bh','ch','dh'} else 0
                value=('constant',(value[1]>>start)&255) if value[0]=='constant' else truncate(value,8,start)
            sh = getattr(op, 'shift', None)
            if sh is not None and sh.value:
                name = self.domain
                # ARM/ARM64 enums differ; use explicit backend constants.
                if name == 'aarch64':
                    direction = {cs.arm64.ARM64_SFT_LSL: 'left', cs.arm64.ARM64_SFT_LSR: 'right'}.get(sh.type)
                    ror = sh.type == cs.arm64.ARM64_SFT_ROR
                else:
                    direction = {cs.arm.ARM_SFT_LSL: 'left', cs.arm.ARM_SFT_LSR: 'right'}.get(sh.type)
                    ror = sh.type == cs.arm.ARM_SFT_ROR
                if ror:
                    self.events.append((ins.address, 'rotate', (32 - sh.value) % 32))
                    return rotate(value, -sh.value)
                if direction:
                    return shift(value, direction, sh.value)
                return self.new()
            return value
        if op.type == 2:
            return ('constant', op.imm & 0xffffffff)
        if op.type == 3:
            key = self.mem_key(ins, op)
            table = self.table_at(self.mem_address(ins, op))
            if table:
                self.events.append((ins.address, 'table_read', table['kind']))
                if table['kind'].startswith('lane_rotate_'):
                    return ('shuffle',int(table['kind'].rsplit('_',1)[1]))
                value=self.new([table['kind']])
                return truncate(value,8) if table['kind']=='sbox' else value
            address=self.array_address(ins,op)
            if address:
                value=self.new()
                if getattr(op,'size',0)==1:value=truncate(value,8)
                return self.arrays.load(*address,value,ins.address)
            if key and key in self.memory:return self.memory[key]
            if key:
                self.memory[key]=self.new()
                return self.memory[key]
            return self.new()
        return self.new()

    def put(self, ins, op, value):
        if value[0] == 'unknown':
            value = self.new()
        if op.type == 1:
            self.regs[self.key(ins, op.reg)] = value
        elif op.type == 3:
            from ..operation_tables import SHA256_IV
            if self.arrays.output(value):self.events.append((ins.address,'rc4_prga',None))
            if value[0]=='constant' and value[1] in SHA256_IV:self.events.append((ins.address,'iv_store',value[1]))
            address=self.array_address(ins,op)
            if address:self.arrays.store(*address,value,ins.address)
            key = self.mem_key(ins, op)
            if not address and (not key or key[0]=='data'):self.arrays.reset()
            if key:
                if key[0]=='data':
                    self.memory={k:v for k,v in self.memory.items() if k[0]!='data' or k[1]==key[1]}
                self.memory[key] = value
            else:
                if address:
                    # Indexed external state writes cannot overwrite private
                    # spill cells in this invocation's allocated stack frame.
                    self.memory={k:v for k,v in self.memory.items() if k[0]!='data'}
                else:
                    self.memory.clear()
                    self.address_memory.clear()
        for role in roles(value):
            self.events.append((ins.address, role, role_tags(value,role)))
        if value[0]=='constant':self.events.append((ins.address,'constant',value[1]))
        if value[0]=='lin' and any(r==7 for _,r in value[1]) and self.arithmetic.quarter(value):
            self.events.append((ins.address,'chacha_quarter',None))
        if value[0]=='lin' and len(value[1])==1:
            (_,rotation),=value[1]
            if rotation:self.events.append((ins.address,'rotate',rotation))

    def step(self, ins):
        if not ins.id:
            self.regs.clear(); self.memory.clear(); self.addresses.clear(); self.array_addresses.clear(); self.array_memory.clear(); self.arrays.reset();return
        import capstone as cs
        ops = ins.operands
        m = ins.mnemonic.split('.')[0]
        if self.domain in {'arm', 'thumb'} and m in {'eors','orrs','lsls','lsrs','adds','subs','movs','rors','ands'}:
            m = m[:-1]
        x86 = self.domain in {'x86_64', 'pe_x86_64'}
        if m in {'sm4e','sm4ekey','vsm4rnds4','vsm4key4','sm3ss1','sm3tt1a','sm3tt1b',
                 'sm3tt2a','sm3tt2b','sm3partw1','sm3partw2',
                 'aesenc','aesenclast','aesdec','aesdeclast','aese','aesmc','aesd','aesimc',
                 'sha256rnds2','sha256msg1','sha256msg2','sha256h','sha256h2','sha256su0','sha256su1',
                 'sha1c','sha1p','sha1m','sha1h','sha1su0','sha1su1'}:
            self.events.append((ins.address,'crypto_instruction',m))
        if ins.group(cs.CS_GRP_CALL):
            if self.local_call(ins): return
        regkey = self.key(ins, ops[0].reg) if ops and ops[0].type == 1 else None
        old_addresses = dict(self.addresses)
        old_stack=dict(self.stack_offsets)
        array_address=self.computed_array_address(ins,m,ops)
        try:
            _, writes = ins.regs_access()
        except cs.CsError:
            writes = []
        if self.domain in {'mipsel', 'mips_be'} and ops and ops[0].type == 1 and m not in {'sw','sb','sh','jr','j','jal','beq','bne'}:
            writes = [ops[0].reg]
        # Recover direct data addresses (including resolved GOT pointers).
        address = None
        if m in {'adr', 'adrp'} and len(ops) == 2 and ops[1].type == 2:
            address = ops[1].imm
        elif x86 and m == 'lea' and len(ops) == 2 and ops[1].type == 3:
            address = self.mem_address(ins, ops[1])
        elif m in {'mov', 'movabs', 'movw', 'li'} and len(ops) >= 2 and ops[1].type == 2:
            address = ops[1].imm
        elif m in {'mov','move'} and len(ops)==2 and ops[1].type==1:
            address=old_addresses.get(self.key(ins,ops[1].reg))
        if self.domain in {'arm','thumb'} and m=='add' and len(ops) in {2,3}:
            sources=ops if len(ops)==2 else ops[1:]
            if all(o.type==1 for o in sources):
                keys=[self.key(ins,o.reg) for o in sources]
                if 'pc' in keys:
                    other=next((k for k in keys if k!='pc'),None)
                    if other in old_addresses:address=ins.address+(4 if self.domain=='thumb' else 8)+old_addresses[other]
        if m == 'lui' and len(ops) == 2:
            address = ops[1].imm << 16
        elif m == 'movt' and len(ops) == 2 and regkey in old_addresses:
            address = (old_addresses[regkey] & 0xffff) | (ops[1].imm << 16)
        elif m in {'add', 'addi', 'addiu', 'ori'}:
            source = ops[0] if x86 else ops[1] if len(ops) > 1 else None
            imm = ops[-1].imm if ops and ops[-1].type == 2 else None
            if source and source.type == 1 and imm is not None and self.key(ins, source.reg) in old_addresses:
                base = old_addresses[self.key(ins, source.reg)]
                address = base | imm if m == 'ori' else base + imm
            elif source and source.type==1 and self.key(ins,source.reg) in old_addresses and self.table_at(old_addresses[self.key(ins,source.reg)]):
                address=old_addresses[self.key(ins,source.reg)]
        elif m in {'mov', 'ldr', 'ldur', 'lw', 'ld'} and len(ops) == 2 and ops[1].type == 3:
            at = self.mem_address(ins, ops[1])
            spill=self.mem_key(ins,ops[1])
            width = getattr(ops[0], 'size', 0) or (8 if self.domain == 'aarch64' and regkey.startswith('x') else 4)
            if spill in self.address_memory:address=self.address_memory[spill]
            elif at is not None and width in {4, 8}:
                raw = self.read_virtual(at, width)
                if raw:
                    address = int.from_bytes(raw, 'big' if self.domain == 'mips_be' else 'little')
        # Memory operands use the pre-instruction base even when the load writes
        # that same register (e.g. movzx eax, byte ptr [rax]). Commit addresses
        # only after all source operands have been evaluated.
        if x86 and m=='mov' and len(ops)==2 and ops[0].type==3:
            spill=self.mem_key(ins,ops[0])
            if spill:
                self.address_memory.pop(spill,None)
                if ops[1].type==1 and self.key(ins,ops[1].reg) in old_addresses:
                    self.address_memory[spill]=old_addresses[self.key(ins,ops[1].reg)]
        # Pointer-expression spills are private frame cells. A stale descriptor
        # must be removed whenever that cell is overwritten by any value.
        pointer_spill=None
        if m in {'mov','str','stur'} and len(ops)==2:
            memory,source=(ops[0],ops[1]) if x86 else (ops[1],ops[0])
            if memory.type==3 and source.type==1:
                key=self.mem_key(ins,memory)
                if key and key[0]!='data' and self.key(ins,source.reg) in self.array_addresses:
                    pointer_spill=(key,self.array_addresses[self.key(ins,source.reg)])
        # Abstract values must only describe 32-bit/lane operations.
        handled = False
        word32 = (not x86 or (ops and getattr(ops[0], 'size', 0) == 4))
        if self.domain == 'aarch64' and ops and ops[0].type == 1:
            word32 = ins.reg_name(ops[0].reg).startswith('w')
        lane32 = m in {'pxor','vpxor','vpxord','por','vpor','pslld','psrld','vpslld','vpsrld','paddd','vpaddd','pand'}
        if len(ops) >= 2:
            dest = ops[0]
            # Thumb/ARM also have destructive two-operand arithmetic forms:
            # eors r1,r3 means r1 = r1 XOR r3. Treating r3 as the sole
            # source loses the dependent round graph despite identical maths.
            destructive = (x86 or (self.domain in {'arm','thumb'} and
                m in {'eor','orr','add','sub','and','bic','lsl','lsr','ror'}))
            args = ops if destructive and len(ops) == 2 else ops[1:]
            if m in {'mov', 'movzx', 'movsxd', 'movd', 'movdqa', 'movdqu', 'vmovdqa', 'vmovdqu',
                     'movaps','movups','vmovaps','vmovups',
                     'ldr', 'ldur', 'ldrb', 'ldrh', 'lw', 'lbu', 'lhu', 'move'}:
                self.put(ins, dest, self.operand(ins, ops[1])); handled = True
            elif self.domain in {'arm','thumb'} and m in {'ror','lsl','lsr'} and len(ops)==2 and getattr(ops[1],'shift',None) and ops[1].shift.value:
                # Capstone represents ARM immediate shift aliases on the
                # source register instead of as a third immediate operand.
                self.put(ins,dest,self.operand(ins,ops[1]));handled=True
            elif word32 and x86 and m=='lea' and len(ops)==2 and ops[1].type==3:
                mem=ops[1].mem
                if mem.base and mem.index and mem.scale==1:
                    a,b=self.reg(ins,mem.base),self.reg(ins,mem.index)
                    value=merge_shifts(a,b) if not mem.disp else ('unknown',)
                    if value[0]=='unknown':
                        value=self.new(tags(a)|tags(b)|{'add'})
                        if not mem.disp:self.arithmetic.add(a,b,value)
                    if mem.disp:self.events.append((ins.address,'immediate',mem.disp&0xffffffff))
                    self.put(ins,dest,value);handled=True
                    self.events.append((ins.address,'add',None))
            elif m in {'str', 'stur', 'strb', 'strh', 'sw', 'sb', 'sh'} and len(ops) == 2:
                self.put(ins, ops[1], self.operand(ins, ops[0])); handled = True
            elif (word32 or lane32) and m in {'xor', 'eor', 'pxor', 'vpxor', 'vpxord'} and len(args) == 2:
                a, b = [self.operand(ins, o) for o in args]
                if self.arrays.xor(a,b):self.events.append((ins.address,'rc4_prga',None))
                self.put(ins, dest, xor(a, b)); self.events.append((ins.address, 'xor', None)); handled = True
            elif (word32 or lane32) and m in {'or', 'orr', 'por', 'vpor'} and len(args) == 2:
                a, b = [self.operand(ins, o) for o in args]
                value = merge_shifts(a, b)
                if value[0] == 'unknown':
                    value = self.new(tags(a) | tags(b))
                self.put(ins, dest, value); handled = True
            elif m in {'pshufb','vpshufb'} and len(args)==2:
                a,mask=[self.operand(ins,o) for o in args]
                if mask[0]=='shuffle':
                    self.put(ins,dest,rotate(a,mask[1]));handled=True
                    self.events.append((ins.address,'rotate',mask[1]))
            elif word32 and m in {'rol', 'ror', 'rorx', 'rotr'} and self.operand(ins,args[-1])[0]=='constant':
                value = self.operand(ins, args[0]); count = self.operand(ins,args[-1])[1]
                if m != 'rol': count = -count
                self.put(ins, dest, rotate(value, count)); self.events.append((ins.address, 'rotate', count % 32)); handled = True
            elif word32 and m == 'extr' and len(ops) == 4 and ops[1].reg == ops[2].reg and ops[3].type == 2:
                self.put(ins, dest, rotate(self.operand(ins, ops[1]), -ops[3].imm));
                self.events.append((ins.address, 'rotate', (32 - ops[3].imm) % 32)); handled = True
            elif word32 and x86 and m in {'shld','shrd'} and len(ops)==3 and ops[2].type==2 and 0<ops[2].imm<32:
                n=ops[2].imm
                a,b=[self.operand(ins,o) for o in ops[:2]]
                aa,bb=bits(a),bits(b)
                if aa is not None and bb is not None:
                    av,bv=('bits',aa),('bits',bb)
                    value=merge_shifts(shift(av,'left' if m=='shld' else 'right',n),shift(bv,'right' if m=='shld' else 'left',32-n))
                    self.put(ins,dest,value);handled=True
            elif (word32 or lane32) and m in {'shl', 'sal', 'shr', 'lsl', 'lsr', 'sll', 'srl', 'pslld', 'psrld', 'vpslld', 'vpsrld'} and self.operand(ins,args[-1])[0]=='constant':
                direction = 'left' if m in {'shl', 'sal', 'lsl', 'sll', 'pslld', 'vpslld'} else 'right'
                count=self.operand(ins,args[-1])[1]&31
                value=self.operand(ins,args[0])
                self.put(ins, dest, shift(value,direction,count) if count else value); handled = True
            elif m in {'add', 'addu', 'addiu', 'paddd', 'vpaddd', 'sub', 'subu', 'and', 'andi', 'andn', 'bic', 'pand'}:
                ts = set().union(*(tags(self.operand(ins, o)) for o in args))
                if m in {'add','addu','addiu','paddd','vpaddd'}:ts.add('add')
                vals=[self.operand(ins,o) for o in args]
                value=self.new(ts)
                byte_add=x86 and ops and getattr(ops[0],'size',0)==1 and m=='add'
                if (word32 or lane32 or byte_add) and m in {'add','addu','addiu','paddd','vpaddd'} and len(vals)==2:
                    self.arithmetic.add(vals[0],vals[1],value)
                    if byte_add:value=truncate(value,8)
                if len(vals)==2 and all(v[0]=='constant' for v in vals):
                    a,b=[v[1] for v in vals]
                    result={'add':a+b,'addu':a+b,'addiu':a+b,'sub':a-b,'subu':a-b,'and':a&b,'andi':a&b}.get(m)
                    if result is not None:value=('constant',result&0xffffffff)
                if (word32 or lane32 or (m=='and' and len(args)==2 and args[-1].type==2 and args[-1].imm==255)) and m in {'and','andi'} and len(args)==2 and args[-1].type==2:
                    b=bits(self.operand(ins,args[0]));mask=args[-1].imm&0xffffffff
                    if b is not None:value=('bits',tuple(v if mask&(1<<i) else frozenset() for i,v in enumerate(b)))
                    if mask==255:self.arrays.mask(value,vals[0],8)
                self.put(ins, dest, value); handled = True
                self.events.append((ins.address, 'add' if m in {'add', 'addu', 'addiu', 'paddd', 'vpaddd'} else m, None))
            for o in ops:
                if o.type == 2:
                    self.events.append((ins.address, 'immediate', o.imm & 0xffffffff))
        if m=='neg' and ops and ops[0].type==1:
            value=self.operand(ins,ops[-1])
            if value[0]=='constant':self.put(ins,ops[0],('constant',(-value[1])&0xffffffff));handled=True
        if x86 and m=='inc' and ops and getattr(ops[0],'size',0) in {1,4}:
            a=self.operand(ins,ops[0]);value=self.new(tags(a)|{'add'})
            self.arithmetic.add(a,('constant',1),value)
            if ops[0].size==1:value=truncate(value,8)
            self.put(ins,ops[0],value);self.events.append((ins.address,'add',None));handled=True
        if m in {'movw','movt','lui','li','ori'} and address is not None and ops and ops[0].type==1:
            self.put(ins,ops[0],('constant',address&0xffffffff));handled=True
        if x86 and m=='xor' and ops and getattr(ops[0],'size',0)==1 and len(ops)==2:
            a,b=[self.operand(ins,o) for o in ops]
            if self.arrays.xor(a,b):self.events.append((ins.address,'rc4_prga',None))
        if m=='rsb' and len(ops)==3:
            a,b=[self.operand(ins,o) for o in ops[1:]]
            if a[0]==b[0]=='constant':self.put(ins,ops[0],('constant',(b[1]-a[1])&0xffffffff));handled=True
        if word32 and m in {'ubfx','ubfiz','bfi','bfxil'} and len(ops)==4 and ops[2].type==ops[3].type==2:
            start,width=ops[2].imm,ops[3].imm
            source=bits(self.operand(ins,ops[1]))
            original=bits(self.operand(ins,ops[0])) if m in {'bfi','bfxil'} else tuple(frozenset() for _ in range(32))
            if source is not None and original is not None and 0<=start<32 and 0<width<=32-start:
                out=list(original)
                for j in range(width):
                    if m in {'bfi','ubfiz'}:out[start+j]=source[j]
                    else:out[j]=source[start+j]
                self.put(ins,ops[0],('bits',tuple(out)));handled=True
        if m in {'uxtb','uxth'} and len(ops)==2:
            self.put(ins,ops[0],truncate(self.operand(ins,ops[1]),8 if m=='uxtb' else 16));handled=True
        if not handled:
            for r in writes:
                self.regs[self.key(ins, r)] = self.new()
        for r in writes:self.stack_offsets.pop(self.key(ins,r),None)
        if m=='mov' and len(ops)==2 and ops[1].type==1 and self.key(ins,ops[1].reg) in old_stack:
            self.stack_offsets[regkey]=old_stack[self.key(ins,ops[1].reg)]
        if m in {'add','sub'} and len(ops)>=2 and ops[-1].type==2:
            src=ops[0] if x86 or len(ops)==2 else ops[1]
            if src.type==1 and self.key(ins,src.reg) in old_stack:
                self.stack_offsets[regkey]=old_stack[self.key(ins,src.reg)]+ops[-1].imm*(1 if m=='add' else -1)
        if x86 and m in {'push','pop'}:
            self.stack_offsets['rsp']=old_stack.get('rsp',0)+(8 if m=='pop' else -8)
        for r in writes:self.array_addresses.pop(self.key(ins,r),None)
        if regkey and array_address:self.array_addresses[regkey]=array_address
        if pointer_spill:self.array_memory[pointer_spill[0]]=pointer_spill[1]
        for r in writes:self.addresses.pop(self.key(ins,r),None)
        if regkey and address is not None:self.addresses[regkey]=address
        if ins.group(cs.CS_GRP_CALL) or ins.group(cs.CS_GRP_RET) or (ins.group(cs.CS_GRP_JUMP) and not self.cfg_mode):
            self.regs.clear(); self.memory.clear(); self.addresses.clear();self.address_memory.clear()
            self.array_addresses.clear();self.arrays.reset()
            self.array_memory.clear()

    def local_call(self, ins):
        """Summarize bounded scalar/state helpers using their real bytes.

        No target symbols or helper names are used. Unknown calls/branches,
        unbound memory writes and larger functions decline the summary. Constant
        offsets from actual state arguments may be written. Caller stack state
        and ABI-preserved registers survive only a complete helper summary.
        """
        import capstone as cs
        abi={'x86_64':(['rdi','rsi','rdx','rcx','r8','r9'],'rax',{'rbx','rbp','r12','r13','r14','r15','rsp'}),
             'pe_x86_64':(['rcx','rdx','r8','r9'],'rax',{'rbx','rbp','rdi','rsi','r12','r13','r14','r15','rsp'}),
             'aarch64':(['x'+str(i) for i in range(8)],'x0',{'sp','fp',*('x'+str(i) for i in range(19,30))}),
             'arm':(['r0','r1','r2','r3'],'r0',{'sp','fp',*('r'+str(i) for i in range(4,12))}),
             'thumb':(['r0','r1','r2','r3'],'r0',{'sp','fp',*('r'+str(i) for i in range(4,12))})}.get(self.domain)
        if not abi or self.helper_depth>=4 or self.helper_budget[0]>=12000:return False
        if len(ins.operands)!=1 or ins.operands[0].type!=2:return False
        target=ins.operands[0].imm
        if self.domain=='thumb':target&=~1
        raw=next((data[target-base:target-base+1024] for base,_,data,flags in self.regions
                  if flags&1 and base<=target<base+len(data)),None)
        if not raw:return False
        child=Lift(self.domain,self.tables,self.regions,helper_depth=self.helper_depth+1,
                   helper_budget=self.helper_budget,helper_cache=self.helper_cache)
        child.arithmetic=self.arithmetic
        args,ret,preserved=abi
        child.serial=self.serial
        # Initialise actual argument values before proving state writes.
        for key in args:
            if key not in self.regs:self.regs[key]=self.new()
        child.regs={k:self.regs[k] for k in args}
        argument_values=set(child.regs.values())
        child.memory={k:v for k,v in self.memory.items() if k[0]=='data'}
        state_writes=set()
        child.addresses={k:self.addresses[k] for k in args if k in self.addresses}
        complete=False
        if target not in self.helper_cache:
            self.helper_cache[target]=list(decode(disassembler(self.domain),raw,target))
        instructions=self.helper_cache[target]
        by_address={op.address:i for i,op in enumerate(instructions)}
        n=0;index=0
        while index<len(instructions):
            op=instructions[index];index+=1;n+=1
            self.helper_budget[0]+=1
            if n>=192 or not op.id:break
            if op.group(cs.CS_GRP_RET):complete=True;break
            if self.domain in {'arm','thumb'} and op.mnemonic=='bx' and op.op_str=='lr':complete=True;break
            if self.domain in {'arm','thumb'} and op.mnemonic.split('.')[0] in {'pop','ldm','ldmib'}:
                regs={op.reg_name(o.reg) for o in op.operands if o.type==1}
                if 'pc' in regs and 'r0' not in regs:complete=True;break
            if op.group(cs.CS_GRP_JUMP) and not op.group(cs.CS_GRP_CALL):
                dest=child.guard_successor(op)
                if dest in by_address:
                    index=by_address[dest];continue
                break
            # Store destinations outside this helper's frame could alias caller
            # values. Such helpers are not scalar summaries.
            bad_store=False
            for operand in op.operands:
                if operand.type==3 and getattr(operand,'access',0)&cs.CS_AC_WRITE:
                    key=child.mem_key(op,operand)
                    if key is None:bad_store=True
                    elif key[0]=='data':
                        if key[1] not in argument_values:bad_store=True
                        else:state_writes.add(key)
            if op.mnemonic in {'str','stur','strb','strh','stp'} and op.operands[-1].type==3:
                key=child.mem_key(op,op.operands[-1])
                if key is None:bad_store=True
                elif key[0]=='data':
                    if key[1] not in argument_values:bad_store=True
                    else:state_writes.add(key)
            if bad_store:break
            if op.group(cs.CS_GRP_CALL) and not child.local_call(op):break
            if not op.group(cs.CS_GRP_CALL):child.step(op)
        self.serial=max(self.serial,child.serial)
        value=child.regs.get(ret)
        if not complete or (value is None and not state_writes):return False
        if value is None:value=self.new()
        self.regs={k:v for k,v in self.regs.items() if k in preserved}
        self.addresses={k:v for k,v in self.addresses.items() if k in preserved}
        self.regs[ret]=value
        if state_writes:
            self.memory={k:v for k,v in self.memory.items() if k[0]!='data'}
            self.memory.update({k:child.memory[k] for k in state_writes if k in child.memory})
            self.arrays.reset()
        self.events.extend(child.events)
        # Also attach the proved callee's operations to its actual callsite.
        # This keeps compression/round witnesses together in the caller even
        # when the compiler placed helpers far away. Callee addresses remain in
        # the unprojected events and the helper-call trace.
        self.events.extend((ins.address,r,v) for _,r,v in child.events)
        self.helper_calls.append({'callsite':ins.address,'target':target,'return_roles':roles(value),
                                  'state_offsets':sorted(k[2] for k in state_writes),
                                  'proof':'bounded actual callee bytes, argument-bound state writes'})
        for role in roles(value):self.events.append((ins.address,role,role_tags(value,role)))
        return True


def witnesses(events, tables, *, window=WINDOW):
    result = []
    events = sorted(set((a, r, tuple(v) if isinstance(v,list) else v) for a,r,v in events), key=lambda e:e[0])
    positions = [e[0] for e in events]
    def neighbourhood(start, size):
        return events[bisect_left(positions,start):bisect_right(positions,start+size)]
    for anchor in [e for e in events if e[1]=='crypto_instruction']:
        nearby=neighbourhood(max(0,anchor[0]-window//2),window)
        ops={e[2] for e in nearby if e[1]=='crypto_instruction'}
        if ({'sm4e','sm4ekey'}<=ops or {'vsm4rnds4','vsm4key4'}<=ops) and not any(x[0]=='SM4' for x in result):
            result.append(('SM4',anchor[0],nearby,'Decoded ISA SM4 round and key expansion instructions'))
        if {'sm3ss1','sm3tt1a','sm3tt1b','sm3tt2a','sm3tt2b','sm3partw1','sm3partw2'}<=ops and not any(x[0]=='SM3' for x in result):
            result.append(('SM3',anchor[0],nearby,'Decoded ISA SM3 message expansion and both round instruction families'))
    # Independent roles are required in a bounded code neighbourhood. No global
    # opcode/rotation histograms or symbol/name scoring are used.
    examined=set()
    for anchor in [e for e in events if e[1]=='sm3_p0']:
        start = max(0, anchor[0] - window // 2)
        bucket=start//512
        if bucket in examined:continue
        examined.add(bucket)
        nearby = neighbourhood(start, window)
        counts = Counter(e[1] for e in nearby)
        rots = {e[2] for e in nearby if e[1] == 'rotate'}
        imms = {e[2] for e in nearby if e[1] == 'immediate'}
        if (not any(x[0]=='SM3' for x in result) and any(e[1]=='sm3_p0' and 'add' in e[2] for e in nearby) and counts['sm3_p1'] and {7, 12, 19} <= rots
                and counts['add'] >= 8 and counts['xor'] >= 12
                and counts['and'] + counts['pand'] >= 2
                and (64 in imms or counts['sm3_p0'] >= 8)):
            result.append(('SM3', anchor[0], nearby, 'P0/P1 with round rotations, arithmetic and 64-round/unrolled recurrence'))
            break
    sbox = [e for e in events if e[1] == 'table_read' and e[2] == 'sbox']
    block = [e for e in events if e[1] == 'sm4_l' and 'sbox' in e[2]]
    key = [e for e in events if e[1] == 'sm4_key_l' and 'sbox' in e[2]]
    ck = [e for e in events if e[1] == 'table_read' and e[2] == 'ck']
    bounded_rounds = any(e[1]=='immediate' and e[2] in {32,128} for e in events)
    if sbox and block and key and ck and (bounded_rounds or len(block)>=8):
        selected = [*block, *key]
        result.append(('SM4', min(e[0] for e in selected), selected,
                       'Standard S-box actually read; dependent block L and key L-prime maps both recovered'))
    # Precomputed T tables are exact complete S-box+L maps, not constants alone.
    # Require several actual indexed reads and XOR combinations in the same
    # block, plus the corresponding key role elsewhere in this module.
    treads = [e for e in events if e[1] == 'table_read' and e[2] in {'block_table', 'key_table', 'ck'}]
    for event in treads:
        local = neighbourhood(event[0],1024)
        c = Counter(e[2] for e in local if e[1] == 'table_read')
        if (c['block_table'] >= 4 and sum(e[1] == 'xor' for e in local) >= 4
                and (key or sum(e[2] == 'key_table' for e in treads) >= 4)
                and any(e[1] == 'table_read' and e[2] == 'ck' for e in events)):
            result.append(('SM4', event[0], local, 'Complete verified SM4 L tables referenced in XOR rounds and key schedule with CK'))
            break
    return result


def scan_binary_semantics(path, report, timeout, *, regions=None, architectures=None):
    from ..function_signatures import function_regions
    regions, domains = function_regions(path) if regions is None else (regions, architectures or [])
    deadline = time.monotonic() + timeout
    tables = locate_tables(regions)
    from ..operation_tables import locate
    from ..operations import binary_findings,emit
    generic_tables=locate(regions)
    tables+=generic_tables
    total_bytes = sum(len(data) for _, _, data, flags in regions if flags & 1)
    if total_bytes > MAX_CODE:
        error(report, 'guomi_semantic', 'max_code_bytes', f'Executable payload exceeds {MAX_CODE} bytes', 'partial'); return
    decoded = 0; matches = []; inspected = []; general_matches=set();cfg_records=[]
    for domain in domains:
        dis = disassembler(domain)
        if not dis:
            continue
        inspected.append(domain)
        from .binary_bignum import binary_equations
        try:
            static_records=[]
            equations=binary_equations(path,regions,domain,deadline,primitive_records=static_records)
            if static_records:report.setdefault('static_primitive_summaries',[]).extend(static_records)
        except ValueError as exc:
            error(report,'guomi_semantic','bignum_limit',str(exc),'partial');return
        sm2_equations=[m for m in equations if m.get('algorithm','SM2')=='SM2']
        for match in (m for m in equations if m.get('algorithm') in {'ECDSA','ECDH','RSA'}):
            general_matches.update(emit(report,[(match['algorithm'],match['offset'],
                [(w['offset'],'bignum_equation',w) for w in match['operation_witnesses']],match['equation'])],
                'operation_binary',domain=domain,regions=regions))
        if sm2_equations and 'SM2' not in matches:
            match=sm2_equations[0];matches.append('SM2')
            report['findings'].append(evidence('SM2','guomi_semantic','binary_instruction',
                'bignum_curve_equation',virtual_address=match['offset'],architecture=domain,
                confidence='medium',confidence_reason=match['equation'],
                implementation_verification='bounded_standard_operation_graph',
                operation_witnesses=match['operation_witnesses'],
                equation_kind=match['kind'],modulus=match['modulus']))
        lift = Lift(domain, tables, regions)
        clusters=[]
        for base, offset, data, flags in regions:
            if not flags & 1:
                continue
            lift.regs.clear(); lift.memory.clear(); lift.addresses.clear()
            function_start=base;event_start=len(lift.events)
            for ins in lift.successful_instructions(dis, data, base):
                decoded += 1
                if decoded % 1024 == 0 and (time.monotonic() > deadline or decoded > MAX_INSTRUCTIONS):
                    error(report, 'guomi_semantic', 'analysis_limit', 'Local operation analysis budget exhausted', 'partial'); return
                lift.step(ins)
                import capstone as cs
                if ins.id and ins.group(cs.CS_GRP_RET):
                    if ins.address-function_start<=128*1024:
                        events=[e for e in lift.events[event_start:] if function_start<=e[0]<=ins.address]
                        if any(e[1]=='sm3_p0' for e in events) and any(e[1]=='sm3_p1' for e in events):
                            clusters.append(events)
                    function_start=ins.address+ins.size;event_start=len(lift.events)
            # A separate conservative CFG pass restores facts across real
            # direct edges. The streaming pass remains for unsupported domains
            # and very large sections; loops do not concatenate alternatives.
            if len(data)<=256*1024 and domain not in {'mipsel','mips_be'} and time.monotonic()<deadline:
                from ..controlflow import analyze
                cfg_lift=Lift(domain,tables,regions)
                cfg=analyze(cfg_lift,list(decode(dis,data,base)),deadline)
                cfg_records.append({'architecture':domain,'section_address':base,**cfg})
                lift.events.extend(cfg_lift.events)
                lift.helper_calls.extend(cfg_lift.helper_calls)
        recognized=witnesses(lift.events,tables)
        general_matches.update(emit(report,binary_findings(lift.events,generic_tables),
            'operation_binary',domain=domain,regions=regions))
        if not any(x[0]=='SM3' for x in recognized):
            for cluster in clusters:
                found=[x for x in witnesses(cluster,[],window=256*1024) if x[0]=='SM3']
                if found:
                    recognized.extend(found);break
        for algorithm, address, events, reason in recognized:
            if algorithm in matches:
                continue
            matches.append(algorithm)
            offset = next((off + address - base for base, off, data, flags in regions
                           if flags & 1 and base <= address < base + len(data)), None)
            report['findings'].append(evidence(algorithm, 'guomi_semantic', 'binary_instruction',
                'standard_operation_graph', offset=offset, virtual_address=address, architecture=domain,
                confidence='medium', confidence_reason=reason,
                implementation_verification='bounded_standard_operation_graph',
                operation_witnesses=[{'address':a, 'role':r, 'detail':v} for a,r,v in events
                                     if r in {'sm3_p0','sm3_p1','sm4_l','sm4_key_l','table_read','crypto_instruction'}][:64],
                verified_tables=tables if algorithm == 'SM4' else []))
        if lift.helper_calls:
            relevant=[h for h in lift.helper_calls if h['return_roles']]
            report.setdefault('semantic_helper_calls',[]).extend((relevant or lift.helper_calls)[:128])
    report['engine_status']['guomi_semantic'] = {'status': 'completed', 'architectures': inspected,
                                               'instructions': decoded, 'matched_algorithms': matches}
    report['engine_status']['operation_binary']={'status':'completed','architectures':inspected,
        'matched_algorithms':sorted(general_matches),'shared_analysis':'guomi_semantic'}
    report['controlflow_analysis']=cfg_records
    report['versions']['guomi_standard_sha256'] = sha256(STANDARD)
    report['coverage_notes'].append('Guomi binary operation witnesses are bounded local data-flow and code-neighbourhood heuristics, not complete control-flow or semantic proofs; unsupported lifting may miss implementations.')
