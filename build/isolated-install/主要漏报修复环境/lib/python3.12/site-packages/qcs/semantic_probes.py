"""Bounded concrete semantics in private Unicorn memory, never host execution.

Results are finite behavioral witnesses, not a proof for all inputs. No target
syscall, native callback, filesystem or network access is available. Only
relocation-backed byte-memory/encoding APIs have explicitly modeled effects.
Unsupported imports/instructions, memory faults and budgets fail closed.
"""
from __future__ import annotations

import hashlib
import time
from pathlib import Path

from .model import evidence

PAGE=4096
ARENA=0x50000000
STACK=0x60000000
TRAPS=0x70000000
STOP=0x71000000
ARENA_SIZE=0x40000


def montgomery(scalar,point):
    """RFC 7748 reference, with caller-supplied already-clamped scalar."""
    p=2**255-19;k=int.from_bytes(scalar,'little');u=int.from_bytes(point,'little')&((1<<255)-1)
    x2,z2,x3,z3,swap=1,0,u,1,0
    for bit in range(254,-1,-1):
        current=(k>>bit)&1;swap^=current
        if swap:x2,x3=x3,x2;z2,z3=z3,z2
        swap=current;a=(x2+z2)%p;aa=a*a%p;b=(x2-z2)%p;bb=b*b%p;e=(aa-bb)%p
        c=(x3+z3)%p;d=(x3-z3)%p;da=d*a%p;cb=c*b%p
        x3=(da+cb)**2%p;z3=u*(da-cb)**2%p;x2=aa*bb%p;z2=e*(aa+121665*e)%p
    if swap:x2,x3=x3,x2;z2,z3=z3,z2
    return (x2*pow(z2,p-2,p)%p).to_bytes(32,'little')


def curve_vectors():
    result=[]
    for index in range(3):
        scalar=bytearray(hashlib.sha256(('qcs-rfc7748-probe-'+str(index)).encode()).digest())
        scalar[0]&=248;scalar[31]=(scalar[31]&127)|64
        point=(9 if index==0 else 17+index).to_bytes(32,'little')
        result.append((bytes(scalar),point,montgomery(scalar,point)))
    return result


BLOCK_VECTORS={
 'AES':[
  ('000102030405060708090a0b0c0d0e0f','00112233445566778899aabbccddeeff','69c4e0d86a7b0430d8cdb78070b4c55a'),
  ('00000000000000000000000000000000','00000000000000000000000000000000','66e94bd4ef8a2c3b884cfa59ca342b2e'),
  ('2b7e151628aed2a6abf7158809cf4f3c','6bc1bee22e409f96e93d7e117393172a','3ad77bb40d7a3660a89ecaf32466ef97')],
 'DES':[
  ('133457799bbcdff1','0123456789abcdef','85e813540f0ab405'),
  ('0000000000000000','0000000000000000','8ca64de9c1b123a7'),
  ('ffffffffffffffff','ffffffffffffffff','7359b2163e4edc58')],
}


def des_boundary(raw):
    """IP^-1 * byte-swap-each-32-bit-half * IP, an explicit encoding.

    This represents a DES implementation with reversed word byte order at
    both permutation boundaries. It is involutive and never changes the key
    schedule or DES rounds. Acceptance records this nonstandard encoding.
    """
    ip=(58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
        62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
        57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
        61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7)
    value=int.from_bytes(raw,'big')
    perm=sum(((value>>(64-p))&1)<<(63-i) for i,p in enumerate(ip))
    packed=perm.to_bytes(8,'big');swapped=int.from_bytes(packed[:4][::-1]+packed[4:][::-1],'big')
    out=sum(((swapped>>(63-i))&1)<<(64-p) for i,p in enumerate(ip))
    return out.to_bytes(8,'big')


class Declined(Exception):pass


class Machine:
    def __init__(self,path,domain):
        import unicorn as uc
        from elftools.elf.elffile import ELFFile
        from .guomi.binary_bignum import import_slots
        self.path=Path(path);self.poisoned=False
        self.ucmod=uc;self.domain=domain;self.returned=False;self.fault=None;self.models={};self.model_calls=[]
        def backend(architecture,mode):
            machine=uc.Uc(architecture,mode)
            # Unicorn defaults to a very large translator reservation. Set a
            # bounded cache before the first register/memory access so the
            # isolated worker also runs under its 1 GiB address-space limit.
            machine.ctl_set_tcg_buffer_size(16*1024*1024)
            return machine
        if domain=='x86_64':
            from unicorn import x86_const as r
            self.machine=backend(uc.UC_ARCH_X86,uc.UC_MODE_64)
            self.args=[r.UC_X86_REG_RDI,r.UC_X86_REG_RSI,r.UC_X86_REG_RDX,r.UC_X86_REG_RCX,r.UC_X86_REG_R8,r.UC_X86_REG_R9]
            self.pc,self.sp,self.lr,self.ret=r.UC_X86_REG_RIP,r.UC_X86_REG_RSP,None,r.UC_X86_REG_RAX
            self.zero_regs=[getattr(r,'UC_X86_REG_'+n) for n in ('RAX','RBX','RCX','RDX','RSI','RDI','RBP','R8','R9','R10','R11','R12','R13','R14','R15')]
            self.width=8;self.endian='little';self.trapcode=b'\xc3'
        elif domain=='aarch64':
            from unicorn import arm64_const as r
            self.machine=backend(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM)
            self.args=[getattr(r,'UC_ARM64_REG_X'+str(i)) for i in range(8)]
            self.pc,self.sp,self.lr,self.ret=r.UC_ARM64_REG_PC,r.UC_ARM64_REG_SP,r.UC_ARM64_REG_LR,r.UC_ARM64_REG_X0
            self.zero_regs=[getattr(r,'UC_ARM64_REG_X'+str(i)) for i in range(29)]+[r.UC_ARM64_REG_FP]
            self.width=8;self.endian='little';self.trapcode=bytes.fromhex('c0035fd6')
        elif domain in {'arm','thumb'}:
            from unicorn import arm_const as r
            self.machine=backend(uc.UC_ARCH_ARM,uc.UC_MODE_ARM)
            self.machine.ctl_set_cpu_model(r.UC_CPU_ARM_CORTEX_A7)
            self.machine.reg_write(r.UC_ARM_REG_C1_C0_2,0xf<<20)
            self.machine.reg_write(r.UC_ARM_REG_FPEXC,1<<30)
            self.args=[getattr(r,'UC_ARM_REG_R'+str(i)) for i in range(4)]
            self.pc,self.sp,self.lr,self.ret=r.UC_ARM_REG_PC,r.UC_ARM_REG_SP,r.UC_ARM_REG_LR,r.UC_ARM_REG_R0
            self.zero_regs=[getattr(r,'UC_ARM_REG_R'+str(i)) for i in range(13)]
            self.width=4;self.endian='little';self.trapcode=bytes.fromhex('1eff2fe1')
        elif domain in {'mipsel','mips_be'}:
            from unicorn import mips_const as r
            self.machine=backend(uc.UC_ARCH_MIPS,uc.UC_MODE_MIPS32|(uc.UC_MODE_BIG_ENDIAN if domain=='mips_be' else uc.UC_MODE_LITTLE_ENDIAN))
            self.args=[getattr(r,'UC_MIPS_REG_A'+str(i)) for i in range(4)]
            self.pc,self.sp,self.lr,self.ret=r.UC_MIPS_REG_PC,r.UC_MIPS_REG_SP,r.UC_MIPS_REG_RA,r.UC_MIPS_REG_V0
            self.zero_regs=[getattr(r,'UC_MIPS_REG_'+str(i)) for i in range(1,32)]
            self.t9=r.UC_MIPS_REG_T9;self.width=4;self.endian='big' if domain=='mips_be' else 'little'
            self.trapcode=(0x03e00008).to_bytes(4,self.endian)+bytes(4)
        else:raise Declined('Unsupported emulation ABI')
        self.pages={};self.writable=[];self.code=[]
        with Path(path).open('rb') as stream:
            elf=ELFFile(stream)
            if elf['e_type'] not in {'ET_DYN','ET_EXEC'}:raise Declined('ELF type')
            for segment in elf.iter_segments():
                if segment['p_type']!='PT_LOAD':continue
                base,size=segment['p_vaddr'],segment['p_memsz'];flags=segment['p_flags']
                if size>32*1024*1024 or not 0<=base<ARENA-32*1024*1024:raise Declined('ELF mapping budget/address')
                permissions=(uc.UC_PROT_READ if flags&4 else 0)|(uc.UC_PROT_WRITE if flags&2 else 0)|(uc.UC_PROT_EXEC if flags&1 else 0)
                for page in range(base&-PAGE,(base+size+PAGE-1)&-PAGE,PAGE):self.pages[page]=self.pages.get(page,0)|permissions
                if flags&1:self.code.append((base,base+size))
                if flags&2:self.writable.append((base,segment.data()+bytes(size-segment['p_filesz'])))
            if len(self.pages)>8192:raise Declined('Mapping pages budget')
            for page,permission in self.pages.items():self.machine.mem_map(page,PAGE,permission)
            for segment in elf.iter_segments():
                if segment['p_type']=='PT_LOAD':self.machine.mem_write(segment['p_vaddr'],segment.data())
        self.machine.mem_map(ARENA,ARENA_SIZE,uc.UC_PROT_READ|uc.UC_PROT_WRITE)
        self.machine.mem_map(STACK,0x20000,uc.UC_PROT_READ|uc.UC_PROT_WRITE)
        self.machine.mem_map(TRAPS,0x10000,uc.UC_PROT_READ|uc.UC_PROT_EXEC)
        self.machine.mem_map(STOP,PAGE,uc.UC_PROT_READ|uc.UC_PROT_EXEC)
        for base,size,permission in ((ARENA,ARENA_SIZE,uc.UC_PROT_READ|uc.UC_PROT_WRITE),
                                    (STACK,0x20000,uc.UC_PROT_READ|uc.UC_PROT_WRITE),
                                    (TRAPS,0x10000,uc.UC_PROT_READ|uc.UC_PROT_EXEC),
                                    (STOP,PAGE,uc.UC_PROT_READ|uc.UC_PROT_EXEC)):
            for page in range(base,base+size,PAGE):self.pages[page]=permission
        for n,(slot,name) in enumerate(import_slots(Path(path)).items()):
            if n>=2048:raise Declined('Import slots budget')
            address=TRAPS+16*n;self.models[address]=name
            self.machine.mem_write(address,self.trapcode)
            self.machine.mem_write(slot,address.to_bytes(self.width,self.endian))
        self.machine.hook_add(uc.UC_HOOK_CODE,self.trap,begin=TRAPS,end=TRAPS+0xffff)
        self.machine.hook_add(uc.UC_HOOK_INTR,self.interrupt)
        # x86 syscall/sysenter may not raise an interrupt in every Unicorn
        # backend. Explicit instruction hooks stop them before any effect.
        if domain=='x86_64':
            from unicorn.x86_const import UC_X86_INS_SYSCALL,UC_X86_INS_SYSENTER
            for instruction in (UC_X86_INS_SYSCALL,UC_X86_INS_SYSENTER):
                self.machine.hook_add(uc.UC_HOOK_INSN,self.syscall,None,1,0,instruction)
        self.clean=self.machine.context_save()
        self.initial_writable=[(a,bytes(self.machine.mem_read(a,len(raw)))) for a,raw in self.writable]

    def interrupt(self,machine,*args):self.fault='target interrupt';machine.emu_stop()
    def syscall(self,machine,*args):self.fault='target syscall';machine.emu_stop()

    def checked_read(self,address,length):
        self.check_memory(address,length,self.ucmod.UC_PROT_READ)
        return bytes(self.machine.mem_read(address,length))

    def checked_write(self,address,raw):
        self.check_memory(address,len(raw),self.ucmod.UC_PROT_WRITE)
        self.machine.mem_write(address,raw)

    def check_memory(self,address,length,permission):
        if not 0<=length<=0x10000 or address<0 or address+length>=1<<(8*self.width):
            raise Declined('Modeled memory range budget')
        if length and any(not self.pages.get(page,0)&permission
                          for page in range(address&-PAGE,(address+length+PAGE-1)&-PAGE,PAGE)):
            raise Declined('Modeled memory permission fault')

    def trap(self,machine,address,size,user):
        name=self.models.get(address);args=[machine.reg_read(r) for r in self.args]
        if name is None and self.domain in {'mipsel','mips_be'} and address-4 in self.models:return
        if name is None:self.fault='unbound import';machine.emu_stop();return
        self.model_calls.append(name)
        if len(self.model_calls)>1024:self.fault='import budget';machine.emu_stop();return
        try:
            if name in {'memcpy','memmove','__memcpy','__memmove'}:
                if args[2]>0x10000:raise Declined('Copy budget')
                self.checked_write(args[0],self.checked_read(args[1],args[2]));value=args[0]
            elif name in {'memset','__memset','explicit_bzero','_Z5cleanPvm','_Z5cleanPvj'}:
                clear=name in {'explicit_bzero','_Z5cleanPvm','_Z5cleanPvj'}
                length=args[1] if clear else args[2]
                if length>0x10000:raise Declined('Set budget')
                self.checked_write(args[0],bytes([0 if clear else args[1]&255])*length);value=args[0]
            elif name in {'_ZN13BigNumberUtil8unpackLEEPjmPKhm','_ZN13BigNumberUtil8unpackLEEPjjPKhj',
                          '_ZN13BigNumberUtil6packLEEPhmPKjm','_ZN13BigNumberUtil6packLEEPhjPKjj'}:
                # The declaration binds uint32_t limbs, count, bytes, length.
                # No class/function-name substring is accepted as a model.
                if args[1]>64 or args[3]>64:raise Declined('Encoding budget')
                if 'unpackLE' in name:
                    raw=self.checked_read(args[2],args[3]);raw=raw.ljust(4*args[1],b'\0')[:4*args[1]]
                    if self.endian=='big':raw=b''.join(raw[i:i+4][::-1] for i in range(0,len(raw),4))
                else:
                    raw=self.checked_read(args[2],4*args[3])
                    if self.endian=='big':raw=b''.join(raw[i:i+4][::-1] for i in range(0,len(raw),4))
                    raw=raw.ljust(args[1],b'\0')[:args[1]]
                self.checked_write(args[0],raw);value=0
            else:raise Declined('Unmodeled import: '+name)
            machine.reg_write(self.ret,value)
        except Exception as exc:self.fault=str(exc);machine.emu_stop()

    def reset(self):
        # A CPU context restore is not a full backend reset after an aborted
        # translation/memory access. In particular, reusing that MIPS backend
        # can crash on a later, otherwise valid function. Discard its private
        # machine and mappings before the next independent candidate.
        if self.poisoned:self.__init__(self.path,self.domain)
        self.machine.context_restore(self.clean)
        for address,raw in self.initial_writable:self.machine.mem_write(address,raw)
        self.machine.mem_write(ARENA,bytes(ARENA_SIZE));self.machine.mem_write(STACK,bytes(0x20000))

    def invoke(self,address,args,*,instructions=200000,milliseconds=40):
        if self.poisoned:raise Declined('Previous emulation fault requires a fresh candidate reset')
        self.fault=None;self.model_calls=[]
        for reg in self.zero_regs:self.machine.reg_write(reg,0)
        sp=STACK+0x1f000
        if self.lr is None:
            sp-=8;self.machine.mem_write(sp,STOP.to_bytes(8,'little'))
        else:self.machine.reg_write(self.lr,STOP)
        self.machine.reg_write(self.sp,sp)
        for reg,value in zip(self.args,args):self.machine.reg_write(reg,value)
        if len(args)>len(self.args):
            delta=16 if self.domain.startswith('mips') else 0
            for n,value in enumerate(args[len(self.args):]):self.machine.mem_write(sp+delta+n*self.width,value.to_bytes(self.width,self.endian))
        if self.domain in {'mipsel','mips_be'}:self.machine.reg_write(self.t9,address)
        entry=address|1 if self.domain=='thumb' else address
        try:self.machine.emu_start(entry,STOP,timeout=milliseconds*1000,count=instructions)
        except self.ucmod.UcError as exc:
            self.poisoned=True
            raise Declined(str(exc)) from exc
        if self.fault or self.machine.reg_read(self.pc)!=STOP:
            self.poisoned=True
            raise Declined(self.fault or 'Instruction/time budget or no return')
        return self.machine.reg_read(self.ret)


def candidate_functions(path,regions,domain):
    from .pointer_paths import unwind_ranges,mips_pic_ranges
    from .guomi.binary_semantics import decode,disassembler
    ranges=unwind_ranges(path)
    operations=[i for base,_,raw,flags in regions if flags&1 for i in decode(disassembler(domain),raw,base) if i.id]
    if domain in {'mipsel','mips_be'}:
        from elftools.elf.elffile import ELFFile
        with Path(path).open('rb') as stream:
            elf=ELFFile(stream);gp=next(((t.entry.d_val+0x7ff0)&0xffffffff for s in elf.iter_segments()
                 if s['p_type']=='PT_DYNAMIC' for t in s.iter_tags() if t.entry.d_tag=='DT_PLTGOT'),None)
        ranges+=mips_pic_ranges(operations,regions,gp)
        # Leaf PIC functions can inherit GP and have no GP prologue. Actual
        # call destinations and the ELF local GOT provide numeric entries.
        # They select probes only, never establish an algorithm.
        starts={a for a,_ in ranges}
        starts.update(base for base,_,raw,flags in regions if flags&1 and raw)
        starts.update(i.operands[-1].imm for i in operations if i.mnemonic in {'jal','bal'}
                      and i.operands and i.operands[-1].type==2)
        for n,ins in enumerate(operations):
            if ins.mnemonic=='jr' and ins.op_str=='$ra':
                following=next((i for i in operations[n+2:n+10] if i.mnemonic!='nop'),None)
                if following is not None:starts.add(following.address)
            if (ins.mnemonic=='addiu' and len(ins.operands)==3 and
                all(o.type==1 and ins.reg_name(o.reg)=='sp' for o in ins.operands[:2]) and
                ins.operands[2].type==2 and -65536<=ins.operands[2].imm<=-8 and not ins.operands[2].imm%8):
                starts.add(ins.address)
        with Path(path).open('rb') as stream:
            elf=ELFFile(stream)
            tags={t.entry.d_tag:t.entry.d_val for s in elf.iter_segments() if s['p_type']=='PT_DYNAMIC' for t in s.iter_tags()}
            got=tags.get('DT_PLTGOT');count=tags.get('DT_MIPS_LOCAL_GOTNO',0)
            if got is not None and 0<count<=16384:
                from .function_signatures import read_virtual
                raw=read_virtual(regions,got,count*4)
                if raw is not None:
                    endian='little' if domain=='mipsel' else 'big'
                    starts.update(int.from_bytes(raw[n:n+4],endian) for n in range(0,len(raw)-3,4))
        code=[(base,base+len(raw)) for base,_,raw,flags in regions if flags&1]
        starts=sorted(a for a in starts if not a%4 and any(lo<=a<hi for lo,hi in code))
        ranges += [(a,min(next((b for b in starts if b>a),a+32768),
                              next(hi for lo,hi in code if lo<=a<hi))-a) for a in starts]
    # Fully unrolled O0 compression functions can exceed 32 KiB. Their real
    # unwind/PIC entries remain candidates; emulation retains independent
    # instruction/time limits rather than discarding those large functions.
    starts=sorted({a for a,size in ranges if 64<=size<=512*1024})
    # Candidates come from unwind/ABI/control structure only. Spellings, sample IDs,
    # debug information, hashes and project paths are never read.
    return starts[:512],operations


def probe_curve(machine,functions,deadline):
    vectors=curve_vectors();result=[]
    for address in functions:
        if time.monotonic()>deadline:break
        try:
            for scalar,point,expected in vectors:
                machine.reset();machine.machine.mem_write(ARENA+0x1000,scalar);machine.machine.mem_write(ARENA+0x2000,point)
                machine.invoke(address,[ARENA,ARENA+0x1000,ARENA+0x2000],instructions=100000000,milliseconds=2500)
                if bytes(machine.machine.mem_read(ARENA,32))!=expected:raise Declined('Curve output mismatch')
            result.append({'algorithm':'ECDH','address':address,'vectors':3,
                'relation':'Three distinct clamped scalar/input-coordinate evaluations match the complete RFC 7748 Montgomery ladder and serialized affine result',
                'modeled_imports':sorted(set(machine.model_calls))});break
        except Declined:continue
    return result


def probe_block(machine,functions,algorithm,deadline):
    vectors=[tuple(bytes.fromhex(x) for x in row) for row in BLOCK_VECTORS[algorithm]]
    result=[];keylen=len(vectors[0][0]);state=ARENA+0x4000;keybuf=ARENA+0x1000;block=ARENA+0x2000
    for setup in functions:
        if time.monotonic()>deadline:break
        key,plain,expected=vectors[0]
        try:
            machine.reset();machine.machine.mem_write(keybuf,key)
            machine.invoke(setup,[state,keybuf,keylen],instructions=3000000,milliseconds=160)
            saved=bytes(machine.machine.mem_read(ARENA,ARENA_SIZE))
            globals_=[(a,bytes(machine.machine.mem_read(a,len(raw)))) for a,raw in machine.initial_writable]
            if not any(saved[0x4000:0xc000]):continue
            if bytes(machine.machine.mem_read(keybuf,keylen))!=key:continue
            # A table initializer independent of the key is not a key setup.
            # Screen it before trying consumers, including compiler support
            # functions with incompatible signatures.
            machine.reset();machine.machine.mem_write(keybuf,vectors[1][0])
            machine.invoke(setup,[state,keybuf,keylen],instructions=3000000,milliseconds=160)
            second=bytes(machine.machine.mem_read(state,0x8000))
            if second==saved[0x4000:0xc000]:continue
        except Declined:continue
        for cipher in functions:
            if cipher==setup or time.monotonic()>deadline:continue
            try:
                machine.reset()
                machine.machine.mem_write(ARENA,saved)
                for a,raw in globals_:machine.machine.mem_write(a,raw)
                machine.machine.mem_write(block,plain)
                machine.invoke(cipher,[state,block],instructions=200000,milliseconds=40)
                encoding='standard'
                if bytes(machine.machine.mem_read(block,len(plain)))!=expected:
                    if algorithm!='DES':continue
                    machine.reset();machine.machine.mem_write(ARENA,saved)
                    for a,raw in globals_:machine.machine.mem_write(a,raw)
                    machine.machine.mem_write(block,des_boundary(plain))
                    machine.invoke(cipher,[state,block],instructions=200000,milliseconds=40)
                    if bytes(machine.machine.mem_read(block,len(plain)))!=des_boundary(expected):continue
                    encoding='IP-boundary-word-byteswap'
                for key,plain,expected in vectors[1:]:
                    if encoding!='standard':plain,expected=des_boundary(plain),des_boundary(expected)
                    machine.reset();machine.machine.mem_write(keybuf,key);machine.machine.mem_write(block,plain)
                    machine.invoke(setup,[state,keybuf,keylen],instructions=3000000,milliseconds=160)
                    machine.invoke(cipher,[state,block],instructions=200000,milliseconds=40)
                    if bytes(machine.machine.mem_read(block,len(plain)))!=expected:raise Declined('Independent block/key mismatch')
                result.append({'algorithm':algorithm,'address':cipher,'setup_address':setup,'vectors':3,'boundary_encoding':encoding,
                    'relation':'Key setup and in-place block transformation match three distinct standard key/plaintext/ciphertext vectors under the explicit '+encoding+' encoding',
                    'modeled_imports':sorted(set(machine.model_calls))});return result
            except Declined:continue
    return result


def rc4_stream(key,plain):
    """Independent byte-oriented RC4 reference for finite stream probes."""
    state=list(range(256));j=0
    for i in range(256):
        j=(j+state[i]+key[i%len(key)])&255;state[i],state[j]=state[j],state[i]
    i=j=0;out=bytearray()
    for byte in plain:
        i=(i+1)&255;j=(j+state[i])&255;state[i],state[j]=state[j],state[i]
        out.append(byte^state[(state[i]+state[j])&255])
    return bytes(out)


def probe_stream(machine,functions,deadline):
    vectors=[(bytes(range(1,n+1)),hashlib.sha256(('qcs-stream-'+str(n)).encode()).digest()) for n in (5,8,16)]
    state,keybuf,block=ARENA+0x4000,ARENA+0x1000,ARENA+0x2000
    for setup in functions:
        if time.monotonic()>deadline:break
        try:
            key,plain=vectors[0];machine.reset();machine.machine.mem_write(keybuf,key)
            machine.invoke(setup,[state,keybuf,len(key),0,0],instructions=1000000,milliseconds=100)
            saved=bytes(machine.machine.mem_read(ARENA,ARENA_SIZE))
            context=saved[0x4000:0xc000]
            # A real KSA must produce a permutation. Identity/unrelated byte
            # buffers cannot justify trying a consumer as a stream cipher.
            permutation=any(sorted(context[n:n+256])==list(range(256)) and context[n:n+256]!=bytes(range(256))
                            for n in range(0,min(1024,len(context)-255),4))
            if not permutation or bytes(machine.machine.mem_read(keybuf,len(key)))!=key:continue
            globals_=[(a,bytes(machine.machine.mem_read(a,len(raw)))) for a,raw in machine.initial_writable]
        except Declined:continue
        for cipher in functions:
            if time.monotonic()>deadline:break
            if cipher==setup:continue
            try:
                machine.reset()
                machine.machine.mem_write(ARENA,saved)
                for a,raw in globals_:machine.machine.mem_write(a,raw)
                machine.machine.mem_write(block,plain)
                machine.invoke(cipher,[state,block,len(plain)],instructions=500000,milliseconds=50)
                if bytes(machine.machine.mem_read(block,len(plain)))!=rc4_stream(key,plain):continue
                for key,plain in vectors[1:]:
                    machine.reset();machine.machine.mem_write(keybuf,key);machine.machine.mem_write(block,plain)
                    machine.invoke(setup,[state,keybuf,len(key),0,0],instructions=1000000,milliseconds=100)
                    # Two consecutive calls must retain exactly the PRGA's
                    # state, rather than resetting to the first output block.
                    machine.invoke(cipher,[state,block,13],instructions=500000,milliseconds=50)
                    machine.invoke(cipher,[state,block+13,len(plain)-13],instructions=500000,milliseconds=50)
                    if bytes(machine.machine.mem_read(block,len(plain)))!=rc4_stream(key,plain):raise Declined('Stream/key/continuation mismatch')
                return [{'algorithm':'RC4','address':cipher,'setup_address':setup,'vectors':3,
                         'relation':'Key scheduling and byte stream match three independent RC4 keys/plaintexts, including consecutive stateful calls',
                         'modeled_imports':sorted(set(machine.model_calls))}]
            except Declined:continue
    return []


def analyze(path,regions,domain,deadline,*,algorithms):
    machine=Machine(path,domain);functions,operations=candidate_functions(path,regions,domain)
    matches=[]
    if 'ECDH' in algorithms:matches+=probe_curve(machine,functions,deadline)
    from .compression_probes import probe
    for algorithm in ('SM3','SHA-1'):
        if algorithm in algorithms:matches+=probe(machine,functions,algorithm,deadline)
    for algorithm in ('AES','DES'):
        if algorithm in algorithms:matches+=probe_block(machine,functions,algorithm,deadline)
    if 'RC4' in algorithms:matches+=probe_stream(machine,functions,deadline)
    return matches


def scan_probes(path,report,timeout):
    # Preparation is part of the caller's remaining time, too. The earlier
    # engines may legitimately use almost all of a scan's global budget.
    # Do not parse/decode the ELF again when no optional budget remains.
    deadline=time.monotonic()+max(0,min(timeout-.75,12))
    def unavailable(algorithms=()):
        report['engine_status']['semantic_probes']={'status':'budget_unavailable',
            'method':'bounded private-memory concrete semantics','candidate_algorithms':sorted(algorithms),
            'matches':[],'reason':'No optional search time remains, including ELF preparation'}
    # ELF/table preparation and isolated-worker startup need a useful budget;
    # declining early is preferable to spending the remaining time decoding
    # an input when no full multi-vector experiment could then finish.
    if timeout<3:
        unavailable()
        return
    from .function_signatures import function_regions
    from .operation_tables import locate
    from .guomi.binary_bignum import import_slots
    regions,domains=function_regions(path);found={f['algorithm'] for f in report['findings']}
    slots=set(import_slots(Path(path)).values());tables=locate(regions)
    # Cheap semantic candidates select budgets only; a candidate never emits
    # a classification. Large binaries retain the other analysis engines.
    algorithms=set()
    candidates={a for c in report.get('clues',[]) for a in c.get('candidate_algorithms',[])}
    algorithms.update(candidates&{'SM3','SHA-1'})
    sm3_constants=(0x79cc4519,0x7a879d8a)
    if all(any(isinstance(raw,bytes) and
           (value.to_bytes(4,'little') in raw or value.to_bytes(4,'big') in raw)
           for _,_,raw,_ in regions) for value in sm3_constants):algorithms.add('SM3')
    if any(n.startswith('_ZN13BigNumberUtil8unpackLE') for n in slots):algorithms.add('ECDH')
    if any(t['kind'] in {'des_s','des_sp'} for t in tables):algorithms.add('DES')
    codebytes=sum(len(raw) for _,_,raw,flags in regions if flags&1)
    if time.monotonic()>=deadline:
        unavailable(algorithms);return
    if codebytes<512*1024 and not {'AES','ECDH','RC4'}<=found:
        from .guomi.binary_semantics import decode,disassembler
        constants=set()
        for domain in domains:
            dis=disassembler(domain)
            if dis is None:continue
            for base,_,raw,flags in regions:
                if not flags&1:continue
                for index,ins in enumerate(decode(dis,raw,base)):
                    if index%256==0 and time.monotonic()>=deadline:
                        unavailable(algorithms);return
                    if ins.id:
                        constants.update(o.imm&0xffffffff for o in ins.operands if o.type==2)
        if {0x1b,0x63}<=constants or any(t['kind'] in {'aes_sbox','aes_t'} for t in tables):algorithms.add('AES')
        if set(sm3_constants)<=constants or {0x4519,0x79cc,0x9d8a,0x7a87}<=constants:algorithms.add('SM3')
        if constants&{121665,121666} or (constants&{0xdb41,0xdb42} and 1 in constants):algorithms.add('ECDH')
        if {255,256}<=constants and codebytes<256*1024:algorithms.add('RC4')
    algorithms-=found
    status={'method':'bounded private-memory concrete semantics','target_native_execution':False,
            'target_system_calls':False,'candidate_algorithms':sorted(algorithms),'matches':[],
            'limitations':['Finite probes do not prove equivalence for all inputs',
                          'ELF ABI: out/scalar/point; context/key/length and context/block[/length]',
                          'Candidate and time budgets; unmodeled imports decline the probe']}
    report['engine_status']['semantic_probes']=status
    if not algorithms:status['status']='not_applicable';return
    if time.monotonic()>=deadline:status['status']='budget_unavailable';return
    failed=False;budget_declined=False
    # A later incompatible candidate must not discard an already validated
    # algorithm. Every algorithm/ABI has its own isolated worker and result.
    for algorithm,cap in (('ECDH',12),('SM3',8),('SHA-1',8),('AES',5),('DES',5),('RC4',4)):
        if algorithm not in algorithms:continue
        for domain in domains:
            if domain not in {'x86_64','aarch64','arm','thumb','mipsel','mips_be'}:continue
            if time.monotonic()>deadline:break
            # Unicorn is native code. Keep backend faults and process limits out
            # of the scanner process; a failed child supplies no positive witness.
            import json,os,sys
            from .process import bounded_run
            remaining=max(.01,min(cap,deadline-time.monotonic()))
            environment=dict(os.environ)
            environment['PYTHONPATH']=os.pathsep.join(str(p) for p in sys.path if p)
            child=bounded_run([sys.executable,'-m','qcs.semantic_probes','--worker',str(Path(path).resolve()),domain,
                               algorithm,str(remaining)],timeout=remaining+.5,env=environment)
            if child['limit']=='timeout':
                # A configured optional search limit is an abstention, like
                # an individual instruction-count limit. It supplies no
                # witness and stays explicit in the engine report. A native
                # backend crash remains a scanner partial, below.
                budget_declined=True
                status.setdefault('budget_declined',[]).append({'architecture':domain,'algorithm':algorithm,
                    'limit':'timeout','reason':'Configured optional probe budget exhausted; no witness accepted'})
                continue
            if child['returncode'] or child['limit']:
                failed=True
                status.setdefault('declined',[]).append({'architecture':domain,'worker_returncode':child['returncode'],
                    'limit':child['limit'],'reason':'Isolated backend failed; no witness accepted'})
                continue
            try:matches=json.loads(child['output'])
            except ValueError:
                failed=True;status.setdefault('declined',[]).append('Invalid worker result');continue
            for match in matches:
                status['matches'].append(dict(match,architecture=domain));algorithms.discard(match['algorithm'])
                address=match['address']
                report['findings'].append(evidence(match['algorithm'],'semantic_probes','binary_instruction',
                    'bounded_behavioral_witness',confidence='medium',confidence_reason=match['relation'],
                    architecture=domain,virtual_address=address,offset=next((off+address-base for base,off,raw,flags in regions if flags&1 and base<=address<base+len(raw)),None),
                    implementation_verification='finite_standard_vector_emulation',behavioral_witness=match,
                    limitations=status['limitations']))
            if algorithm not in algorithms:break
    status['status']='backend_declined' if failed else 'budget_exhausted' if budget_declined or time.monotonic()>deadline else 'completed'
    if budget_declined:
        report['coverage_notes'].append('Optional finite-emulation search reached its configured budget and abstained. No result from that worker was accepted; this is not evidence of algorithm absence.')
    if failed:
        if report['scan_status']=='completed':report['scan_status']='partial'
        report['coverage_notes'].append('An isolated instruction-emulation worker failed; no result from that worker was accepted. Other engine findings are retained.')


if __name__=='__main__':
    import json,resource,sys
    if len(sys.argv)!=6 or sys.argv[1]!='--worker':raise SystemExit('Internal isolated probe worker')
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_AS,(1024*1024*1024,1024*1024*1024))
    resource.setrlimit(resource.RLIMIT_CPU,(20,20))
    from .function_signatures import function_regions
    path=Path(sys.argv[2]);regions,_=function_regions(path)
    try:result=analyze(path,regions,sys.argv[3],time.monotonic()+min(12,float(sys.argv[5])),algorithms=set(sys.argv[4].split(',')))
    except Declined:result=[]
    print(json.dumps(result,separators=(',',':')))
