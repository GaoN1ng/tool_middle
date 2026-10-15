"""SM2 arithmetic-call equations in ELF with generic imported math operations.

Relocation-backed imports or complete development primitive/callee matches
supply semantics. Unrecognised static functions are never guessed from names. Pointer lifting
is bounded to x86-64 SysV, AArch64 and ARM AAPCS and follows recorded successful-operation
order; it is not execution or a full CFG feasibility proof.
"""
from .bignum import Equations, OPERATIONS
from ..operation_bignum import ConventionalEquations,EXPONENTS,CURVE_MUL
import re

TRUSTED=set(OPERATIONS)|{'EC_POINT_mul','EC_POINT_get_affine_coordinates',
    'EC_POINT_get_affine_coordinates_GFp','BN_value_one','ossl_ec_group_do_inverse_ord',
    'bn_to_mont_fixed_top','BN_to_montgomery','bn_mul_mont_fixed_top','BN_mod_mul_montgomery',
    'EC_GROUP_get0_order','EC_GROUP_get_mont_data'}
TRUSTED.update(EXPONENTS)
TRUSTED.update(CURVE_MUL)
TRUSTED.update({'BN_bn2bin','BN_bn2binpad','mbedtls_mpi_write_binary'})
TRUSTED.update({'nn_inc','nn_export_to_buf','fp_export_to_buf','prj_pt_unique',
                'prj_pt_import_from_buf','prj_pt_import_from_aff_buf',
                'ec_pub_key_import_from_aff_buf','_prj_pt_unprotected_mult'})
from ..curve_ladder import FIELD_APIS
TRUSTED.update(FIELD_APIS)
from ..curve_exchange import APIS as EXCHANGE_APIS
TRUSTED.update(EXCHANGE_APIS)


def import_slots(path):
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection
    slots={}
    with path.open('rb') as f:
        if f.read(4)!=b'\x7fELF':return slots
        f.seek(0);elf=ELFFile(f)
        for section in elf.iter_sections():
            if not isinstance(section,RelocationSection):continue
            syms=elf.get_section(section['sh_link'])
            for reloc in section.iter_relocations():
                index=reloc['r_info_sym']
                if not index:continue
                sym=syms.get_symbol(index)
                if sym['st_shndx']=='SHN_UNDEF':slots[reloc['r_offset']]=sym.name
        if elf['e_machine']=='EM_MIPS':
            # The MIPS ABI describes global GOT slots through dynamic tags,
            # without one relocation per imported symbol. Bind only the
            # indexed, undefined dynamic symbol in that actual GOT layout.
            tags={tag.entry.d_tag:tag.entry.d_val
                  for segment in elf.iter_segments() if segment['p_type']=='PT_DYNAMIC'
                  for tag in segment.iter_tags()}
            required={'DT_PLTGOT','DT_MIPS_LOCAL_GOTNO','DT_MIPS_GOTSYM','DT_SYMTAB'}
            if required<=tags.keys():
                symbols=next((s for s in elf.iter_sections()
                              if s['sh_type']=='SHT_DYNSYM' and s['sh_addr']==tags['DT_SYMTAB']),None)
                first=tags['DT_MIPS_GOTSYM'];local=tags['DT_MIPS_LOCAL_GOTNO']
                if symbols is not None and 0<=first<=symbols.num_symbols() and local<=1_000_000:
                    width=elf.elfclass//8
                    for i in range(first,symbols.num_symbols()):
                        sym=symbols.get_symbol(i)
                        address=tags['DT_PLTGOT']+(local+i-first)*width
                        allocated=any(seg['p_type']=='PT_LOAD' and
                                      seg['p_vaddr']<=address and address+width<=seg['p_vaddr']+seg['p_filesz']
                                      for seg in elf.iter_segments())
                        if allocated and sym.name and sym['st_shndx']=='SHN_UNDEF':
                            slots.setdefault(address,sym.name)
    return slots


class PointerLift:
    def __init__(self,domain,regions,slots,static_targets=None, *, mips_gp=None):
        from .binary_semantics import Lift
        self.domain,self.regions,self.slots=domain,regions,slots
        self.keys=Lift(domain,[],regions)
        self.regs={};self.memory={};self.equations=ConventionalEquations(pointer_size=8 if domain in {'x86_64','aarch64'} else 4);self.matches=[]
        self.frame=0;self.calls=0
        self.target_cache={}
        self.static_targets=static_targets or {}
        self.mips_gp=mips_gp;self.lui_sites={}
        self.coordinate_words={};self.high_bit_words={};self.xhat_buffers={}
        self.seed_arguments()

    def seed_arguments(self):
        registers=(['rdi','rsi','rdx','rcx','r8','r9'] if self.domain=='x86_64' else
                   ['a'+str(i) for i in range(4)] if self.domain in {'mipsel','mips_be'} else
                   ['r'+str(i) for i in range(4)] if self.domain in {'arm','thumb'} else
                   ['x'+str(i) for i in range(8)])
        self.regs.update({r:'input:'+str(self.frame)+':'+r for r in registers})

    def key(self,ins,reg):return self.keys.key(ins,reg)
    def reg(self,ins,reg):
        key=self.key(ins,reg)
        if key in {'xzr','wzr','zero'}:return '0'
        if key not in self.regs:self.regs[key]=('stack:'+str(self.frame)+'[0]' if key=='sp' else 'input:'+str(self.frame)+':'+key)
        return self.regs[key]
    def address(self,ins,op):
        mem=op.mem
        if mem.base and ins.reg_name(mem.base)=='rip':return ins.address+ins.size+mem.disp
        if not mem.base:return mem.disp
        base=self.reg(ins,mem.base)
        if getattr(mem,'index',0):return None
        if base.isdigit():return int(base)+mem.disp
        return self.offset(base,mem.disp)
    @staticmethod
    def offset(base,delta):
        if str(base).lstrip('-').isdigit():return int(base)+delta
        match=re.fullmatch(r'(.*)\[(-?\d+)\]',str(base))
        if match:base,old=match.groups();delta+=int(old)
        return str(base)+'['+str(delta)+']'
    def value(self,ins,op):
        if op.type==1:return self.reg(ins,op.reg)
        if op.type==2:return str(op.imm)
        if op.type==3:
            address=self.address(ins,op)
            if address is None:return 'unknown@'+str(ins.address)
            return self.memory.get(address,'load:'+str(address))
        return 'unknown@'+str(ins.address)
    def write(self,ins,op,value):
        if op.type==1:self.regs[self.key(ins,op.reg)]=value
        elif op.type==3:
            address=self.address(ins,op)
            if address is not None:
                self.store(address,value,ins.address)
                if value=='0' and getattr(op,'size',0)==16:
                    self.store(self.offset(address,8),'0',ins.address)

    def store(self,address,value,site):
        self.memory[address]=value
        width=8 if self.domain in {'x86_64','aarch64'} else 4
        words=32//width;half=words//2
        high=2 if self.domain=='mips_be' else half-1
        coordinate=self.coordinate_words.get(value)
        if coordinate and coordinate[1]==0:self.xhat_buffers[address]=coordinate[0]
        for buffer,point in list(self.xhat_buffers.items()):
            values=[self.memory.get(self.offset(buffer,width*j)) for j in range(words)]
            valid=(all(self.coordinate_words.get(values[j])==(point,j) for j in range(half) if j!=high) and
                   self.high_bit_words.get(values[high])==(point,high) and
                   all(v=='0' for v in values[half:]))
            if not valid and str(address) in {str(self.offset(buffer,width*j)) for j in range(words)}:
                self.equations.exchange.xhats.pop(buffer,None)
                self.equations.exchange.scalars.pop(buffer,None)
            if valid:
                self.equations.exchange.xhat(buffer,point,site,
                    'Actual low 128 affine-x bits, bit 127 set, complete upper 128 zero stores')

    def target(self,ins):
        from .binary_semantics import disassembler,decode
        ops=ins.operands
        if self.domain in {'mipsel','mips_be'} and ins.mnemonic in {'jalr','jr'} and ops and ops[-1].type==1:
            value=self.reg(ins,ops[-1].reg)
            return value.removeprefix('import:') if value.startswith('import:') else None
        if len(ops)!=1:return None
        if ops[0].type==3:return self.slots.get(self.address(ins,ops[0]))
        if ops[0].type!=2:return None
        dest=ops[0].imm
        if dest in self.static_targets:return self.static_targets[dest]
        if self.domain=='thumb' and ins.mnemonic.split('.')[0]=='b':
            dest=self.thumb_veneer(dest)
            if dest is None:return None
        if (dest,self.domain) in self.target_cache:return self.target_cache[dest,self.domain]
        result=self.resolve_stub(dest)
        self.target_cache[dest,self.domain]=result
        return result

    def thumb_veneer(self,dest):
        """Resolve a small interworking tail veneer, no arbitrary function."""
        from .binary_semantics import disassembler,decode
        raw=next((data[dest-base:dest-base+24] for base,_,data,flags in self.regions if flags&1 and base<=dest<base+len(data)),None)
        if not raw:return None
        regs={}
        for n,op in enumerate(decode(disassembler('thumb'),raw,dest)):
            if n>=5 or not op.id:return None
            o=op.operands;m=op.mnemonic.split('.')[0]
            if m in {'movw','movt'} and len(o)==2 and o[1].type==2:
                k=op.reg_name(o[0].reg)
                if m=='movt' and k not in regs:return None
                regs[k]=o[1].imm if m=='movw' else (regs[k]&65535)|(o[1].imm<<16)
            elif m=='add' and len(o)==2 and o[1].type==1 and op.reg_name(o[1].reg)=='pc':
                k=op.reg_name(o[0].reg)
                if k not in regs:return None
                regs[k]+=op.address+4
            elif m=='bx' and len(o)==1:return regs.get(op.reg_name(o[0].reg))
            else:return None
        return None

    def resolve_stub(self,dest):
        from .binary_semantics import disassembler,decode
        raw=next((data[dest-base:dest-base+32] for base,_,data,flags in self.regions
                  if flags&1 and base<=dest<base+len(data)),None)
        if not raw:return None
        # PLT stubs only. The resolved import must have an undefined relocation.
        regs={}
        # Thumb BLX calls ARM-mode ELF PLT entries. Decode that interworking
        # target with ARM, never infer the API from the target's own symbols.
        stub_domain='arm' if self.domain in {'arm','thumb'} else self.domain
        for n,op in enumerate(decode(disassembler(stub_domain),raw,dest)):
            if n>5 or not op.id:break
            if self.domain=='x86_64' and op.mnemonic=='jmp' and op.operands[0].type==3:
                mem=op.operands[0].mem
                if op.reg_name(mem.base)=='rip':return self.slots.get(op.address+op.size+mem.disp)
            if self.domain=='aarch64':
                o=op.operands
                if op.mnemonic=='adrp':regs[op.reg_name(o[0].reg)]=o[1].imm
                elif op.mnemonic=='ldr' and o[1].type==3:
                    base=regs.get(op.reg_name(o[1].mem.base))
                    target=op.reg_name(o[0].reg)
                    if isinstance(base,int):
                        name=self.slots.get(base+o[1].mem.disp)
                        if name:regs[target]=name
                        else:regs.pop(target,None)
                    else:
                        # A previously resolved API name is not an address.
                        # Unknown loads invalidate the destination as well.
                        regs.pop(target,None)
                elif op.mnemonic=='br':
                    name=regs.get(op.reg_name(o[0].reg))
                    return name if isinstance(name,str) else None
            if stub_domain=='arm':
                o=op.operands
                if op.mnemonic=='add' and len(o)>=3 and o[1].type==1 and o[2].type==2:
                    source=op.reg_name(o[1].reg)
                    base=op.address+8 if source=='pc' else regs.get(source)
                    # Capstone represents ARM modified-immediate PLT ADDs
                    # as #imm,#rotation, not the already rotated constant.
                    imm=o[2].imm&0xffffffff
                    if len(o)==4 and o[3].type==2:
                        r=o[3].imm&31;imm=((imm>>r)|(imm<<(32-r)))&0xffffffff if r else imm
                    if isinstance(base,int):regs[op.reg_name(o[0].reg)]=base+imm
                elif op.mnemonic=='ldr' and len(o)==2 and o[1].type==3 and op.reg_name(o[0].reg)=='pc':
                    base=regs.get(op.reg_name(o[1].mem.base))
                    return self.slots.get(base+o[1].mem.disp) if isinstance(base,int) else None
        return None

    def finish(self):
        self.matches.extend(self.equations.matches)
        self.matches.extend(self.equations.general_matches)
        self.equations=ConventionalEquations(pointer_size=8 if self.domain in {'x86_64','aarch64'} else 4);self.regs={};self.memory={};self.frame+=1
        self.seed_arguments()
        self.lui_sites.clear()
        self.coordinate_words.clear();self.high_bit_words.clear();self.xhat_buffers.clear()

    def step(self,ins):
        import capstone as cs
        if not ins.id:return
        ops=ins.operands;m=ins.mnemonic.split('.')[0]
        arm=self.domain in {'arm','thumb'}
        mips=self.domain in {'mipsel','mips_be'}
        if arm and m in {'movs','adds','subs','orrs','ands','bics'}:m=m[:-1]
        if arm and m in {'addw','subw'}:m=m[:-1]
        if ins.group(cs.CS_GRP_RET) or (mips and m=='jr' and ins.op_str=='$ra') or (arm and ((m=='pop' and any(o.type==1 and ins.reg_name(o.reg)=='pc' for o in ops)) or (m=='bx' and ops and ins.reg_name(ops[0].reg)=='lr'))):
            self.finish();return
        tail=((ins.group(cs.CS_GRP_JUMP) and m in {'jmp','b'}) or (mips and m=='jr')) and self.target(ins) in TRUSTED
        if ins.group(cs.CS_GRP_CALL) or (mips and m in {'jal','jalr','bal'}) or tail:
            name=self.target(ins);self.calls+=1
            argsregs=(['rdi','rsi','rdx','rcx','r8','r9'] if self.domain=='x86_64' else ['a'+str(i) for i in range(4)] if mips else ['r'+str(i) for i in range(4)] if arm else ['x'+str(i) for i in range(8)])
            args=[self.regs.get(k,'unknown-argument@'+str(ins.address)+':'+k) for k in argsregs]
            if arm or mips:
                sp=self.regs.get('sp','stack:'+str(self.frame)+'[0]')
                args.extend(self.memory.get(self.offset(sp,i),'load:'+str(self.offset(sp,i))) for i in range(16 if mips else 0,32 if mips else 16,4))
            if name is None and self.domain=='arm' and ops and ops[0].type==2 and args[2].isdigit():
                from ..copy_semantics import arm_copy
                from .binary_semantics import disassembler,decode
                from ..function_signatures import read_virtual
                raw=read_virtual(self.regions,ops[0].imm,256)
                if raw and arm_copy(list(decode(disassembler('arm'),raw,ops[0].imm)),int(args[2])):
                    name='qcs:proven-byte-copy'
            if name and name.startswith('qcs:xhat:'):
                p,q=map(int,name.split(':')[2:])
                self.equations.exchange.xhat(args[q],args[p],ins.address,
                    'Bound local callee: affine-coordinate read and complete 128-bit truncate/set/zero stores')
            else:
                # The unused ABI argument registers are not memory effects.
                # Standard byte-copy/set imports only write their destination;
                # stale r3 must not invalidate an unrelated serialized point.
                effect_args=args[:1] if name in {'memcpy','memmove','memset','__memcpy','__memmove','__memset',
                                                'explicit_bzero','bzero','qcs:proven-byte-copy'} else args
                self.equations.feed(name or 'unknown-local-call',effect_args,ins.address)
            if name=='sm2_z256_point_get_xy':
                width=8 if self.domain in {'x86_64','aarch64'} else 4
                for j in range(32//width):
                    token='affine-x@'+str(ins.address)+':'+str(j)
                    self.coordinate_words[token]=(args[0],j)
                    self.memory[self.offset(args[1],width*j)]=token
            saved=({'rbx','rbp','rsp','r12','r13','r14','r15'} if self.domain=='x86_64' else {'sp','fp',*('s'+str(i) for i in range(8))} if mips else {'sp','fp','sb','sl',*('r'+str(i) for i in range(4,12))} if arm else {'sp','fp',*('x'+str(i) for i in range(19,30))})
            if arm:saved.update({'d'+str(i) for i in range(8,16)}|{'q'+str(i) for i in range(4,8)})
            self.regs={k:v for k,v in self.regs.items() if k in saved}
            ret='rax' if self.domain=='x86_64' else 'v0' if mips else 'r0' if arm else 'x0'
            self.regs[ret]='1' if name=='BN_value_one' else 'result@'+str(ins.address)
            if name=='EC_GROUP_get0_order':self.equations.group_orders[args[0]]=self.regs[ret]
            elif name=='EC_GROUP_get_mont_data':self.equations.mont_groups[self.regs[ret]]=args[0]
            if tail:
                self.finish()
            return
        if mips:
            if m=='or' and len(ops)==3:
                a,b=[self.value(ins,o) for o in ops[1:]]
                for literal,other in ((a,b),(b,a)):
                    if literal in {str(1<<31),str(-(1<<31))} and other in self.coordinate_words:
                        token='high-bit@'+str(ins.address);self.high_bit_words[token]=self.coordinate_words[other]
                        self.write(ins,ops[0],token);return
                self.write(ins,ops[0],a if b=='0' else b if a=='0' else 'unknown@'+str(ins.address));return
            if m=='lui' and len(ops)==2:
                self.write(ins,ops[0],str((ops[1].imm<<16)&0xffffffff))
                self.lui_sites[self.key(ins,ops[0].reg)]=ins.address;return
            if m in {'addiu','addi','ori'} and len(ops)==3 and ops[2].type==2:
                source=self.value(ins,ops[1]);n=ops[2].imm
                value=str((int(source)|n if m=='ori' else int(source)+n)&0xffffffff) if source.lstrip('-').isdigit() else str(self.offset(source,n))
                self.write(ins,ops[0],value)
                source_key=self.key(ins,ops[1].reg);destination=self.key(ins,ops[0].reg)
                if source_key in self.lui_sites:self.lui_sites[destination]=self.lui_sites[source_key]
                return
            if m=='addu' and len(ops)==3:
                a,b=[self.value(ins,o) for o in ops[1:]]
                value=None
                if a.lstrip('-').isdigit() and b.lstrip('-').isdigit():value=str((int(a)+int(b))&0xffffffff)
                elif self.mips_gp is not None:
                    for source,other in ((ops[1],ops[2]),(ops[2],ops[1])):
                        key=self.key(ins,source.reg);site=self.lui_sites.get(key)
                        n=self.value(ins,source)
                        if (self.key(ins,other.reg)=='t9' and site is not None and 0<=ins.address-site<=128
                            and n.isdigit() and (int(n)+site)&0xffffffff==self.mips_gp):value=str(self.mips_gp)
                if value is None:
                    if a.lstrip('-').isdigit():value=str(self.offset(b,int(a)))
                    elif b.lstrip('-').isdigit():value=str(self.offset(a,int(b)))
                self.write(ins,ops[0],value or 'unknown@'+str(ins.address));return
            if m in {'lw','lbu','lhu','sw','sb','sh','move','li'} and len(ops)==2:
                dest,source=(ops[1],ops[0]) if m in {'sw','sb','sh'} else ops
                address=self.address(ins,source) if source.type==3 else None
                name=self.slots.get(address)
                self.write(ins,dest,'import:'+name if name else self.value(ins,source));return
            # Unknown MIPS instructions explicitly clobber their destination.
            # Branches, NOPs and stores have no pointer destination here.
            if m not in {'nop','j','b','beq','bne','beqz','bnez','bgtz','bgez','bltz','blez','break','sb','sh'} and ops and ops[0].type==1:
                self.write(ins,ops[0],'unknown@'+str(ins.address));return
        if arm and m=='push':
            sp=self.regs.get('sp','stack:'+str(self.frame)+'[0]');new=self.offset(sp,-4*len(ops))
            for i,o in enumerate(ops):self.memory[self.offset(new,4*i)]=self.value(ins,o)
            self.regs['sp']=str(new);return
        if arm and m=='pop':
            sp=self.regs.get('sp','stack:'+str(self.frame)+'[0]')
            for i,o in enumerate(ops):self.write(ins,o,self.memory.get(self.offset(sp,4*i),'load:'+str(self.offset(sp,4*i))))
            self.regs['sp']=str(self.offset(sp,4*len(ops)));return
        if arm and m=='vmov' and len(ops)==2 and ops[0].type==1 and ops[1].type==2 and ops[1].imm==0:
            register=ins.reg_name(ops[0].reg);self.write(ins,ops[0],'0')
            if register.startswith('q'):
                n=int(register[1:]);self.regs['d'+str(2*n)]='0';self.regs['d'+str(2*n+1)]='0'
            return
        if arm and m=='vst1' and ops and ops[-1].type==3:
            mem=ops[-1].mem;address=self.reg(ins,mem.base)
            for n,op in enumerate(ops[:-1]):
                value=self.value(ins,op)
                self.store(self.offset(address,8*n),value,ins.address)
                self.store(self.offset(address,8*n+4),value if value=='0' else 'unknown@'+str(ins.address),ins.address)
            return
        if arm and m in {'stm','stmia','ldm','ldmia'} and len(ops)>1 and ops[0].type==1:
            base=self.value(ins,ops[0]);values=[self.value(ins,o) for o in ops[1:]]
            for i,o in enumerate(ops[1:]):
                address=self.offset(base,4*i)
                if m.startswith('stm'):self.store(address,values[i],ins.address)
                else:self.write(ins,o,self.memory.get(address,'load:'+str(address)))
            if ins.writeback:self.write(ins,ops[0],str(self.offset(base,4*(len(ops)-1))))
            return
        if m in {'mov','movw','movabs','movzx','movsxd','ldr','ldur','str','stur',
                 'movaps','movups','movdqa','movdqu'} and len(ops)==2:
            dest,src=(ops[1],ops[0]) if m in {'str','stur'} else ops
            self.write(ins,dest,self.value(ins,src));return
        if m=='lea' and len(ops)==2:
            self.write(ins,ops[0],str(self.address(ins,ops[1])));return
        if m in {'xor','eor','xorps','pxor'} and len(ops)>=2 and ops[-1].type==ops[-2].type==1 and ops[-1].reg==ops[-2].reg:
            self.write(ins,ops[0],'0');return
        if m in {'and','ands','bic'} and len(ops) in {2,3}:
            operands=ops if len(ops)==2 else ops[1:]
            a,b=[self.value(ins,o) for o in operands]
            bits=63 if self.domain in {'x86_64','aarch64'} else 31
            high=1 if bits==63 else 2 if self.domain=='mips_be' else 3
            for literal,other in ((a,b),(b,a)):
                coordinate=self.coordinate_words.get(other)
                masked=(literal==str(1<<bits) if m=='bic' else literal==str((1<<bits)-1))
                if masked and coordinate and coordinate[1]==high:
                    token='masked-high@'+str(ins.address);self.coordinate_words[token]=coordinate
                    self.write(ins,ops[0],token);return
        if m in {'or','orr'} and len(ops) in {2,3}:
            operands=ops if len(ops)==2 else ops[1:]
            a,b=[self.value(ins,o) for o in operands]
            for literal,other in ((a,b),(b,a)):
                bits=63 if self.domain in {'x86_64','aarch64'} else 31
                if literal in {str(1<<bits),str(-(1<<bits))} and other in self.coordinate_words:
                    token='high-bit@'+str(ins.address);self.high_bit_words[token]=self.coordinate_words[other]
                    self.write(ins,ops[0],token);return
        if m in {'adr','adrp'} and len(ops)==2:
            self.write(ins,ops[0],str(ops[1].imm));return
        if m in {'add','sub'} and len(ops)>=2 and ops[-1].type==2:
            source=ops[0] if self.domain=='x86_64' or len(ops)==2 else ops[1]
            value=self.value(ins,source);delta=ops[-1].imm*(1 if m=='add' else -1)
            self.write(ins,ops[0],str(self.offset(value,delta)));return
        if m in {'stp','ldp','strd','ldrd'} and len(ops) in {3,4} and ops[2].type==3:
            address=self.address(ins,ops[2]);second=self.offset(address,4 if arm else 8)
            if m in {'stp','strd'}:
                self.store(address,self.value(ins,ops[0]),ins.address)
                self.store(second,self.value(ins,ops[1]),ins.address)
            else:
                self.write(ins,ops[0],self.memory.get(address,'load:'+str(address)))
                self.write(ins,ops[1],self.memory.get(second,'load:'+str(second)))
            if ins.writeback:
                base=ops[2].mem.base
                value=str(self.offset(self.reg(ins,base),ops[3].imm)) if len(ops)==4 and ops[3].type==2 else str(address)
                self.write(ins,type('Register',(),{'type':1,'reg':base})(),value)
            return
        if ins.group(cs.CS_GRP_JUMP):return
        try:_,written=ins.regs_access()
        except cs.CsError:written=[]
        for reg in written:
            key=self.key(ins,reg)
            if key not in {'rsp','sp','rip','pc','eflags','nzcv'}:self.regs[key]='unknown@'+str(ins.address)+':'+key


def binary_equations(path,regions,domain,deadline,*,primitive_records=None):
    import time
    from .binary_semantics import disassembler,decode
    if domain not in {'x86_64','aarch64','arm','thumb','mipsel','mips_be'}:return []
    slots=import_slots(path)
    from ..static_binary import targets
    static_targets,static_witnesses=targets(regions,domain,deadline,path=path)
    if primitive_records is not None:primitive_records.extend(static_witnesses)
    if not set(slots.values())&TRUSTED and not static_targets:return []
    gp=None
    if domain in {'mipsel','mips_be'}:
        from elftools.elf.elffile import ELFFile
        with path.open('rb') as stream:
            elf=ELFFile(stream)
            gp=next(((t.entry.d_val+0x7ff0)&0xffffffff for s in elf.iter_segments()
                     if s['p_type']=='PT_DYNAMIC' for t in s.iter_tags() if t.entry.d_tag=='DT_PLTGOT'),None)
    lift=PointerLift(domain,regions,slots,static_targets,mips_gp=gp)
    n=0
    path_matches=[]
    from ..pointer_paths import unwind_ranges,mips_pic_ranges,analyze as analyze_paths
    from ..binary_decode import control_instructions
    ranges=unwind_ranges(path)
    instructions=None
    if domain in {'mipsel','mips_be'}:
        instructions=[ins for base,_,data,flags in regions if flags&1
                      for ins in decode(disassembler(domain),data,base)]
        ranges+=mips_pic_ranges(instructions,regions,gp)
    if ranges:
        if instructions is None:
            instructions=[ins for base,_,data,flags in regions if flags&1
                          for ins in control_instructions(disassembler(domain),data,base,domain=domain,
                                                          entries=[a for a,_ in ranges])]
        helpers={}
        # Path alternatives are an optional supplement to the linear pass.
        # They must not consume its entire budget and discard valid results
        # later merely because the fallback cannot start before the deadline.
        path_deadline=min(deadline,time.monotonic()+8)
        path_matches,records=analyze_paths(PointerLift(domain,regions,slots,static_targets,mips_gp=gp),
                                         instructions,ranges,path_deadline,helper_summaries=helpers)
        if helpers:
            static_targets.update({a:'qcs:xhat:'+str(p)+':'+str(q) for a,(p,q) in helpers.items()})
            extra,helper_records=analyze_paths(PointerLift(domain,regions,slots,static_targets,mips_gp=gp),
                                             instructions,ranges,path_deadline)
            path_matches+=extra
            if primitive_records is not None:
                primitive_records.extend({'address':a,'method':'inferred affine x-hat helper',
                    'point_argument':p,'destination_argument':q} for a,(p,q) in helpers.items())
        if primitive_records is not None:primitive_records.extend({'method':'path-specific unwind range',**r} for r in records)
    for base,_,data,flags in regions:
        if not flags&1:continue
        instructions=iter(decode(disassembler(domain),data,base))
        for ins in instructions:
            n+=1
            if n%1024==0 and (n>500000 or time.monotonic()>deadline):raise ValueError('Big-number call analysis budget exhausted')
            if domain in {'mipsel','mips_be'} and ins.mnemonic in {'jal','jalr','bal','jr'}:
                slot=next(instructions,None)
                from ..controlflow import mips_transfer
                if slot is None or slot.address!=ins.address+4 or mips_transfer(slot):
                    lift.finish();continue
                lift.step(slot)
            lift.step(ins)
    result=[];seen=set()
    for match in [*path_matches,*lift.matches,*lift.equations.matches,*lift.equations.general_matches]:
        key=(match.get('algorithm'),match.get('offset'),match.get('equation'))
        if key not in seen:seen.add(key);result.append(match)
    return result
