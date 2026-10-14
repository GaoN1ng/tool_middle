#!/usr/bin/env python3
"""Compile pinned source references; never derive signatures from test binaries.

Masks use compiler ET_REL relocation records paired with whole linked functions.
Capstone is a build dependency to record immutable data references, not needed
by the runtime matcher. Build hashes, commands and licenses remain auditable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

import capstone as cs
import ziglang
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

PROJECT = Path(__file__).resolve().parents[1]
ROOT = PROJECT.parent
OUT = PROJECT/"artifacts/stripped-repair/retry-references"
TINY = ROOT/"samples/public-benchmark/sources/esp-idf/components/bt/common/tinycrypt"
MBED = ROOT/"third_party/mbedtls"
MICRO = ROOT/"samples/stripped-repair/sources/micro-ecc-541b3a78026420a3e369c4c9281c396b5e531113"
TARGETS = {"x86_64": "x86_64-linux-musl", "aarch64": "aarch64-linux-musl", "arm": "arm-linux-musleabihf", "x86_64_native": None}
TINY_INCLUDES = [TINY/"include", TINY/"port", ROOT/"samples/public-benchmark/metadata/build-compat"]
MODULES = {
 "tiny-sha256": (TINY/"src", ["sha256.c", "utils.c"], TINY_INCLUDES, [], {"tc_sha256_init": ("SHA-256", "initialization"), "tc_sha256_final": ("SHA-256", "finalization")}),
 "tiny-ecdh": (TINY/"src", ["ecc.c", "ecc_dh.c", "ecc_platform_specific.c", "utils.c"], TINY_INCLUDES, [], {"uECC_shared_secret": ("ECDH", "agreement")}),
 "tiny-ecdsa": (TINY/"src", ["ecc.c", "ecc_dsa.c", "ecc_platform_specific.c", "utils.c", "sha256.c", "hmac.c", "hmac_prng.c"], TINY_INCLUDES, [], {"uECC_verify": ("ECDSA", "signature"), "uECC_sign_with_k": ("ECDSA", "signature")}),
 "mbed-rsa": (MBED/"library", ["rsa.c"], [MBED/"include", MBED/"library"], [], {"mbedtls_rsa_public": ("RSA", "rsa_operation"), "mbedtls_rsa_private": ("RSA", "rsa_operation")}),
 "mbed-sha256": (MBED/"library", ["sha256.c"], [MBED/"include", MBED/"library"], [], {"mbedtls_sha256_starts": ("SHA-256", "initialization"), "mbedtls_internal_sha256_process": ("SHA-256", "compression")}),
 "micro-ecdh": (MICRO, ["uECC.c"], [MICRO], ["-DuECC_PLATFORM=uECC_arch_other", "-DuECC_WORD_SIZE=4"], {"uECC_shared_secret": ("ECDH", "agreement")}),
 "micro-ecdsa": (MICRO, ["uECC.c"], [MICRO], ["-DuECC_PLATFORM=uECC_arch_other", "-DuECC_WORD_SIZE=4"], {"uECC_verify": ("ECDSA", "signature"), "uECC_sign_with_k": ("ECDSA", "signature")}),
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def address_data(elf, address, size):
    for segment in elf.iter_segments():
        if segment["p_type"] == "PT_LOAD" and not segment["p_flags"] & 2:
            at = address-segment["p_vaddr"]
            if 0 <= at and at+size <= segment["p_filesz"]:
                return segment.data()[at:at+size]
    return None


def relocation_mask(machine, kind, little_endian=True):
    if machine == "EM_X86_64":
        return {1: bytes(8), 2: bytes(4), 4: bytes(4), 9: bytes(4), 10: bytes(4), 11: bytes(4), 24: bytes(8), 41: bytes(4), 42: bytes(4)}[kind]
    if machine == "EM_AARCH64":
        m = {257: 0, 258: 0, 260: 0, 261: 0, 273: 0xff00001f, 274: 0x9f00001f, 275: 0x9f00001f, 276: 0x9f00001f,
             277: 0xffc003ff, 278: 0xffc003ff, 280: 0xff00001f, 282: 0xfc000000, 283: 0xfc000000,
             284: 0xffc003ff, 285: 0xffc003ff, 286: 0xffc003ff, 299: 0xffc003ff,
             311: 0x9f00001f, 312: 0xffc003ff}[kind]
        return m.to_bytes(8 if kind in {257, 260} else 4, "little")
    if machine == "EM_ARM":
        return {2: 0, 3: 0, 10: 0xd000f800, 25: 0, 26: 0, 28: 0xff000000, 29: 0xff000000, 30: 0xd000f800, 43: 0xfff0f000, 44: 0xfff0f000, 45: 0xfff0f000, 46: 0xfff0f000, 47: 0x8f00fbf0, 48: 0x8f00fbf0, 49: 0x8f00fbf0, 50: 0x8f00fbf0, 96: 0}[kind].to_bytes(4, "little")
    if machine == "EM_MIPS":
        if kind == 37:  # R_MIPS_JALR is a linker hint, no encoded address field.
            return b""
        return {2: 0, 4: 0xfc000000, 5: 0xffff0000, 6: 0xffff0000,
                7: 0xffff0000, 9: 0xffff0000, 11: 0xffff0000, 12: 0,
                64: 0xffff0000, 65: 0xffff0000}[kind].to_bytes(4, "little" if little_endian else "big")
    raise ValueError(machine)


def literals(elf, data, address, machine):
    result = []
    if machine in {"EM_ARM", "EM_MIPS"}:
        # ARM literal pools stay inside these whole functions, exact and unmasked.
        return result
    arch, mode = (cs.CS_ARCH_X86, cs.CS_MODE_64) if machine == "EM_X86_64" else (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM)
    dis = cs.Cs(arch, mode)
    dis.detail = True
    pages = {}
    for ins in dis.disasm(data, address):
        at = ins.address-address
        if machine == "EM_X86_64":
            for op in ins.operands:
                if op.type == cs.x86.X86_OP_MEM and op.mem.base == cs.x86.X86_REG_RIP:
                    value = address_data(elf, ins.address+ins.size+op.mem.disp, op.size)
                    if value:
                        result.append({"kind": "x86_rip", "offset": at+ins.disp_offset, "next_instruction": at+ins.size, "bytes": value.hex()})
        else:
            if ins.mnemonic == "adrp":
                pages[ins.operands[0].reg] = (at, ins.operands[1].imm)
            elif ins.mnemonic == "ldr" and len(ins.operands) == 2 and ins.operands[1].type == cs.arm64.ARM64_OP_MEM:
                mem = ins.operands[1].mem
                if mem.base in pages:
                    p, page_address = pages[mem.base]
                    reg = ins.reg_name(ins.operands[0].reg)
                    size = {"q": 16, "d": 8, "x": 8, "s": 4, "w": 4, "h": 2, "b": 1}.get(reg[0])
                    value = address_data(elf, page_address+mem.disp, size) if size else None
                    if value:
                        result.append({"kind": "a64_page_load", "offset": at, "page_offset": p, "scale": size, "bytes": value.hex()})
            _, writes = ins.regs_access()
            if ins.mnemonic != "adrp":
                for reg in writes:
                    pages.pop(reg, None)
    return result


def extract(path, objects, module, arch, opt, *, initialization_binder=None, dependency_only=False):
    functions = MODULES[module][-1]
    relocations = {}
    for object_path in objects:
        with object_path.open("rb") as stream:
            obj = ELFFile(stream)
            for symbol in obj.get_section_by_name(".symtab").iter_symbols():
                if symbol.name not in functions:
                    continue
                relocs = []
                for sec in obj.iter_sections():
                    if isinstance(sec, RelocationSection) and sec["sh_info"] == symbol["st_shndx"]:
                        symbol_start = symbol["st_value"] & ~1 if obj["e_machine"] == "EM_ARM" else symbol["st_value"]
                        relocs.extend((r["r_offset"]-symbol_start, r["r_info_type"]) for r in sec.iter_relocations()
                                      if symbol_start <= r["r_offset"] < symbol_start+symbol["st_size"])
                relocations[symbol.name] = (symbol["st_size"], relocs)
    result = []
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        machine = elf["e_machine"]
        for symbol in elf.get_section_by_name(".symtab").iter_symbols():
            if symbol.name not in functions or symbol["st_info"]["type"] != "STT_FUNC":
                continue
            address, size = symbol["st_value"], symbol["st_size"]
            if machine == "EM_ARM" and address & 1:
                address &= ~1
                if arch != "thumb":
                    raise ValueError("Thumb function in non-Thumb signature domain")
            sec = elf.get_section(symbol["st_shndx"])
            start = address-sec["sh_addr"]
            data = sec.data()[start:start+size]
            mask = bytearray(b"\xff"*size)
            object_size, relocs = relocations[symbol.name]
            if object_size != size:
                raise ValueError("Linker changed function size; manual review required")
            for offset, kind in relocs:
                m = relocation_mask(machine, kind, elf.little_endian)
                if machine == "EM_MIPS" and kind == 37:
                    word = int.from_bytes(data[offset:offset+4], "little" if elf.little_endian else "big")
                    # LLD relaxes JALR hints to PC-relative BAL for local
                    # callees; its branch displacement changes on relinking.
                    if word & 0xffff0000 == 0x04110000:
                        m = (0xffff0000).to_bytes(4, "little" if elf.little_endian else "big")
                if machine == "EM_AARCH64":
                    word = int.from_bytes(data[offset:offset+4], "little")
                    # LLD can relax ADRP+ADD into NOP+ADR. Apply the address
                    # field mask of the *linked* instruction, not ADD's mask.
                    if kind in {275, 276, 277} and word & 0x9f000000 == 0x10000000:
                        m = (0x9f00001f).to_bytes(4, "little")
                    elif kind in {275, 276} and word == 0xd503201f:
                        m = b'\xff'*4
                if offset+len(m) > size:
                    raise ValueError("Relocation crosses function boundary")
                mask[offset:offset+len(m)] = m
            bits = sum(x.bit_count() for x in mask)
            algorithm, role = functions[symbol.name]
            refs = literals(elf, data, address, machine)
            bound_initializer=False
            if role=='initialization' and initialization_binder is not None:
                probe={'architecture':arch,'bytes':data.hex(),'literals':refs,'reference':{'address':address}}
                bound_initializer=initialization_binder(path,probe)
                refs=probe['literals']
            # A short whole initializer is usable only with an independently
            # bound complete 256-bit IV plus substantial exact opcode bits.
            short_bound=bound_initializer and size>=24 and bits>=160 and sum(len(bytes.fromhex(x['bytes'])) for x in refs)>=32
            short_dependency=dependency_only and role=='primitive_dependency' and size>=4 and bits>=16
            # A whole x86 tail thunk carries just its JMP opcode after masking
            # the displacement. It may bind a dependency, never a semantic
            # root; the static graph must verify its exact target as well.
            short_dependency=short_dependency or (dependency_only and role=='primitive_dependency'
                and arch=='x86_64' and size==5 and bits==8 and data[0]==0xe9)
            if (bits < 256 or size < 40) and not short_bound and not short_dependency:
                raise ValueError(f"Function too small: {symbol.name}: {size}, {bits}")
            if role == "initialization" and not bound_initializer and machine not in {"EM_ARM", "EM_MIPS"} and not refs and b'\x67\xe6\x09\x6a' not in data:
                # At O0 AArch64 materializes each 32-bit IV with MOV/MOVK;
                # those non-relocation immediate bits remain exact in the mask.
                values, registers = set(), {}
                dis = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_ARM)
                dis.detail = True
                if machine == "EM_AARCH64":
                    for ins in dis.disasm(data, address):
                        if ins.mnemonic in {"mov", "movz", "movk"} and len(ins.operands) == 2 and ins.operands[1].type == cs.arm64.ARM64_OP_IMM:
                            reg, op = ins.operands[0].reg, ins.operands[1]
                            shift = op.shift.value
                            value = op.imm << shift
                            if ins.mnemonic == "movk":
                                value |= registers.get(reg, 0) & ~(65535 << shift)
                            registers[reg] = value & 0xffffffff
                            values.add(registers[reg])
                if not {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19} <= values:
                    raise ValueError("Initializer does not bind its hash IV")
            normalized = bytes(a & b for a, b in zip(data, mask))
            sid = hashlib.sha256(arch.encode()+normalized+mask).hexdigest()
            result.append({"id": sid, "architecture": arch, "family": module, "algorithm": algorithm,
                "role": role, "function": symbol.name, "bytes": normalized.hex(), "mask": mask.hex(),
                "significant_bits": bits, "alignment": 1 if arch == "x86_64" else 2 if arch == "thumb" else 4, "literals": refs,
                "reference": {"artifact": str(path.relative_to(ROOT)), "sha256": digest(path), "optimization": opt,
                              "compiler": "Zig 0.13.0 / bundled Clang", "address": address}})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=PROJECT/"qcs/rules/function_signatures.json")
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    cc = [str(Path(ziglang.__file__).parent/"zig"), "cc"]
    env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(PROJECT/".zig-cache/global"), ZIG_LOCAL_CACHE_DIR=str(PROJECT/".zig-cache/local"))
    commands, signatures, count = [], [], 0
    for variant, target in TARGETS.items():
        arch = variant.split("_native")[0]
        target_flags = ["-target", target] if target else []
        for module, (root, units, includes, extra, functions) in MODULES.items():
            if target is None and not module.startswith("mbed-"):
                continue
            for opt in ["O1", "O2", "Os", "O2-g0"]:
                path = OUT/variant/(module+"-"+opt+".so")
                path.parent.mkdir(parents=True, exist_ok=True)
                flags = ["-fPIC", "-"+opt.split('-')[0], "-fvisibility=hidden", "-ffile-prefix-map="+str(ROOT)+"=."]+(["-g0"] if opt.endswith('-g0') else [])+target_flags+extra+["-I"+str(p) for p in includes]
                objects = [path.with_suffix("."+unit+".o") for unit in units]
                builds = [cc+flags+["-c", str(root/unit), "-o", str(obj)] for unit, obj in zip(units, objects)]
                builds.append(cc+["-shared", "-Wl,--no-gc-sections"]+target_flags+[str(p) for p in objects]+["-o", str(path)])
                for command in builds:
                    run = subprocess.run(command, env=env, capture_output=True, text=True, timeout=180)
                    commands.append({"argv": command, "exit_code": run.returncode, "stderr": run.stderr,
                        "source_hashes": {str((root/p).relative_to(ROOT)): digest(root/p) for p in units}})
                    (OUT/"build-log.json").write_text(json.dumps(commands, indent=2)+"\n")
                    if run.returncode:
                        raise RuntimeError(run.stderr)
                signatures.extend(extract(path, objects, module, arch, opt))
                count += 1
                print(variant, module, opt, flush=True)
    unique, algorithms = {}, {}
    for s in signatures:
        if s["id"] in algorithms and algorithms[s["id"]] != s["algorithm"]:
            raise ValueError("Cross-algorithm signature collision")
        algorithms[s["id"]] = s["algorithm"]
        unique[(s["id"], json.dumps(s["literals"], sort_keys=True))] = s
    origins = {"tiny": ("espressif/esp-idf", "fcae32885b0296b32044cb99ecbdc50d98dddb83", "Apache-2.0 AND BSD-3-Clause"),
               "mbed": ("Mbed-TLS/mbedtls", "c765c831e5c2a0971410692f92f7a81d6ec65ec2", "Apache-2.0 OR GPL-2.0-or-later"),
               "micro": ("kmackay/micro-ecc", "541b3a78026420a3e369c4c9281c396b5e531113", "BSD-2-Clause")}
    families = {}
    for name, spec in MODULES.items():
        repo, commit, license_name = origins[name.split('-')[0]]
        if name in {"tiny-ecdh", "tiny-ecdsa"}:
            license_name += " AND BSD-2-Clause"
        families[name] = {"required_roles": sorted({v[1] for v in spec[-1].values()}),
            "repository": "https://github.com/"+repo, "commit": commit, "license": license_name}
    args.output.write_text(json.dumps({"schema_version": "1.0", "method": "Whole function masks from actual relocations, immutable literals and required witness roles", "build_tool": "tools/build_function_signatures.py", "families": families, "signatures": list(unique.values())}, indent=2)+"\n")
    print(json.dumps({"reference_builds": count, "commands": len(commands), "signatures": len(unique), "database_sha256": digest(args.output)}))


if __name__ == "__main__":
    main()
