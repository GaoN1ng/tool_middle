"""Recognize selected whole library functions without consulting target symbols.

Reviewed ELF/COFF relocation bits and explicitly audited linker alternatives
are matched. Algorithm literals and declared ELF zero-initialized data are
checked separately; reference-specific diagnostic operands may be excluded.
This is conservative known-code recognition, not algorithm inference from generic
math and not a reimplementation of Ghidra's Function ID hash/scoring scheme.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .model import error, evidence

from .paths import resource_path
DATABASE = resource_path("rules/function_signatures.json")
MACHINES = {"EM_X86_64": "x86_64", "EM_AARCH64": "aarch64", "EM_ARM": "arm",
            "EM_MIPS": "mipsel", "EM_XTENSA": "xtensa"}


def hex_pattern(data, mask):
    # YARA nibble masks overmatch some partial bits; verify all bits afterward.
    return " ".join("".join(f"{b >> shift & 15:x}" if m >> shift & 15 == 15 else "?"
                            for shift in (4, 0)) for b, m in zip(data, mask))


def anchor(signature):
    return cached_anchor(signature["bytes"], signature["mask"])


@lru_cache(maxsize=256)
def cached_anchor(data_hex, mask_hex):
    data, mask = bytes.fromhex(data_hex), bytes.fromhex(mask_hex)
    length = min(64, len(data))
    # Keep YARA's masked candidate search short. Long wildcard expressions can
    # miss otherwise exact candidates in its regex engine. The full function is
    # still verified byte by byte below, including all significant bits.
    weights = [m.bit_count() for m in mask]
    best = score = sum(weights[:length])
    offset = 0
    for at in range(1, len(data)-length+1):
        score += weights[at+length-1]-weights[at-1]
        if score > best:
            offset, best = at, score
    return offset, hex_pattern(data[offset:offset+length], mask[offset:offset+length])


@lru_cache(maxsize=4)
def load_database(path, digest):
    import yara
    db = json.loads(Path(path).read_text(encoding="utf-8"))
    rules = {}
    for arch in sorted({s["architecture"] for s in db["signatures"]}):
        selected = [(i, s) for i, s in enumerate(db["signatures"]) if s["architecture"] == arch]
        if selected:
            source = "\n".join(f"rule sig_{i} {{ strings: $body = {{ {anchor(s)[1]} }} condition: $body }}"
                               for i, s in selected)
            rules[arch] = yara.compile(source=source)
    return db, rules


def read_virtual(segments, address, size):
    for base, offset, data, flags in segments:
        if base <= address and address + size <= base + len(data):
            return data[address-base:address-base+size]
    return None


@dataclass(frozen=True)
class ZeroFill:
    """A declared ELF load-segment zero tail, without allocating its size.

    These ranges supply small initial-data constraints only. They never supply
    candidate executable bytes, including for segments originally marked PF_X.
    """
    size: int

    def __len__(self):
        return self.size

    def __getitem__(self, item):
        start, stop, step = item.indices(self.size)
        return bytes(len(range(start, stop, step)))


def elf_load_regions(elf):
    regions = []
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD":
            continue
        base, offset = segment["p_vaddr"], segment["p_offset"]
        filesz, memsz, flags = segment["p_filesz"], segment["p_memsz"], segment["p_flags"]
        if memsz < filesz or base+memsz > 1 << elf.elfclass or memsz >= 1 << 63:
            raise ValueError("Invalid ELF load-segment memory extent")
        data = segment.data()
        if len(data) != filesz:
            raise ValueError("Truncated ELF load segment")
        regions.append((base, offset, data, flags))
        if memsz > filesz:
            regions.append((base+filesz, offset+filesz, ZeroFill(memsz-filesz), flags & ~1))
    return regions


def valid_literals(signature, body, address, segments):
    for literal in signature.get("literals", []):
        at = literal["offset"]
        if literal["kind"] == "arm_relative_pool":
            target = address + literal["pc_offset"] + int.from_bytes(body[at:at+4], "little", signed=True)
        elif literal["kind"] == "a64_adr_data":
            word=int.from_bytes(body[at:at+4],"little")
            imm=((word>>5&0x7ffff)<<2)|(word>>29&3)
            if imm&(1<<20):imm-=1<<21
            target=address+at+imm
        elif literal["kind"] in {"x86_rip", "x86_rip_pointer"}:
            target = address + literal["next_instruction"] + int.from_bytes(body[at:at+4], "little", signed=True)
            if literal["kind"] == "x86_rip_pointer":
                pointer = read_virtual(segments, target, 8)
                if pointer is None:
                    return False
                target = int.from_bytes(pointer, "little")
        elif literal["kind"] == "a64_page_load":
            p = literal["page_offset"]
            adrp = int.from_bytes(body[p:p+4], "little")
            imm = ((adrp >> 5 & 0x7ffff) << 2) | (adrp >> 29 & 3)
            if imm & (1 << 20):
                imm -= 1 << 21
            load = int.from_bytes(body[at:at+4], "little")
            target = ((address+p) & ~4095) + (imm << 12) + (load >> 10 & 4095) * literal["scale"]
        elif literal["kind"] in {"xtensa_l32r", "xtensa_l32r_pointer"}:
            # Xtensa L32R uses a negative, word-scaled 16-bit displacement
            # from the aligned PC (Xtensa ISA reference, L32R operation).
            imm = int.from_bytes(body[at+1:at+3], "little")-65536
            target = ((address+at+3) & ~3) + imm*4
            if literal["kind"] == "xtensa_l32r_pointer":
                pointer = read_virtual(segments, target, 4)
                if pointer is None:
                    return False
                target = int.from_bytes(pointer, "little")
        else:
            raise ValueError(f"Unknown literal constraint: {literal['kind']}")
        expected = bytes.fromhex(literal["bytes"])
        if read_virtual(segments, target, len(expected)) != expected:
            return False
    return True


def valid_linker_variants(signature, body, address, segments):
    """Validate only alternatives audited from reference ET_REL records.

    R_X86_64_REX_GOTPCRELX can relax a RIP MOV through a GOT slot to a
    RIP LEA of the object itself. Pointer initial values are environment data,
    not algorithm constants. All other instruction bits stay in the mask.
    """
    for variant in signature.get('linker_variants', []):
        if variant['kind'] != 'x86_gotpcrelx_load_address':
            raise ValueError('Unknown linker variant: '+variant['kind'])
        start, opcode, disp, end = (variant[k] for k in (
            'instruction_offset','opcode_offset','displacement_offset','next_instruction'))
        if not (signature['architecture']=='x86_64' and variant['relocation_type']==42
                and variant['reference_symbol'] in {'stdin','stdout','stderr'}
                and 0<=start<end<=len(body) and end-start==7
                and opcode==start+1 and disp==start+3
                and body[start] & 0xf8 == 0x48 and body[opcode] in {0x8b,0x8d}
                and body[start+2] & 0xc7 == 0x05):
            return False
        target=address+end+int.from_bytes(body[disp:disp+4],'little',signed=True)
        if read_virtual(segments,target,8) is None:
            return False
    return True


def function_regions(path):
    """Return loaded regions and signature domains, never target names."""
    from elftools.elf.elffile import ELFFile
    with Path(path).open("rb") as stream:
        magic = stream.read(4)
        if magic[:2] == b"MZ":
            import pefile
            pe = pefile.PE(str(path), fast_load=True)
            try:
                arch = {0x8664: "pe_x86_64"}.get(pe.FILE_HEADER.Machine)
                regions = [(pe.OPTIONAL_HEADER.ImageBase+s.VirtualAddress, s.PointerToRawData,
                            s.get_data()[:s.Misc_VirtualSize],
                            (1 if s.Characteristics & 0x20000000 else 0) |
                            (2 if s.Characteristics & 0x80000000 else 0)) for s in pe.sections]
                return regions, [arch] if arch else []
            finally:
                pe.close()
        if magic != b"\x7fELF":
            return [], []
        stream.seek(0)
        elf = ELFFile(stream)
        arch = MACHINES.get(elf["e_machine"])
        if not elf.little_endian:
            arch = "mips_be" if elf["e_machine"] == "EM_MIPS" else None
        if not arch or elf["e_type"] not in {"ET_EXEC", "ET_DYN"}:
            return [], []
        segments = elf_load_regions(elf)
        # A linker can map .rodata in PF_X together with .text. Prefer actual
        # executable section ranges when section headers exist, while retaining
        # every loaded segment for virtual readonly-literal verification.
        sections = [(s["sh_addr"], s["sh_offset"], s.data(), 1)
                    for s in elf.iter_sections() if s["sh_flags"] & 4 and s["sh_type"] != "SHT_NOBITS"
                    and any(flags & 1 and base <= s["sh_addr"] and s["sh_addr"]+s["sh_size"] <= base+len(data)
                            for base, offset, data, flags in segments)]
        if elf.num_sections():
            segments = [(a, off, data, flags & ~1) for a, off, data, flags in segments]+sections
        return segments, ["arm", "thumb"] if arch == "arm" else [arch]


def scan_functions(path, report, timeout, *, regions=None, architectures=None, database=None, engine="function_signature"):
    database = DATABASE if database is None else Path(database)
    started = time.monotonic()
    digest = hashlib.sha256(database.read_bytes()).hexdigest()
    db, rules = load_database(str(database), digest)
    version_key="function_signatures" if engine == "function_signature" else engine
    report["versions"][version_key] = {"database_sha256": digest,
        "schema_version": db["schema_version"], "signature_count": len(db["signatures"]),
        "method": "whole_function_relocation_mask_and_literals"}
    if db.get('environment_reference_policy'):
        report['versions'][version_key]['environment_reference_policy']=db['environment_reference_policy']
        report['versions'][version_key]['method']='whole_function_relocation_mask_literals_and_audited_linker_variants'
    segments, domains = function_regions(path) if regions is None else (regions, architectures or [])
    domains = [a for a in domains if a in rules]
    if not domains:
        report["engine_status"][engine] = {"status": "disabled", "reason": "No validated function signatures for this format, architecture or object type"}
        return
    witnesses = {}
    for base, file_offset, data, flags in segments:
        if not flags & 1:
            continue
        remaining = timeout-(time.monotonic()-started)
        if remaining <= 0:
            error(report, engine, "timeout", "Function scan deadline exhausted", "partial")
            return
        matches = [(arch, match) for arch in domains for match in rules[arch].match(data=data, timeout=max(1, int(remaining)))]
        for arch, match in matches:
            sig = db["signatures"][int(match.rule.removeprefix("sig_"))]
            expected, mask = bytes.fromhex(sig["bytes"]), bytes.fromhex(sig["mask"])
            anchor_offset = anchor(sig)[0]
            for string in match.strings:
                for instance in string.instances:
                    offset = instance.offset-anchor_offset
                    if offset < 0:
                        continue
                    address = base+offset
                    body = data[offset:offset+len(expected)]
                    if address % sig["alignment"] or len(body) != len(expected):
                        continue
                    if (any((a ^ b) & m for a, b, m in zip(body, expected, mask))
                            or not valid_literals(sig, body, address, segments)
                            or not valid_linker_variants(sig, body, address, segments)):
                        continue
                    key = (sig["family"], sig["algorithm"], arch)
                    item = {"function": sig["function"], "role": sig["role"], "signature_id": sig["id"],
                        "offset": file_offset+offset, "address": address, "length": len(body),
                        "significant_bits": sig["significant_bits"], "literal_constraints": len(sig.get("literals", [])),
                        "audited_linker_variants": len(sig.get('linker_variants', [])),
                        "reference": sig["reference"]}
                    witnesses.setdefault(key, {}).setdefault(sig["role"], {})[(address, sig["function"])] = item
    for (family, algorithm, arch), roles in sorted(witnesses.items()):
        required = db["families"][family]["required_roles"]
        items = [v for role in roles.values() for v in role.values()]
        complete = all(role in roles for role in required)
        report["findings" if complete else "clues"].append(evidence(
            algorithm if complete else None, engine, "binary_function_signature", family,
            confidence="medium" if complete else "low",
            confidence_reason="Whole known functions match with relocation masks and referenced data; recorded linker alternatives checked where applicable; static evidence within recorded library/compiler settings" if complete else "Incomplete function witnesses; required operation roles are missing",
            candidate_algorithms=[] if complete else [algorithm], offset=min(x["offset"] for x in items),
            matched_functions=items, required_roles=required, matched_roles=sorted(roles),
            rule_architecture=arch, implementation_family=family, database_sha256=digest))
    report["engine_status"][engine] = {"status": "completed", "architectures": domains, "matched_families": len(witnesses)}
    report["coverage_notes"].append("Function signatures recognize recorded library/compiler/configuration builds, including selected Thumb/MIPS/Xtensa and static PE references. Unrecorded builds, LTO, inlining and obfuscation remain limitations; shared SHA compression alone stays unresolved.")
