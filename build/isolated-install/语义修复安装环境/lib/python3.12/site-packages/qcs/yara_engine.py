from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path

from .model import evidence, error

from .paths import resource_path
MAPPING_PATH = resource_path("rules/yara_mapping.json")

def aes_instruction_offsets(path, offsets):
    """Require decoded AES opcodes at actual executable instruction boundaries.

    The upstream VEX wildcard also matches invalid encodings and constants.
    No function names, symbols or target execution are used.
    """
    from .function_signatures import function_regions
    from .guomi.binary_semantics import decode,disassembler
    regions,_=function_regions(path);wanted=set(offsets);valid=set()
    for base,file_offset,data,flags in regions:
        if not flags&1 or not any(file_offset<=p<file_offset+len(data) for p in wanted):continue
        if len(data)>8*1024*1024:continue
        for instruction in decode(disassembler('x86_64'),data,base):
            at=file_offset+instruction.address-base
            if at in wanted and instruction.id and instruction.mnemonic in {'aesenc','aesdec','vaesenc','vaesdec'}:
                valid.add(at)
    return valid

def rules_digest(root):
    h = hashlib.sha256()
    for path in sorted(root.rglob("*.yar")):
        h.update(path.relative_to(root).as_posix().encode() + b"\0" + path.read_bytes())
    return h.hexdigest()

@lru_cache(maxsize=8)
def compiled(rule_path, digest):
    import yara
    return yara.compile(filepath=rule_path)

def scan_yara(path, report, rule_path, timeout):
    import yara
    mapping = json.loads(MAPPING_PATH.read_text(encoding="utf-8"))["rules"]
    digest = rules_digest(rule_path.parent)
    report["versions"]["yara"] = {"python_binding": yara.__version__, "rule_entry": str(rule_path),
        "rules_sha256": digest, "mapping_sha256": hashlib.sha256(MAPPING_PATH.read_bytes()).hexdigest(),
        "upstream_commit": "1b1c7bfede7133f097ed823bed64df92f4a4bc96"}
    rules = compiled(str(rule_path), digest)
    arch = report["artifact"].get("architecture")
    x64 = arch in {"x64", "x86_64"}
    skipped = []
    for match in rules.match(filepath=str(path), timeout=max(1, int(timeout))):
        spec = mapping.get(match.rule)
        if spec is None:
            error(report, "yara", "unmapped_rule", f"Unreviewed YARA rule: {match.rule}", "partial")
            spec = {"algorithm": None, "candidates": [], "type": "binary_constant", "architecture": "any", "basis": "Unreviewed rule; no algorithm assignment", "confidence": "low"}
        matches = []
        for string_match in match.strings:
            if hasattr(string_match, "instances"):
                matches.extend({"identifier": string_match.identifier, "offset": inst.offset,
                    "matched_length": inst.matched_length, "matched_hex": inst.matched_data.hex()} for inst in string_match.instances)
            else:
                offset, identifier, data = string_match
                matches.append({"identifier": identifier, "offset": offset, "matched_length": len(data), "matched_hex": data.hex()})
        item = evidence(spec["algorithm"], "yara", spec["type"], match.rule,
            offset=min((x["offset"] for x in matches), default=None), matches=matches,
            confidence=spec["confidence"], confidence_reason=spec["basis"],
            candidate_algorithms=spec["candidates"], rule_metadata=match.meta,
            rule_architecture=spec["architecture"])
        if spec.get("required_any_identifier") and not set(spec["required_any_identifier"]).intersection(x["identifier"] for x in matches):
            item.update(algorithm=None, algorithm_category="unknown", confidence="low",
                candidate_algorithms=spec["fallback_candidates"],
                confidence_reason="Only shared IV constants matched; algorithm-specific discriminator absent")
        if spec["architecture"] == "x86_64" and not x64:
            item.update(algorithm=None, algorithm_category="unknown", confidence="low",
                confidence_reason="Instruction-like byte match suppressed: architecture is not established x86-64")
            skipped.append(match.rule)
        if match.rule=='AES_bytecode_AESNI_x64' and x64:
            valid=aes_instruction_offsets(path,[m['offset'] for m in matches])
            item['decoded_instruction_offsets']=sorted(valid)
            if not valid:
                item.update(algorithm=None,algorithm_category='unknown',candidate_algorithms=['AES'],confidence='low',
                    confidence_reason='Opcode-like bytes lack a decoded AES instruction at an executable instruction boundary')
                skipped.append(match.rule)
        if item["algorithm"] and item["algorithm_category"] != "encoding":
            report["findings"].append(item)
        else:
            report["clues"].append(item)
    if not x64:
        report["coverage_notes"].append("YARA x86-64 instruction mappings suppressed on other/unknown architectures; constants provide limited coverage.")
    report["engine_status"].setdefault("yara", {"status": "completed", "suppressed_instruction_rules": skipped})
