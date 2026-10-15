from __future__ import annotations

from pathlib import Path
import importlib.metadata

from .api_rules import classify, MULTI_API, normalize_symbol, TERMINAL_RULES_PATH
from .model import evidence,sha256

def record(report, name, status, table, address=None, dll=None):
    algo, generic = classify(name)
    if not algo and not generic:
        return
    item = evidence(algo, "symbol", "binary_symbol", name, symbol_status=status,
        symbol_table=table, address=address, dll=dll,
        confidence="high" if algo else "low",
        confidence_reason="Explicit algorithm function import/definition; static reference only" if algo else "Generic API cannot determine an algorithm")
    if algo and item["algorithm_category"] != "encoding":
        for algorithm in MULTI_API.get(normalize_symbol(name), [algo]):
            report["findings"].append({**item, 'algorithm': algorithm})
    else:
        item["clue_category"] = generic or "encoding"
        if generic == "SHA-224/SHA-256":
            item["candidate_algorithms"] = ["SHA-224", "SHA-256"]
        report["clues"].append(item)

def scan_elf(path: Path, report: dict):
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        report["artifact"].update(format="ELF", architecture=elf.get_machine_arch(),
            machine=elf["e_machine"], bits=elf.elfclass, endianness="little" if elf.little_endian else "big")
        tables, seen, count = [], {}, 0
        for section in elf.iter_sections():
            if section.name in {".dynsym", ".symtab"} and isinstance(section, SymbolTableSection):
                tables.append(section.name)
                for symbol in section.iter_symbols():
                    if symbol["st_info"]["type"] not in {"STT_FUNC", "STT_GNU_IFUNC", "STT_LOOS"} or not symbol.name:
                        continue
                    count += 1
                    status = "import" if symbol["st_shndx"] == "SHN_UNDEF" else "defined"
                    key = symbol.name, status, symbol["st_value"]
                    if key in seen:
                        # Preserve table provenance while deduplicating the function identity.
                        for item in seen[key]:
                            item["symbol_tables"].append(section.name)
                        continue
                    before_findings, before_clues = len(report["findings"]), len(report["clues"])
                    record(report, symbol.name, status, section.name, symbol["st_value"] or None)
                    items = report['findings'][before_findings:] + report['clues'][before_clues:]
                    for item in items:
                        item["symbol_tables"] = [section.name]
                    seen[key] = items
            if section["sh_type"] == "SHT_DYNAMIC":
                for tag in section.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        report["dependencies"].append({"engine": "symbol", "evidence_type": "library_dependency", "name": tag.needed, "symbol_table": section.name})
        report["artifact"]["symbol_tables"] = tables
        report["artifact"]["function_symbol_count"] = count
        report["artifact"]["symbol_state"] = "retained" if ".symtab" in tables else "stripped_or_dynamic_only"
        if ".symtab" not in tables:
            report["coverage_notes"].append("ELF static symbol table absent: known-function recognition can supply selected asymmetric implementation evidence; unmatched unnamed operations remain a coverage gap.")
    report["engine_status"]["symbol"] = {"status": "completed"}

def scan_pe(path: Path, report: dict):
    import pefile
    pe = pefile.PE(str(path), fast_load=True)
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"], pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"]])
        machine = pe.FILE_HEADER.Machine
        report["artifact"].update(format="PE", architecture={0x8664: "x64", 0x14c: "x86", 0xaa64: "AArch64"}.get(machine, f"machine_{machine:x}"),
            machine=machine, bits=64 if pe.OPTIONAL_HEADER.Magic == 0x20b else 32, endianness="little", symbol_state="imports_only")
        for attr, table in [("DIRECTORY_ENTRY_IMPORT", "PE.imports"), ("DIRECTORY_ENTRY_DELAY_IMPORT", "PE.delay_imports")]:
            for entry in getattr(pe, attr, []):
                dll = entry.dll.decode("ascii", errors="replace")
                report["dependencies"].append({"engine": "symbol", "evidence_type": "library_dependency", "name": dll, "symbol_table": table})
                for imp in entry.imports:
                    if imp.name:
                        record(report, imp.name.decode("ascii", errors="replace"), "import", table, imp.address, dll)
                    else:
                        report["clues"].append(evidence(None, "symbol", "binary_symbol", f"ordinal:{imp.ordinal}", dll=dll, symbol_status="import", symbol_table=table, confidence_reason="Ordinal imports have no algorithm name"))
        report["coverage_notes"].append("PE symbol scan covers named/delay imports. Selected static x64 implementations use a separate function-signature channel; unmatched static builds remain outside reliable coverage.")
    finally:
        pe.close()
    report["engine_status"]["symbol"] = {"status": "completed"}

def scan_symbols(path: Path, report: dict):
    with path.open("rb") as stream:
        magic = stream.read(4)
    if magic == b"\x7fELF":
        report["versions"]["pyelftools"] = importlib.metadata.version("pyelftools")
        scan_elf(path, report)
    elif magic[:2] == b"MZ":
        report["versions"]["pefile"] = importlib.metadata.version("pefile")
        scan_pe(path, report)
    else:
        report["artifact"].update(format="raw", symbol_state="unavailable")
        report["engine_status"]["symbol"] = {"status": "unsupported", "reason": "No ELF/PE header"}
        report["coverage_notes"].append("Raw binary: symbols/architecture unknown; only architecture-independent constants scanned.")
    report["versions"]["symbol_rules_sha256"] = sha256(Path(__file__).with_name("api_rules.py"))
    report['versions']['terminal_api_mapping_sha256'] = sha256(TERMINAL_RULES_PATH)
    from .guomi import API_PATH
    report['versions']['guomi_api_mapping_sha256'] = sha256(API_PATH)
