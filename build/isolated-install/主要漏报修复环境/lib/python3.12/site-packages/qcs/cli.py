from __future__ import annotations

import argparse
import csv
import importlib
import importlib.metadata
import json
import platform
import shutil
import sys
from pathlib import Path

from .model import all_evidence
from .scanner import Options, WORKSPACE, scan

def doctor(options):
    checks = [{"dependency": "linux_runtime", "status": "available" if sys.platform.startswith("linux") else "unsupported",
               "system": platform.system(), "architecture": platform.machine(),
               "python_executable": sys.executable}]
    for module, package in [("yara", "yara-python"), ("elftools", "pyelftools"), ("pefile", "pefile"), ("capstone", "capstone"),
                            ('tree_sitter','tree-sitter'),('tree_sitter_javascript','tree-sitter-javascript'),
                            ('tree_sitter_c','tree-sitter-c'),('tree_sitter_cpp','tree-sitter-cpp'),('unicorn','unicorn')]:
        try:
            importlib.import_module(module)
            checks.append({"dependency": package, "status": "available", "version": importlib.metadata.version(package)})
        except Exception as exc:
            checks.append({"dependency": package, "status": "missing", "reason": str(exc), "remedy": "Run setup-linux.sh with Python 3.12, or install requirements.lock in an isolated Python 3.12 environment"})
    try:
        from .yara_engine import compiled, rules_digest
        compiled(str(options.rules), rules_digest(options.rules.parent))
        checks.append({"dependency": "yara_rules", "status": "available", "sha256": rules_digest(options.rules.parent)})
    except Exception as exc:
        checks.append({"dependency": "yara_rules", "status": "failed", "reason": str(exc)})
    try:
        from .function_signatures import DATABASE, load_database
        from .model import sha256
        digest = sha256(DATABASE)
        database, _ = load_database(str(DATABASE), digest)
        checks.append({"dependency": "function_signatures", "status": "available", "sha256": digest,
                       "signature_count": len(database["signatures"])})
    except Exception as exc:
        checks.append({"dependency": "function_signatures", "status": "failed", "reason": str(exc)})
    try:
        from .source_reference import DATABASE, load_references
        from .model import sha256
        digest = sha256(DATABASE)
        references = load_references(str(DATABASE), digest)
        checks.append({"dependency": "source_implementations", "status": "available", "sha256": digest,
                       "reference_count": len(references)})
    except Exception as exc:
        checks.append({"dependency": "source_implementations", "status": "failed", "reason": str(exc)})
    if options.windriver:
        try:
            from .windriver import engines
            engines(str(options.windriver_root))
            checks.append({"dependency": "windriver", "status": "available", "path": str(options.windriver_root)})
        except Exception as exc:
            checks.append({"dependency": "windriver", "status": "missing", "reason": str(exc), "remedy": "Reinstall the QCS wheel, restore the locked checkout, or explicitly use --no-windriver"})
    else:
        checks.append({"dependency": "windriver", "status": "disabled", "optional": True})
    try:
        from .guomi import API_PATH, SOURCE_PATH, SIGNATURE_PATH, RULES_PATH, DEVELOPMENT_SOURCE_PATH, DEVELOPMENT_SIGNATURE_PATH
        from .function_signatures import load_database
        from .source_reference import load_references
        from .yara_engine import compiled
        from .model import sha256
        database,_=load_database(str(SIGNATURE_PATH),sha256(SIGNATURE_PATH))
        dev_database,_=load_database(str(DEVELOPMENT_SIGNATURE_PATH),sha256(DEVELOPMENT_SIGNATURE_PATH))
        compiled(str(RULES_PATH),sha256(RULES_PATH))
        json.loads(API_PATH.read_text(encoding="utf-8")); sources=load_references(str(SOURCE_PATH),sha256(SOURCE_PATH))
        checks.append({'dependency':'guomi_module','status':'available',
            'signature_count':len(database['signatures']),'source_modules':len(sources),
            'development_signature_count':len(dev_database['signatures']),
            'development_source_modules':len(load_references(str(DEVELOPMENT_SOURCE_PATH),sha256(DEVELOPMENT_SOURCE_PATH))),
            'api_sha256':sha256(API_PATH),'signatures_sha256':sha256(SIGNATURE_PATH)})
    except Exception as exc:
        checks.append({'dependency':'guomi_module','status':'failed','reason':str(exc)})
    try:
        import capstone
        from .guomi.source_semantics import parser
        parser(False);parser(True)
        checks.append({'dependency':'guomi_operation_parsers','status':'available','capstone_version':capstone.__version__})
    except Exception as exc:
        checks.append({'dependency':'guomi_operation_parsers','status':'failed','reason':str(exc)})
    try:
        from .firmware import binwalk_command, check_binwalk
        text = check_binwalk(tuple(binwalk_command(options)))
        checks.append({"dependency": "binwalk", "status": "available", "optional": True,
            "purpose": "Legacy fallback only; native SquashFS/ESP/gzip adapters do not require Binwalk",
            "version_banner": next((line.strip() for line in text.splitlines() if line.startswith("Binwalk v")), "unknown")})
    except Exception as exc:
        checks.append({"dependency": "binwalk", "status": "missing_or_unsupported", "optional": True, "reason": str(exc),
            "remedy": "Native SquashFS/ESP/gzip remain usable; use pinned Binwalk v2 for the legacy fallback"})
    for tool in ("unsquashfs", "mksquashfs"):
        checks.append({"dependency": tool, "status": "available" if shutil.which(tool) else "missing", "path": shutil.which(tool),
                       "optional": True, "purpose": "SquashFS extraction" if tool == "unsquashfs" else "SquashFS fixture generation only",
                       "remedy": "Install squashfs-tools using your Linux distribution package manager"})
    checks.append({"dependency": "python", "status": "available" if sys.version_info[:2] == (3, 12) else "version_mismatch", "version": sys.version.split()[0], "remedy": "Use Python 3.12; preserve existing virtual environments"})
    ready = all(c["status"] == "available" or c.get("optional") for c in checks)
    available = {c["dependency"] for c in checks if c["status"] == "available"}
    return {"schema_version": "1.0", "checks": checks, "ready": ready,
            "capabilities": {"source": ready, "executable": ready, "firmware_esp_gzip": ready,
                             "firmware_squashfs": ready and "unsquashfs" in available,
                             "squashfs_fixture_build": "mksquashfs" in available}}

def write_json(value, output):
    text = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    else:
        print(text, end="")

def write_scan_csv(report, output):
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as stream:
        fields = ["artifact", "algorithm", "algorithm_category", "evidence_type", "engine", "identifier", "line", "offset", "confidence", "runtime_usage"]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        def walk(r):
            for item in r["findings"]:
                writer.writerow({"artifact": r["input_path"], **{k: item.get(k) for k in fields if k != "artifact"}})
            for child in r["components"]:
                walk(child)
        walk(report)

def main(argv=None):
    # Keep command-line reports readable in minimal Linux images with the C locale.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="QCS static crypto evidence scanner")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("scan", "doctor", "evaluate"):
        p = sub.add_parser(name)
        if name != "doctor":
            p.add_argument("path")
        p.add_argument("--rules", type=Path, default=Options.rules)
        p.add_argument("--binwalk")
        p.add_argument("--windriver-root",type=Path,default=Options.windriver_root)
        p.add_argument("--no-windriver", action="store_true")
        p.add_argument("--timeout", type=float, default=60)
        p.add_argument("--max-files", type=int, default=10000)
        p.add_argument("--max-depth", type=int, default=4)
        p.add_argument("--max-bytes", type=int, default=1024 ** 3)
        p.add_argument("--max-file-bytes", type=int, default=256 * 1024 ** 2)
        if name in {"scan", "doctor"}:
            p.add_argument("--output")
        if name == "doctor":
            p.add_argument("--require-squashfs", action="store_true", help="Fail readiness if the SquashFS extractor is unavailable")
        if name == "scan":
            p.add_argument("--kind", choices=["auto", "source", "executable", "firmware"], default="auto")
            p.add_argument("--csv")
        if name == "evaluate":
            p.add_argument("--output-dir", required=True)
            p.add_argument("--split", choices=["development", "acceptance"], default="acceptance")
    args = parser.parse_args(argv)
    from .paths import output_path
    try:
        for field in ('output', 'csv', 'output_dir'):
            value = getattr(args, field, None)
            if value:
                setattr(args, field, str(output_path(value)))
    except ValueError as exc:
        parser.error(str(exc))
    if min(args.timeout, args.max_files, args.max_depth, args.max_bytes, args.max_file_bytes) <= 0:
        parser.error("Resource limits must be positive")
    options = Options(rules=args.rules.absolute(), binwalk=args.binwalk, windriver_root=args.windriver_root.absolute(), windriver=not args.no_windriver,
        timeout=args.timeout, max_files=args.max_files, max_depth=args.max_depth, max_bytes=args.max_bytes, max_file_bytes=args.max_file_bytes)
    if args.command == "doctor":
        result = doctor(options)
        if args.require_squashfs:
            result["ready"] = result["ready"] and result["capabilities"]["firmware_squashfs"]
            result["required_capabilities"] = ["firmware_squashfs"]
        write_json(result, args.output)
        return 0 if result["ready"] else 2
    if args.command == "scan":
        result = scan(args.path, args.kind, options)
        write_json(result, args.output)
        if args.csv:
            write_scan_csv(result, args.csv)
        return {"completed": 0, "partial": 2, "unsupported": 3, "failed": 4}[result["scan_status"]]
    try:
        from .evaluate import evaluate
        result = evaluate(args.path, args.output_dir, options, args.split)
    except Exception as exc:
        write_json({"schema_version": "1.0", "evaluation_complete": False, "errors": [{"code": "evaluation_error", "message": f"{type(exc).__name__}: {exc}"}]}, Path(args.output_dir) / "summary.json")
        return 4
    print(json.dumps({"evaluation_complete": result["evaluation_complete"], "selected_sample_count": result["selected_sample_count"], "summary": str(Path(args.output_dir) / "summary.json")}, ensure_ascii=False))
    return 0 if result["evaluation_complete"] else 2
