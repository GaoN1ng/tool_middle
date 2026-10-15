from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from .model import error, finish, new_report, sha256
from .paths import DEFAULT_RULES, DEFAULT_WINDRIVER, WORKSPACE

SOURCE_EXTENSIONS = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx", ".hh"}
JAVASCRIPT_EXTENSIONS = {'.js','.cjs','.mjs'}
TEXT_EXTENSIONS = {".txt", ".conf", ".cfg", ".ini", ".xml", ".json", ".md"}
EXCLUDED_DIRS = {".git", ".venv", ".venv-qcs", ".venv-linux", "__pycache__", "node_modules", ".qcs-cache"}

@dataclass
class Options:
    rules: Path = DEFAULT_RULES
    windriver_root: Path = DEFAULT_WINDRIVER
    windriver: bool = True
    binwalk: str | None = None
    timeout: float = 60
    max_files: int = 10000
    max_depth: int = 4
    max_bytes: int = 1024 * 1024 * 1024
    max_file_bytes: int = 256 * 1024 * 1024

@dataclass
class Budget:
    files: int = 0
    bytes: int = 0
    started: float = field(default_factory=time.monotonic)

def detect_kind(path: Path) -> str:
    if path.is_dir():
        return "directory"
    with path.open("rb") as stream:
        head = stream.read(4096)
    if head.startswith(b"\x7fELF") or head.startswith(b"MZ"):
        return "executable"
    if head.startswith((b"hsqs", b"sqsh", b"UBI#", b"\x27\x05\x19\x56", b"\xd0\x0d\xfe\xed")):
        return "firmware"
    from .firmware_native import is_esp_header
    if is_esp_header(head) or head.startswith(b"\x1f\x8b\x08"):
        return "firmware"
    if b"\0" not in head and path.suffix.lower() in SOURCE_EXTENSIONS | JAVASCRIPT_EXTENSIONS:
        return "source"
    if b"\0" not in head and path.suffix.lower() in TEXT_EXTENSIONS:
        return "text"
    return "unknown"

def run_engine(report, name, action):
    try:
        action()
    except (ImportError, ModuleNotFoundError) as exc:
        error(report, name, "missing_dependency", f"{exc}. Install requirements.lock in an isolated environment and run qcs doctor.")
    except Exception as exc:
        error(report, name, "engine_error", f"{type(exc).__name__}: {exc}")

def scan(path, kind="auto", options=None, *, budget=None, depth=0, firmware_context=None):
    options = options or Options()
    budget = budget or Budget()
    path = Path(path).absolute()
    report = new_report(path, kind)
    if firmware_context:
        report["artifact"].update(firmware_sha256=firmware_context["sha256"], firmware_relative_path=firmware_context["relative_path"])
        report["input_path"] = f"firmware:{firmware_context['sha256']}/{firmware_context['relative_path']}"
        report["extraction_chain"] = list(firmware_context["chain"])
    try:
        if path.is_symlink():
            report["scan_status"] = "unsupported"
            error(report, "dispatch", "symlink", "Symlinks are not followed", "unsupported")
            return finish(report)
        if not path.exists():
            raise FileNotFoundError(str(path))
        detected = detect_kind(path)
        if kind == "auto":
            kind = detected
        report["input_kind"] = kind
        report["artifact"]["kind"] = kind
        if path.is_dir():
            scan_directory(path, kind, report, options, budget, depth)
            return finish(report)
        size = path.stat().st_size
        if size > options.max_file_bytes:
            error(report, "dispatch", "max_file_bytes", f"Input size {size} exceeds {options.max_file_bytes}", "partial")
            report["scan_status"] = "partial"
            return finish(report)
        if budget.files >= options.max_files or budget.bytes + size > options.max_bytes:
            report["scan_status"] = "partial"
            error(report, "dispatch", "resource_limit", "Global file count or byte budget exhausted", "partial")
            return finish(report)
        if time.monotonic() - budget.started > options.timeout:
            report["scan_status"] = "partial"
            error(report, "dispatch", "timeout", "Overall scan deadline exhausted", "partial")
            return finish(report)
        budget.files += 1
        budget.bytes += size
        report["artifact"].update(sha256=sha256(path), size_bytes=size)
        if kind == "text":
            from .source import scan_plain_text
            run_engine(report, "source", lambda: scan_plain_text(path,report))
        elif kind == "source":
            if detected in {"executable", "firmware"}:
                raise ValueError("--kind source conflicts with binary header")
            if path.suffix.lower() in JAVASCRIPT_EXTENSIONS:
                from .guomi.javascript import scan_javascript
                run_engine(report,'guomi_javascript',lambda: scan_javascript(path,report))
            else:
                from .source import scan_source
                from .guomi import scan_c_source
                run_engine(report, "source", lambda: scan_source(path, report))
                run_engine(report,'guomi_source',lambda: scan_c_source(path,report))
                from .guomi.source_semantics import scan_source_semantics
                run_engine(report,'guomi_source_semantic',lambda: scan_source_semantics(path,report))
            if options.windriver and path.suffix.lower() not in JAVASCRIPT_EXTENSIONS:
                from .windriver import scan_windriver
                run_engine(report, "windriver", lambda: scan_windriver(path, report, options.windriver_root))
            else:
                report["engine_status"]["windriver"] = {"status": "disabled"}
        elif kind == "executable":
            from .symbols import scan_symbols
            from .yara_engine import scan_yara
            from .function_signatures import scan_functions
            run_engine(report, "symbol", lambda: scan_symbols(path, report))
            remaining = max(1, options.timeout - (time.monotonic() - budget.started))
            run_engine(report, "yara", lambda: scan_yara(path, report, options.rules, remaining))
            remaining = max(1, options.timeout - (time.monotonic() - budget.started))
            run_engine(report, "function_signature", lambda: scan_functions(path, report, remaining))
            from .guomi import scan_binary
            remaining = max(.001, options.timeout - (time.monotonic() - budget.started))
            run_engine(report,'guomi',lambda: scan_binary(path,report,remaining))
            from .guomi.binary_semantics import scan_binary_semantics
            # The last large lifting pass uses a soft deadline, checked at
            # bounded instruction/path intervals. Leave time for its final
            # summaries, optional-stage dispatch and report serialization.
            reserve=min(2,options.timeout/10)
            remaining = max(.001, options.timeout - (time.monotonic() - budget.started) - reserve)
            run_engine(report,'guomi_semantic',lambda: scan_binary_semantics(path,report,remaining))
            from .semantic_probes import scan_probes
            remaining = max(.001, options.timeout - (time.monotonic() - budget.started))
            run_engine(report,'semantic_probes',lambda: scan_probes(path,report,remaining))
            from .operations import reconcile_shared_sha1
            reconcile_shared_sha1(report)
        elif kind == "firmware":
            from .firmware import scan_firmware
            run_engine(report, "firmware", lambda: scan_firmware(path, report, options, budget, depth))
        else:
            report["scan_status"] = "unsupported"
            error(report, "dispatch", "unknown_file_type", "Unrecognized object; select --kind explicitly if appropriate. This does not mean no crypto.", "unsupported")
        if time.monotonic()-budget.started > options.timeout and report["scan_status"]=="completed":
            report["scan_status"]="partial"
            error(report,"dispatch","timeout","Overall scan deadline exceeded","partial")
    except Exception as exc:
        report["scan_status"] = "failed"
        error(report, "dispatch", "input_error", f"{type(exc).__name__}: {exc}")
    return finish(report)

def scan_directory(path, kind, report, options, budget, depth):
    if kind == "firmware":
        raise ValueError("Firmware input must be an image file")
    tree_hash = hashlib.sha256()
    for directory, dirs, files in os.walk(path, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED_DIRS and not (Path(directory) / d).is_symlink())
        for name in sorted(files):
            child_path = Path(directory) / name
            relative = child_path.relative_to(path).as_posix()
            if budget.files >= options.max_files or time.monotonic() - budget.started > options.timeout:
                report["scan_status"] = "partial"
                error(report, "dispatch", "directory_limit", "File count or scan deadline exhausted", "partial")
                break
            child_kind = detect_kind(child_path) if not child_path.is_symlink() else "unknown"
            # A --kind source tree still records other objects as unsupported.
            selected = kind if kind in {"source", "executable"} and child_kind == kind else "auto"
            child = scan(child_path, selected, options, budget=budget, depth=depth)
            child["artifact"]["relative_path"] = relative
            report["components"].append(child)
            tree_hash.update(relative.encode() + b"\0" + (child["artifact"]["sha256"] or "unhashed").encode() + b"\n")
        if report["scan_status"] == "partial":
            break
    report["artifact"].update(format="directory", sha256=tree_hash.hexdigest(), sha256_method="sorted relative paths plus component SHA-256; partial when traversal incomplete")
    report["engine_status"]["dispatch"] = {"status": "completed"}
