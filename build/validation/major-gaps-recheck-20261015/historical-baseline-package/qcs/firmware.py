from __future__ import annotations

import getpass
import re
import shutil
import sys
import tempfile
import time
from functools import lru_cache
from pathlib import Path

from .model import error
from .process import bounded_run

def binwalk_command(options):
    if options.binwalk:
        return [options.binwalk]
    installed = shutil.which("binwalk")
    if installed:
        return [installed]
    local = Path(__file__).resolve().parents[1] / "tools/binwalk_compat.py"
    upstream = Path(__file__).resolve().parents[2] / "third_party/binwalk/src/binwalk"
    if upstream.is_dir():
        return [sys.executable, str(local)]
    raise ModuleNotFoundError("Binwalk missing; restore pinned Binwalk 2.3.4 and capstone, or use --binwalk PATH")

@lru_cache(maxsize=4)
def check_binwalk(command):
    result = bounded_run(list(command) + ["--help"], timeout=10)
    help_text = result["output"]
    required = ["--extract", "--directory", "--include", "--count", "--size"]
    if result["returncode"] or any(flag not in help_text for flag in required):
        raise RuntimeError("Binwalk help did not validate the supported v2 command; v3 adapter not implemented: " + help_text[:1500])
    return help_text

def scan_firmware(path, report, options, budget, depth):
    from .scanner import scan
    if depth >= options.max_depth:
        report["scan_status"] = "partial"
        error(report, "firmware", "max_depth", f"Extraction depth limit {options.max_depth} reached", "partial")
        return
    from .firmware_native import scan_native
    if scan_native(path, report, options, budget, depth):
        return
    command = binwalk_command(options)
    help_text = check_binwalk(tuple(command))
    report["versions"]["binwalk"] = {"command": command, "version_banner": next((line.strip() for line in help_text.splitlines() if line.startswith("Binwalk v")), "unknown"),
        "adapter": "v2 help-validated; SquashFS extraction only",
        "vendored_tag": "v2.3.4" if len(command) > 1 else None,
        "vendored_commit": "cddfede795971045d99422bd7a9676c8803ec5ee" if len(command) > 1 else None}
    if not shutil.which("unsquashfs"):
        raise ModuleNotFoundError("unsquashfs missing; install squashfs-tools (mksquashfs also needed for fixture builds)")
    # Only run the reviewed SquashFS extractor. Other filesystems remain explicit boundaries.
    report["coverage_notes"].append("Firmware extraction supports Binwalk v2 + standard SquashFS. UBI/JFFS2, encrypted/obfuscated images and Binwalk v3 are outside this adapter's tested scope.")
    with tempfile.TemporaryDirectory(prefix="qcs-firmware-") as temp:
        output = Path(temp)
        remaining = options.timeout - (time.monotonic() - budget.started)
        argv = command + ["--extract", "--include", "squashfs", "--directory", str(output),
            "--count", str(options.max_files - budget.files), "--size", str(options.max_bytes - budget.bytes), str(path)]
        if hasattr(__import__("os"), "geteuid") and __import__("os").geteuid() == 0:
            if "--run-as" not in help_text:
                raise RuntimeError("Binwalk does not advertise --run-as for this root environment")
            argv[ len(command):len(command) ] = ["--run-as", getpass.getuser()]
        result = bounded_run(argv, timeout=max(.1, remaining), cwd=output, monitor=output,
            max_files=options.max_files - budget.files, max_bytes=options.max_bytes - budget.bytes)
        # Keep logs with stable paths, never dangling temporary paths.
        report["extraction_log"] = result["output"].replace(str(output), "<extraction-root>")
        hits = [{"offset": int(m[1]), "description": m[2].strip()} for m in re.finditer(r"^\s*(\d+)\s+0x[0-9a-fA-F]+\s+(.*[Ss]quashfs.*)$", result["output"], re.M)]
        report["extraction_chain"].append({"engine": "binwalk", "input_sha256": report["artifact"]["sha256"], "signatures": hits, "depth": depth})
        if result["limit"]:
            report["scan_status"] = "partial"
            error(report, "firmware", "extraction_limit", f"Extraction stopped at {result['limit']}", "partial")
        elif result["returncode"]:
            report["scan_status"] = "failed"
            error(report, "firmware", "extraction_failed", f"Binwalk exit {result['returncode']}; see extraction_log")
        roots = sorted(p for p in output.rglob("squashfs-root*") if p.is_dir() and not p.is_symlink())
        # Do not count carved copies of the input as scanned components.
        roots = [p for p in roots if not any(parent in roots for parent in p.parents)]
        if not roots:
            if not result["limit"]:
                report["scan_status"] = "failed" if hits else "unsupported"
                error(report, "firmware", "no_extracted_filesystem", "No usable SquashFS filesystem extracted; no conclusion about crypto", "failed" if hits else "unsupported")
            return
        root_sha = report["artifact"].get("firmware_sha256", report["artifact"]["sha256"])
        report["artifact"].update(format="firmware/SquashFS", firmware_sha256=root_sha)
        for fsroot in roots:
            import os
            for directory, dirs, files in os.walk(fsroot, followlinks=False):
                dirs[:] = sorted(d for d in dirs if not (Path(directory) / d).is_symlink())
                for name in sorted(files):
                    component_path = Path(directory) / name
                    inside_path = component_path.relative_to(fsroot).as_posix()
                    relative = inside_path if len(roots)==1 else fsroot.name + "/" + inside_path
                    if report["artifact"].get("firmware_relative_path"):
                        relative = report["artifact"]["firmware_relative_path"] + "!/" + relative
                    child = scan(component_path, "auto", options, budget=budget, depth=depth + 1,
                        firmware_context={"sha256": root_sha, "relative_path": relative, "chain": report["extraction_chain"]})
                    child["artifact"].update(firmware_sha256=root_sha, container_sha256=report["artifact"]["sha256"], firmware_relative_path=relative)
                    child["artifact"].update(filesystem_relative_path=inside_path,
                        extracted_relative_path=component_path.relative_to(output).as_posix(),
                        filesystem_image_offset=hits[0]["offset"] if len(hits)==1 else None)
                    report["components"].append(child)
        if not report["components"]:
            report["scan_status"] = "unsupported"
            error(report, "firmware", "empty_filesystem", "Extracted filesystem has no scannable files", "unsupported")
        report["engine_status"].setdefault("firmware", {"status": "completed", "duration_seconds": result["duration_seconds"]})
