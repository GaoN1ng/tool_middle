#!/usr/bin/env python3
"""Stage an internal fixture workspace; no dependency on the legacy workspace."""
import json
import os
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]


def prepare():
    workspace = ROOT / "build/testing/workspace"
    package = ROOT / "build/testing/package/qcs"
    shutil.copytree(ROOT / "src/qcs", package, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copytree(ROOT / "build/runtime/qcs", package, dirs_exist_ok=True)
    catalog = json.loads((ROOT / "build/datasets/catalog.json").read_text(encoding="utf-8"))
    for entry in catalog["files"]:
        for origin in entry["origins"]:
            link = workspace / origin
            link.parent.mkdir(parents=True, exist_ok=True)
            link.unlink(missing_ok=True)
            os.link(ROOT / entry["path"], link)
    for original in (ROOT / "build/datasets/original_manifests").rglob("*"):
        if original.is_file():
            link = workspace / original.relative_to(ROOT / "build/datasets/original_manifests")
            link.parent.mkdir(parents=True, exist_ok=True)
            link.unlink(missing_ok=True)
            os.link(original, link)
    for relative, target in {
        "quantum-crypto-scanner/qcs": package,
        "quantum-crypto-scanner/tools": ROOT / "tools/legacy",
        "qcs": ROOT / "bin/qcs",
    }.items():
        link = workspace / relative
        link.parent.mkdir(parents=True, exist_ok=True)
        link.unlink(missing_ok=True)
        link.symlink_to(os.path.relpath(target, link.parent))
    print("Prepared internal regression workspace:", workspace)


if __name__ == "__main__":
    prepare()
