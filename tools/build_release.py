#!/usr/bin/env python3
"""Build a portable submission archive, including required build artifacts."""
import hashlib
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {"cache", "tmp", "dist", "lib", "bdist.linux-x86_64", "testing", "venv", "venv-ml", "isolated-install"}


def main():
    output = ROOT / "build/dist/ustc_tool_middle.tar.gz"
    output.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with tarfile.open(output, "w:gz", compresslevel=6) as archive:
        for path in sorted(ROOT.rglob("*")):
            rel = path.relative_to(ROOT)
            if "__pycache__" in rel.parts or path.suffix == ".pyc":
                continue
            if rel.parts[0] == "build" and len(rel.parts) > 1 and (
                rel.parts[1] in EXCLUDED or rel.parts[1].endswith(".egg-info")):
                continue
            if path.is_dir() and not path.is_symlink():
                archive.add(path, arcname=str(Path(ROOT.name) / rel), recursive=False)
            elif path.is_file() and not path.is_symlink():
                archive.add(path, arcname=str(Path(ROOT.name) / rel), recursive=False)
                count += 1
    h = hashlib.sha256()
    with output.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    report = {"archive": output.name, "sha256": h.hexdigest(), "bytes": output.stat().st_size, "file_count": count,
        "excluded_generated_directories": sorted(EXCLUDED),
        "test_workspace": "Regenerate with tools/prepare_tests.py; all inputs included"}
    (output.parent / "release.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
