#!/usr/bin/env python3
"""Verify sample hashes, manifest targets, output placement and internal links."""
from collections import Counter
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    issues = []
    catalog = json.loads((ROOT / "build/datasets/catalog.json").read_text(encoding="utf-8"))
    entries = catalog["files"]
    digests = {}
    for entry in entries:
        path = ROOT / entry["path"]
        digest = sha(path)
        digests[path.resolve()] = digest
        if digest != entry["sha256"]:
            issues.append("Sample digest mismatch: " + entry["path"])
    manifest_cases = 0
    for manifest in (ROOT / "build/datasets/manifests").glob("*.json"):
        m = json.loads(manifest.read_text(encoding="utf-8"))
        for row in m["samples"]:
            manifest_cases += 1
            path = (manifest.parent / row["path"]).resolve()
            if digests.get(path) != row["sha256"]:
                issues.append(f"Manifest target/hash mismatch: {manifest.name}:{row['id']}")
    for path in ROOT.rglob("*"):
        rel = path.relative_to(ROOT)
        # Local venvs point to their installed system Python and are excluded
        # from the portable archive. Fixture aliases must still be internal.
        if rel.parts[0] == 'build' and len(rel.parts) > 1 and (
            rel.parts[1].startswith('venv') or rel.parts[1] in {'isolated-install', 'cache', 'tmp'}):
            continue
        if path.is_symlink():
            if not path.resolve().is_relative_to(ROOT) or not path.exists():
                issues.append("External or broken symlink: " + str(rel))
            continue
        if not path.is_file():
            continue
        if rel.parts[0] == "build":
            continue
        if path.suffix.lower() == ".md" and rel not in {Path("readme.md"), Path("todo.md")}:
            issues.append("Unexpected Markdown: " + str(rel))
        if path.suffix.lower() in {".json", ".jsonl", ".pyc", ".log", ".csv", ".joblib", ".whl"}:
            issues.append("Generated artifact outside build/: " + str(rel))
        if path.suffix in {".bin", ".img", ".squashfs", ".so", ".elf", ".exe", ".dll", ".o"} and rel.parts[0] != "Samples":
            issues.append("Unexpected binary outside Samples/build: " + str(rel))
    report = {"passed": not issues, "verified_unique_sample_files": len(entries),
        "verified_manifest_cases": manifest_cases,
        "counts": dict(Counter(e["assigned_split"] + "/" + e["category"] for e in entries)),
        "issues": issues}
    output = ROOT / "build/checks/integrity.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
