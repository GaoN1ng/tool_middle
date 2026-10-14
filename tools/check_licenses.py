#!/usr/bin/env python3
"""Verify preserved license bytes, provenance mappings and local package copies."""
from collections import Counter
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    catalog = json.loads((ROOT / "build/licenses/catalog.json").read_text(encoding="utf-8"))
    issues = []
    index = (ROOT / "licenses/INDEX.txt").read_text(encoding="utf-8")
    targets = set()
    originals = set()
    retained = 0
    for row in catalog["records"]:
        target = ROOT / row["path"]
        targets.add(row["path"])
        if not target.resolve().is_relative_to(ROOT):
            issues.append("License outside submission: " + row["path"])
            continue
        if not target.is_file() or target.stat().st_size != row["bytes"] or digest(target) != row["sha256"]:
            issues.append("License bytes missing/changed: " + row["path"])
        if row["path"] not in index:
            issues.append("License absent from index: " + row["path"])
        if row["original_path"] in originals:
            issues.append("Duplicate original mapping: " + row["original_path"])
        originals.add(row["original_path"])
        if row["retained_original"]:
            retained += 1
            local = ROOT / row["original_path"]
            if not local.is_file() or digest(local) != row["sha256"]:
                issues.append("Resource-local license changed/missing: " + row["original_path"])
    actual = {str(p.relative_to(ROOT)) for p in (ROOT / "licenses").rglob("*") if p.is_file()}
    expected = {p for p in targets if p.startswith("licenses/")} | {"licenses/INDEX.txt", "licenses/NOTICE.txt"}
    for path in sorted(actual ^ expected):
        issues.append("Unindexed or missing central license: " + path)
    before = ROOT / "build/checks/metrics-license-before.json"
    if before.is_file():
        baseline = json.loads(before.read_text(encoding="utf-8"))
        mapping = {row["original_path"]: row for row in catalog["records"]}
        for row in baseline["legal_files"]:
            current = mapping.get(row["path"])
            if current is None or current["sha256"] != row["sha256"]:
                issues.append("Original legal text lost/changed: " + row["path"])
    report = {"passed": not issues, "verified_origin_mappings": len(originals),
              "unique_central_legal_files": len(expected) - 2,
              "verified_retained_originals": retained,
              "sample_projects": len(catalog["sample_projects"]),
              "origin_mappings_by_category": dict(Counter(r["category"] for r in catalog["records"])),
              "issues": issues}
    output = ROOT / "build/checks/licenses.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
