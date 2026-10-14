#!/usr/bin/env python3
"""Stream-verify a portable archive without extracting or executing its inputs."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile

ROOT = Path(__file__).resolve().parents[2]


def main():
    archive = ROOT / "build/dist/ustc_tool_middle.tar.gz"
    catalog = json.loads((ROOT / "build/datasets/catalog.json").read_text(encoding="utf-8"))
    expected = {e["path"]: e["sha256"] for e in catalog["files"]}
    for path in (ROOT / "build/runtime").rglob("*"):
        if path.is_file():
            expected[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    model = ROOT / "build/models/rf-baseline/model.joblib"
    expected[str(model.relative_to(ROOT))] = hashlib.sha256(model.read_bytes()).hexdigest()
    input_paths = set(expected)
    # Verify the current documents and central legal layout as well as inputs.
    for name in ("LICENSE", "readme.md", "todo.md", "pyproject.toml", "MANIFEST.in", "tools/check_licenses.py"):
        expected[name] = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
    legal_paths = []
    for folder in ("licenses", "build/licenses", "src/qcs/guomi/licenses"):
        for path in (ROOT / folder).rglob("*"):
            if path.is_file():
                relative = str(path.relative_to(ROOT))
                expected[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
                legal_paths.append(relative)
    issues = []
    found = set()
    md = []
    files = set()
    with tarfile.open(archive, mode="r|gz") as stream:
        for entry in stream:
            path = PurePosixPath(entry.name)
            if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != ROOT.name:
                issues.append("Unsafe archive path: " + entry.name)
                continue
            if entry.issym() or entry.islnk():
                issues.append("Unexpected archive link: " + entry.name)
            if not entry.isfile():
                continue
            relative = str(PurePosixPath(*path.parts[1:]))
            files.add(relative)
            if relative.endswith(".md"):
                md.append(relative)
                if relative not in {"readme.md", "todo.md"}:
                    issues.append("Unexpected Markdown in archive: " + relative)
            if relative.endswith((".json", ".jsonl", ".log", ".pyc", ".csv", ".joblib", ".whl")) and not relative.startswith("build/"):
                issues.append("Artifact outside build in archive: " + relative)
            if relative in expected:
                h = hashlib.sha256()
                body = stream.extractfile(entry)
                for block in iter(lambda: body.read(1024 * 1024), b""):
                    h.update(block)
                if h.hexdigest() != expected[relative]:
                    issues.append("Archive hash mismatch: " + relative)
                found.add(relative)
    for relative in expected.keys() - found:
        issues.append("Missing archive input: " + relative)
    for required in {"readme.md", "todo.md", "pyproject.toml", "src/qcs/cli.py", "tools/prepare_tests.py"} - files:
        issues.append("Missing required release file: " + required)
    report = {"passed": not issues, "verified_sample_files": len(catalog["files"]),
              "verified_sample_and_runtime_files": len(input_paths & found), "archive_file_count": len(files),
              "verified_total_expected_files": len(found),
              "verified_legal_and_provenance_files": len(legal_paths),
              "verified_current_documents_and_packaging_files": 6,
              "markdown_files": sorted(md), "issues": issues,
              "policy": "Streaming hashes only; no target input executed and no external source required"}
    (ROOT / "build/checks/release-integrity.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
