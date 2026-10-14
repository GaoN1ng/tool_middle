#!/usr/bin/env python3
"""Copy the active legacy workspace into a self-contained submission.

This performs packaging only. It does not train, scan validation data, or change
algorithm labels. Run with --source /path/to/legacy/workspace.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import shutil

DEST = Path(__file__).resolve().parents[1]
BUILD = DEST / "build"
COLLECTIONS = [
    "samples/public-benchmark/manifest.json",
    "samples/stripped-repair/manifest.json",
    "samples/guomi-development-20261012/all-manifest.json",
    "samples/guomi-operations-20261012/manifest.json",
    "samples/operation-development-20261013/manifest.json",
    "samples/research-development-20261013/manifest.json",
    "samples/semantic-development-20261013/manifest.json",
    "samples/tinycrypt-environment-20261013/manifest.json",
    "samples/controlflow-development-20261014/manifest.json",
    "samples/controlflow-diversity-addendum-20261014/manifest.json",
    "validation_set/manifest.json",
    "validation_set/guomi-20261012/manifest.json",
    "validation_set/guomi-improved-20261012/manifest.json",
    "validation_set/guomi-operations-20261012/manifest.json",
    "validation_set/operations-independent-20261013/manifest.json",
    "validation_set/semantic-independent-20261013/manifest.json",
    "validation_set/controlflow-independent-20261014/manifest.json",
    "validation_set/rf-independent-20261014/manifest.json",
    "quantum-crypto-scanner/fixtures/manifest.json",
]
BANKS = [
    "rules/source_implementations.json", "guomi/source_references.json",
    "guomi/development_source_references.json", "rules/function_signatures.json",
    "guomi/function_signatures.json", "guomi/development_function_signatures.json",
    "rules/static_primitives.json",
]


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def copy(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists() or sha(source) != sha(target):
        shutil.copy2(source, target)


def category(path, kind=None):
    with path.open("rb") as stream:
        magic = stream.read(8)
    if kind == "firmware" or path.suffix.lower() in {".bin", ".img", ".squashfs", ".gz", ".ota"}:
        return "firmware_samples"
    if magic[:4] == b"\x7fELF":
        return "elf_samples"
    if magic[:2] == b"MZ":
        return "exe_samples"
    return "code_samples"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve()
    project = source / "quantum-crypto-scanner"
    for split in ("test_set", "val_set"):
        for cat in ("code_samples", "elf_samples", "exe_samples", "firmware_samples"):
            (DEST / "Samples" / split / cat).mkdir(parents=True, exist_ok=True)
    records = {}
    missing = []
    conflicts = []
    manifests = {}
    metadata = {}
    aliases = {}
    input_digests = {}

    def add(path, role, *, kind=None, use=None, expected=None):
        path = path.resolve()
        if not path.is_file():
            missing.append({"path": str(path.relative_to(source)), "role": role})
            return
        origin = str(path.relative_to(source))
        digest = input_digests.setdefault(path, None)
        if digest is None:
            digest = input_digests[path] = sha(path)
        if expected and digest != expected:
            raise ValueError(f"Input hash mismatch: {origin}")
        entry = records.setdefault(digest, {"sha256": digest, "bytes": path.stat().st_size,
            "category": category(path, kind), "origins": [], "roles": [], "uses": []})
        if origin not in entry["origins"]:
            entry["origins"].append(origin)
        if role not in entry["roles"]:
            entry["roles"].append(role)
        if use and use not in entry["uses"]:
            entry["uses"].append(use)
        aliases[origin] = digest

    # Active manifests only; interrupted/retry snapshots are not extra samples.
    for relative in COLLECTIONS:
        path = source / relative
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifests[relative] = manifest
        for row in manifest["samples"]:
            role = "historical_validation" if relative.startswith("validation_set/") else "development_or_regression"
            add(path.parent / row["path"], role, kind=row["kind"], expected=row.get("sha256"),
                use={"manifest": relative, "id": row["id"], "historical_split": row.get("split"),
                     "truth": row.get("truth"), "known_algorithms": manifest.get("algorithms", []),
                     "project": row.get("project"), "family": row.get("family")})
        metadata[relative] = path

    reference_aliases = {}
    def reference_source(origin, expected):
        candidate = source / origin
        if not candidate.is_file() and expected in records:
            candidate = source / records[expected]["origins"][0]
            reference_aliases[origin + "@" + expected] = str(candidate.relative_to(source))
        if not candidate.is_file():
            for found in (source / "samples").rglob(Path(origin).name):
                if found.is_file() and sha(found) == expected:
                    candidate = found
                    reference_aliases[origin + "@" + expected] = str(candidate.relative_to(source))
                    break
        add(candidate, "reference_bank", expected=expected)

    # Every file that actually contributed to shipped source/function banks.
    for relative in BANKS:
        bank = json.loads((project / "qcs" / relative).read_text(encoding="utf-8"))
        for ref in bank.get("references", []):
            info = ref["source"]
            add(source / info["path"], "reference_bank", expected=info.get("sha256"))
        for signature in bank.get("signatures", []):
            ref = signature["reference"]
            add(source / ref["artifact"], "reference_bank", expected=ref.get("sha256"))
            source_hashes = ref.get("source_hashes", {})
            if not isinstance(source_hashes, dict):
                source_hashes = {}
            for origin, expected in source_hashes.items():
                reference_source(origin, expected)

    # Regression fixtures and already-integrated team inputs. No archives or
    # Windows environments from other_ref are needed at runtime.
    extra_trees = [
        "quantum-crypto-scanner/fixtures",
        "quantum-crypto-scanner/artifacts/coverage-fixes-20261012/negative-controls",
        "quantum-crypto-scanner/artifacts/coverage-fixes-20261012/xtensa",
        "quantum-crypto-scanner/artifacts/guomi-integration-20261012/provided",
        "quantum-crypto-scanner/artifacts/guomi-integration-20261012/verification",
        "quantum-crypto-scanner/artifacts/guomi-sm2-fix-20261012/portability",
        "samples/public-benchmark/firmware",
    ]
    source_suffixes = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".js", ".cjs", ".mjs", ".rs", ".inc", ".S", ".s"}
    binary_suffixes = {".so", ".elf", ".exe", ".dll", ".o", ".out", ".a", ".bin", ".img", ".squashfs", ".gz"}
    for relative in extra_trees:
        for path in (source / relative).rglob("*"):
            if not path.is_file() or any(p in {"__pycache__", ".git", "node_modules"} for p in path.parts):
                continue
            if path.suffix in source_suffixes | binary_suffixes:
                add(path, "regression_support")
            elif path.suffix == ".json" and (path.name == "manifest.json" or path.name.endswith("-manifest.json")):
                metadata[str(path.relative_to(source))] = path
    for relative in [
        "third_party/crypto-detection/example/sha1/sha1test.out",
        "third_party/mbedtls/library/sha1.c",
        "quantum-crypto-scanner/artifacts/guomi-integration-20261012/upstream/gmssl/src/sm3.c",
        "quantum-crypto-scanner/artifacts/guomi-integration-20261012/upstream/gmssl/src/sm4.c",
        "quantum-crypto-scanner/artifacts/guomi-integration-20261012/upstream/gmssl/src/sm2_sign.c",
        "quantum-crypto-scanner/artifacts/guomi-integration-20261012/upstream/gmssl/src/sm2_enc.c",
    ]:
        add(source / relative, "regression_support")
    for relative in [
        "samples/guomi-development-20261012/control-manifest.json",
        "quantum-crypto-scanner/artifacts/guomi-sm2-fix-20261012/portability-manifest.json",
        "quantum-crypto-scanner/artifacts/guomi-sm2-fix-20261012/before-function-signatures.json",
        "quantum-crypto-scanner/artifacts/guomi-integration-20261012/verification/relinked-manifest.json",
    ]:
        metadata[relative] = source / relative
    # Annotation siblings retain symbol-to-function alignment offline. They do
    # not become additional independent evaluation observations.
    for entry in list(records.values()):
        if entry["category"] != "elf_samples" or "historical_validation" in entry["roles"]:
            continue
        for origin in list(entry["origins"]):
            for name in ("inspection.so", "unstripped.so", "symbolic.so"):
                sibling = (source / origin).parent / name
                if sibling.is_file():
                    add(sibling, "offline_annotation_support")

    # Retain local headers belonging to selected source units and ancestor
    # license notices. Preserve source notices; do not relicense samples.
    for entry in list(records.values()):
        if entry["category"] != "code_samples":
            continue
        for origin in list(entry["origins"]):
            path = source / origin
            role = "historical_validation" if entry["roles"] == ["historical_validation"] else "development_support"
            for header in path.parent.iterdir():
                if header.is_file() and header.suffix in {".h", ".hpp", ".inc"}:
                    add(header, role)
            for parent in path.parents:
                if parent == source:
                    break
                for notice in parent.iterdir():
                    if notice.is_file() and notice.name.lower().startswith(("license", "licence", "copying", "copyright", "notice")):
                        rel = notice.relative_to(source)
                        target = DEST / "licenses" / "samples" / rel
                        if target.suffix.lower() == ".md":
                            target = target.with_suffix(".txt")
                        copy(notice, target)

    mixed = []
    for digest, entry in sorted(records.items()):
        is_validation = "historical_validation" in entry["roles"]
        used_dev = any(r not in {"historical_validation"} for r in entry["roles"])
        split = "val_set" if is_validation and not used_dev else "test_set"
        entry["assigned_split"] = split
        entry["has_development_validation_overlap"] = is_validation and used_dev
        if entry["has_development_validation_overlap"]:
            mixed.append(digest)
        # Hash directory deduplicates byte-identical inputs while preserving a
        # useful extension and basename; origin aliases remain in the catalog.
        origin = entry["origins"][0]
        target = DEST / "Samples" / split / entry["category"] / digest[:2] / digest[:16] / Path(origin).name
        copy(source / origin, target)
        entry["path"] = str(target.relative_to(DEST))
        if sha(target) != digest:
            raise ValueError(f"Copy hash mismatch: {target}")

    # Copy historical manifests verbatim under build, and generate runnable
    # manifests that resolve into the organized Samples directory.
    for relative, path in metadata.items():
        target = BUILD / "datasets" / "original_manifests" / relative
        copy(path, target)
    for relative, manifest in manifests.items():
        name = relative.replace("/", "__")
        output = BUILD / "datasets" / "manifests" / name
        normalized = {**manifest, "organization": {"original_manifest": relative,
            "note": "Historical evaluated data; organization is not a new independent experiment. Original split retained separately; physical role follows all known development uses."}}
        rows = []
        for row in manifest["samples"]:
            logical = str((source / relative).parent.joinpath(row["path"]).resolve().relative_to(source))
            entry = records[aliases[logical]]
            defaults = {"build": "Historical manifest; original build metadata retained", "terminal_business_type": None,
                        "compiler_flags": [], "symbol_state": "unknown", "architecture": "unknown"}
            annotation = next((str((source / logical).parent.joinpath(name).relative_to(source))
                for name in ("inspection.so", "unstripped.so", "symbolic.so")
                if str((source / logical).parent.joinpath(name).relative_to(source)) in aliases), None)
            annotation_path = os.path.relpath(DEST / records[aliases[annotation]]["path"], output.parent) if annotation else None
            rows.append({**defaults, **row, "historical_split": row.get("split"),
                "split": "development" if entry["assigned_split"] == "test_set" else "acceptance",
                "path": os.path.relpath(DEST / entry["path"], output.parent),
                "annotation_path": annotation_path,
                "organization_overlap": entry["has_development_validation_overlap"]})
        normalized["samples"] = rows
        write(output, normalized)

    # Generated compatibility aliases are strictly internal. Regression tests
    # can retain historical logical fixture paths without depending on originals.
    compatibility = BUILD / "testing" / "workspace"
    for origin, digest in sorted(aliases.items()):
        link = compatibility / origin
        target = DEST / records[digest]["path"]
        link.parent.mkdir(parents=True, exist_ok=True)
        if not link.is_symlink() and link.exists():
            raise ValueError(f"Refusing to replace compatibility path: {link}")
        link.unlink(missing_ok=True)
        link.symlink_to(os.path.relpath(target, link.parent))
    for relative in metadata:
        link = compatibility / relative
        target = BUILD / "datasets" / "original_manifests" / relative
        link.parent.mkdir(parents=True, exist_ok=True)
        link.unlink(missing_ok=True)
        link.symlink_to(os.path.relpath(target, link.parent))

    # Runtime code/resources: JSON is an artifact, so it lives under build.
    runtime_inputs = []
    for path in (project / "qcs").rglob("*"):
        if not path.is_file() or "__pycache__" in path.parts or path.suffix.lower() in {".md", ".pyc"}:
            continue
        relative = path.relative_to(project / "qcs")
        target = BUILD / "runtime" / "qcs" / relative if path.suffix == ".json" else DEST / "src" / "qcs" / relative
        copy(path, target)
        runtime_inputs.append({"original": str(path.relative_to(source)), "sha256": sha(path), "path": str(target.relative_to(DEST))})
    copy(project / "qcs/guomi/constants.yar", BUILD / "runtime/qcs/guomi/constants.yar")
    for path in (project / "tests").glob("test_*.py"):
        copy(path, DEST / "tests" / path.name)
    for name in ("pe_fixture.py", "build_function_signatures.py"):
        copy(project / "tools" / name, DEST / "tools/legacy" / name)
    for name in ("features", "rf", "curate", "dataset", "audit_dataset", "learn"):
        copy(project / "ml_rf" / (name + ".py"), DEST / "src/qcs_ml" / (name + ".py"))
    for name in ("test_features.py", "test_learning.py"):
        copy(project / "ml_rf" / name, DEST / "tests" / ("test_ml_" + name[5:]))
    copy(project / "LICENSE", DEST / "LICENSE")
    copy(project / "requirements.lock", DEST / "requirements.lock")
    copy(project / "ml_rf/requirements.txt", DEST / "requirements-ml.lock")

    # Frozen RF weights and audit summaries: preserve bytes, no retraining.
    rf = project / "artifacts/rf-baseline-20261014"
    for path in (rf / "frozen").iterdir():
        if path.is_file() and path.suffix != ".md":
            copy(path, BUILD / "models/rf-baseline" / path.name)
    for name in ("annotation-audit.json", "dataset-summary.json", "development-inputs.json", "function-inventory.json", "function-truth.json",
                 "development-results.json", "independent-results.json", "protocol.json", "primary-rescues.json", "integrity-final.json"):
        copy(rf / name, BUILD / "history/rf-baseline" / name)
    write(BUILD / "datasets/catalog.json", {"schema_version": "1.0", "source_workspace": str(source),
        "policy": "Content deduplication; development use overrides historical validation. Cases/labels remain collection-scoped; file counts are not independent author counts.",
        "files": list(records.values())})
    counts = Counter((e["assigned_split"], e["category"]) for e in records.values())
    report = {"unique_files": len(records), "bytes": sum(e["bytes"] for e in records.values()),
        "logical_input_paths": len(aliases), "active_manifests": len(manifests),
        "counts": {f"{split}/{cat}": count for (split, cat), count in sorted(counts.items())},
        "overlap_files": len(mixed), "overlap_sha256": mixed, "missing_inputs": missing,
        "conflicts": conflicts, "runtime_originals": runtime_inputs, "reference_source_aliases": reference_aliases,
        "not_migrated": ["essay", "other_ref original archives", "old virtualenvs/toolchains", "interrupted runs", "historical Markdown", "1.5GiB regenerable RF feature JSONL"]}
    write(BUILD / "datasets/migration-report.json", report)
    print(json.dumps({k: v for k, v in report.items() if k not in {"runtime_originals", "overlap_sha256"}}, ensure_ascii=False, indent=2))
    if missing:
        raise SystemExit("Unresolved input paths; see build/datasets/migration-report.json")


if __name__ == "__main__":
    main()
