from __future__ import annotations

import hashlib
import platform
from datetime import datetime, timezone
from pathlib import Path

from . import __version__

ALGORITHMS = {
    "AES": "symmetric", "DES": "symmetric", "3DES": "symmetric",
    "RC4": "symmetric", "ChaCha20": "symmetric",
    "RSA": "asymmetric", "ECDSA": "asymmetric", "ECDH": "asymmetric",
    "DH": "asymmetric", "DSA": "asymmetric", "Ed25519": "asymmetric",
    "MD5": "hash", "SHA-1": "hash", "SHA-256": "hash",
    "SHA-512": "hash", "SHA-3": "hash", "HMAC": "mac", "Base64": "encoding",
    "SM2": "asymmetric", "SM3": "hash", "SM4": "symmetric",
}
CORE_ALGORITHMS = ["AES", "DES", "RC4", "ChaCha20", "RSA", "ECDSA", "ECDH", "MD5", "SHA-1", "SHA-256"]

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def new_report(path: Path, kind: str) -> dict:
    return {
        "schema_version": "1.0", "input_path": str(path), "input_kind": kind,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": {"name": "qcs", "version": __version__, "python": platform.python_version()}, "versions": {},
        "artifact": {"kind": kind, "format": None, "architecture": None,
                     "sha256": None, "firmware_relative_path": None},
        "scan_status": "completed", "engine_status": {}, "errors": [],
        "coverage_notes": ["Static evidence does not prove runtime use or absence of crypto."],
        "extraction_chain": [], "findings": [], "algorithm_assets": [],
        "clues": [], "dependencies": [], "components": [],
    }

def error(report: dict, engine: str, code: str, message: str, status: str = "failed") -> None:
    report["errors"].append({"engine": engine, "code": code, "message": message})
    report["engine_status"][engine] = {"status": status, "reason": message}

def evidence(algorithm: str | None, engine: str, kind: str, identifier: str, **extra) -> dict:
    item = {"algorithm": algorithm,
            "algorithm_category": ALGORITHMS.get(algorithm, "unknown"),
            "candidate_algorithms": [], "engine": engine, "evidence_type": kind,
            "identifier": identifier, "line": None, "offset": None,
            "confidence": "low", "confidence_reason": "Unresolved clue",
            "runtime_usage": "unknown", "usage": "key_agreement" if algorithm in {"DH", "ECDH"} else None}
    item.update(extra)
    if algorithm in {"ECDSA","DSA"}:
        item["usage"]="signature"
    elif algorithm in {"RSA","SM2"} and kind in {"source_api","binary_symbol"}:
        if "sign" in identifier.lower() or "verify" in identifier.lower():
            item["usage"]="signature"
        elif "encrypt" in identifier.lower() or "decrypt" in identifier.lower():
            item["usage"]="encryption"
    return item

def finish(report: dict) -> dict:
    for item in report["findings"] + report["clues"]:
        item["artifact_path"] = report["input_path"]
    groups = {}
    for item in all_evidence(report):
        algo = item["algorithm"]
        if not algo or item["algorithm_category"] in {"encoding", "unknown"}:
            continue
        groups.setdefault(algo, []).append(item)
    rank = {"low": 0, "medium": 1, "high": 2}
    report["algorithm_assets"] = [{
        "algorithm": algo, "algorithm_category": ALGORITHMS[algo],
        "confidence": max((x["confidence"] for x in items), key=rank.get),
        "confidence_reason": "Strongest rule basis retained; evidence count is not a probability.",
        "evidence_count": len(items), "evidence": items, "runtime_usage": "unknown",
    } for algo, items in sorted(groups.items())]
    if report["scan_status"] == "completed":
        states = [x["status"] for x in report["engine_status"].values() if x["status"] != "disabled"]
        children = [x["scan_status"] for x in report["components"]]
        if report["errors"] or any(s in {"failed", "partial", "unsupported"} for s in states + children):
            good = any(s == "completed" for s in states + children)
            report["scan_status"] = "partial" if good else "failed"
    return report

def all_evidence(report: dict):
    yield from report["findings"]
    for child in report["components"]:
        yield from all_evidence(child)

def predictions(report: dict, scope: str) -> set[str]:
    result = set()
    for item in all_evidence(report):
        if not item["algorithm"] or item["algorithm_category"] in {"unknown", "encoding"}:
            continue
        if scope == "api_reference":
            use = (item["evidence_type"] == "source_api" and item.get("source_role") == "call") or (
                item["evidence_type"] == "binary_symbol" and item.get("symbol_status") == "import")
        else:
            use = item["evidence_type"] in {"binary_constant", "binary_instruction", "binary_function_signature"} or (
                item['evidence_type']=='source_operation_graph' and
                item.get('engine') in {'guomi_source_semantic','operation_source'} and
                item.get('source_role')=='definition' and
                item.get('implementation_verification')=='bounded_standard_operation_graph' and
                bool(item.get('operation_witnesses'))) or (
                item["evidence_type"] == "binary_symbol" and item.get("symbol_status") == "defined") or (
                item["evidence_type"] == "source_implementation" and
                item.get("implementation_verification") == "pinned_source_sha256" and
                bool(item.get("source_sha256")) and
                item["source_sha256"] == item.get("reference_source", {}).get("sha256"))
        if use:
            result.add(item["algorithm"])
    return result
