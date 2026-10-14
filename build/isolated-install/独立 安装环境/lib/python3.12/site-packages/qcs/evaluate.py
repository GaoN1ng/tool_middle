from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path

from .model import ALGORITHMS, CORE_ALGORITHMS, predictions, sha256
from .scanner import Options, scan

def metrics(rows, algorithms):
    per_algorithm = {}
    for algo in algorithms:
        counts = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
        for row in rows:
            actual, predicted = algo in row["truth"], algo in row["predicted"]
            counts["TP" if actual and predicted else "FN" if actual else "FP" if predicted else "TN"] += 1
        tp, fp, fn, tn = (counts[k] for k in ("TP", "FP", "FN", "TN"))
        counts.update(precision=tp / (tp + fp) if tp + fp else None,
            recall=tp / (tp + fn) if tp + fn else None,
            f1=2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
            accuracy=(tp + tn) / len(rows) if rows else None,
            positive_samples=tp + fn, negative_samples=fp + tn,
            positive_fraction=(tp + fn) / len(rows) if rows else None)
        per_algorithm[algo] = counts
    sums = {k: sum(v[k] for v in per_algorithm.values()) for k in ("TP", "FP", "FN", "TN")}
    tp, fp, fn, tn = (sums[k] for k in ("TP", "FP", "FN", "TN"))
    return {"sample_count": len(rows), "completed_count": sum(r["scan_status"] == "completed" for r in rows),
        "scan_completion_rate": sum(r["scan_status"] == "completed" for r in rows) / len(rows) if rows else None,
        "file_exact_match_rate": sum(r["truth"] == r["predicted"] and r["scan_status"] == "completed" for r in rows) / len(rows) if rows else None,
        "micro": {**sums, "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
            "accuracy": (tp + tn) / (tp + fp + fn + tn) if tp + fp + fn + tn else None},
        "per_algorithm": per_algorithm}

def evaluate(manifest_path, output_dir, options=None, split="acceptance"):
    manifest_path, output_dir = Path(manifest_path).absolute(), Path(output_dir).absolute()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    algorithms = manifest.get("algorithms", CORE_ALGORITHMS)
    if len(set(algorithms)) != len(algorithms) or any(a not in ALGORITHMS or ALGORITHMS[a] == "encoding" for a in algorithms):
        raise ValueError("Invalid metric algorithm universe")
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "reports").mkdir(exist_ok=True)
    rows, boundaries, issues = [], [], []
    selected = [s for s in manifest["samples"] if s["split"] == split]
    if not selected:
        raise ValueError(f"No samples in split {split}")
    seen = set()
    for sample in selected:
        sid = sample["id"]
        if sid in seen or not sid.replace("-", "").replace("_", "").isalnum():
            raise ValueError("Duplicate or unsafe sample id")
        seen.add(sid)
        for field in ("source", "license", "build", "truth_basis", "kind", "architecture", "compiler_flags", "sha256", "terminal_business_type", "symbol_state", "truth"):
            if field not in sample:
                raise ValueError(f"{sid}: missing manifest field {field}")
        path = (manifest_path.parent / sample["path"]).absolute()
        report = scan(path, sample["kind"], options or Options())
        digest = report["artifact"]["sha256"]
        if digest != sample["sha256"]:
            report["scan_status"] = "failed"
            report["errors"].append({"engine": "evaluate", "code": "manifest_hash_mismatch", "message": f"Expected {sample['sha256']}, observed {digest}"})
            issues.append({"id": sid, "reason": "manifest_hash_mismatch"})
        (output_dir / "reports" / f"{sid}.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        if sample.get("boundary"):
            passed = report["scan_status"] in sample["expected_statuses"] and digest == sample["sha256"]
            boundaries.append({"id": sid, "status": report["scan_status"], "expected_statuses": sample["expected_statuses"], "passed": passed, "errors": report["errors"]})
        for scope, truth in sample["truth"].items():
            if scope not in {"api_reference", "implementation_contains"} or truth is None:
                continue
            if not set(truth) <= set(algorithms):
                raise ValueError(f"{sid}: truth outside declared algorithm universe")
            predicted_all = predictions(report, scope) if digest == sample["sha256"] else set()
            predicted = sorted(predicted_all.intersection(algorithms))
            # Metrics use the predeclared universe; additional detections stay visible.
            rows.append({"id": sid, "scope": scope, "kind": sample["kind"], "symbol_state": sample["symbol_state"],
                "project": sample.get("project"), "family": sample.get("family"), "architecture": sample["architecture"],
                "scan_status": report["scan_status"], "truth": sorted(set(truth)), "predicted": predicted,
                "predicted_outside_metric_universe": sorted(predicted_all.difference(algorithms)),
                "false_positive": sorted(set(predicted) - set(truth)), "false_negative": sorted(set(truth) - set(predicted)),
                "errors": report["errors"]})
    groups = defaultdict(list)
    for row in rows:
        groups[(row["scope"], "all")].append(row)
        groups[(row["scope"], "kind:" + row["kind"])].append(row)
        groups[(row["scope"], "symbols:" + row["symbol_state"])].append(row)
        for field in ("project", "family", "architecture"):
            if row.get(field) and row[field] != "not_applicable":
                groups[(row["scope"], field + ":" + row[field])].append(row)
    summary = {"schema_version": "1.0", "manifest_sha256": sha256(manifest_path), "split": split,
        "selected_sample_count": len(selected), "algorithms": algorithms, "rows": rows,
        "boundary_checks": boundaries, "issues": issues,
        "metrics": {scope: {group: metrics(data, algorithms) for (s, group), data in groups.items() if s == scope} for scope in ("api_reference", "implementation_contains")},
        "limitations": ["Artificial fixtures and selected open-source objects; not a representative power-terminal benchmark.",
                        "Static API references and implementation inclusion are separate truth scopes; runtime use is unproven.",
                        "Failures and unknown algorithms remain in denominators; explicit boundary cases are listed separately from the start."],
        "competition_target": {"accuracy_threshold": .9, "claim": "not_validated_on_real_power_terminal_dataset"}}
    summary["evaluation_complete"] = not issues and all(r["scan_status"] == "completed" for r in rows) and all(b["passed"] for b in boundaries)
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    with (output_dir / "samples.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["id", "scope", "kind", "symbol_state", "project", "family", "architecture", "scan_status", "truth", "predicted", "false_positive", "false_negative"])
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v, ensure_ascii=False) if isinstance(v, list) else v for k, v in row.items() if k in writer.fieldnames})
    with (output_dir / "metrics.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["scope", "group", "algorithm", "TP", "FP", "FN", "TN", "precision", "recall", "f1", "accuracy", "positive_samples", "negative_samples", "positive_fraction"])
        writer.writeheader()
        for scope, sets in summary["metrics"].items():
            for group, values in sets.items():
                for algorithm, numbers in values["per_algorithm"].items():
                    writer.writerow({"scope": scope, "group": group, "algorithm": algorithm, **numbers})
    return summary
