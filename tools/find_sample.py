#!/usr/bin/env python3
"""Locate a deduplicated sample by original path, basename, hash or label."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("query", help="Substring of original/new path or SHA-256")
    p.add_argument("--split", choices=["test_set", "val_set"])
    p.add_argument("--algorithm", help="Exact declared implementation label")
    args = p.parse_args()
    catalog = json.loads((ROOT / "build/datasets/catalog.json").read_text(encoding="utf-8"))
    count = 0
    for entry in catalog["files"]:
        if args.split and entry["assigned_split"] != args.split:
            continue
        if args.query not in entry["sha256"] and not any(args.query in s for s in entry["origins"] + [entry["path"]]):
            continue
        if args.algorithm and not any(args.algorithm in (u.get("truth", {}).get("implementation_contains") or []) for u in entry["uses"]):
            continue
        print(entry["path"])
        count += 1
    if not count:
        p.exit(1, "No matching samples.\n")


if __name__ == "__main__":
    main()
