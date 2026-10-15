"""Pinned, reviewed source modules; function names alone are never proof."""
import json
import re
from functools import lru_cache
from pathlib import Path

from .model import ALGORITHMS

from .paths import resource_path
DATABASE = resource_path("rules/source_implementations.json")


@lru_cache(maxsize=4)
def load_references(path, digest):
    # The digest participates in the cache key when the registry changes.
    database = json.loads(Path(path).read_text(encoding="utf-8"))
    if database.get("schema_version") != "1.0":
        raise ValueError("Unsupported source implementation registry schema")
    if not database.get("references"):
        raise ValueError("Empty source implementation registry")
    references = {}
    for reference in database["references"]:
        source = reference["source"]
        sha = source["sha256"]
        if not re.fullmatch(r"[0-9a-f]{64}", sha) or sha in references:
            raise ValueError("Invalid or duplicate source implementation hash")
        if not all(source.get(k) for k in ("url", "commit", "license")):
            raise ValueError("Source implementation reference lacks provenance")
        if not reference["functions"]:
            raise ValueError("Source implementation reference lacks reviewed functions")
        for name, algorithms in reference["functions"].items():
            if not algorithms or any(ALGORITHMS.get(a, "unknown") in {"unknown", "encoding"} for a in algorithms):
                raise ValueError("Invalid source implementation algorithm")
            offsets = reference["definition_offsets"].get(name)
            if not offsets or any(type(pos) is not int or pos < 0 for pos in offsets):
                raise ValueError("Source implementation reference lacks definition positions")
        references[sha] = reference
    return references
