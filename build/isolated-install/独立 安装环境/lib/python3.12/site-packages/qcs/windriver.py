"""Wrap upstream text engines, preserving raw output as weak clues."""
import sys
from functools import lru_cache
from pathlib import Path

from .model import evidence, sha256
from .text import decode_source

@lru_cache(maxsize=1)
def engines(root: str):
    if not (Path(root) / "cryptodetector").is_dir():
        raise ModuleNotFoundError("Wind River checkout missing; restore third_party/crypto-detector at the locked commit")
    sys.path.insert(0, root)
    from cryptodetector import Language
    from cryptodetector.methods.api.api_finder import APIFinder
    from cryptodetector.methods.keyword.keyword_search import KeywordSearch
    return Language.C, APIFinder(), KeywordSearch()

def scan_windriver(path, report, root):
    language, api, keyword = engines(str(root))
    text, _ = decode_source(path.read_bytes())
    for engine in (api, keyword):
        for hit in engine.search(text, language):
            report["clues"].append(evidence(None, "windriver", "source_keyword", hit["matched_text"],
                line=hit["line_number"], offset=hit["file_index_begin"], upstream_method=engine.method_id,
                upstream_evidence=hit, confidence_reason="Upstream text match may include comments/literals; independently verified calls are in source findings"))
    report["versions"]["windriver"] = {
        "commit": "d6156a818f57826e520ca117cc3baed55f51483c",
        "api_rules_sha256": sha256(root / "cryptodetector/methods/api/api_definitions.txt"),
        "keyword_rules_sha256": sha256(root / "cryptodetector/methods/keyword/keyword_list.txt")}
    report["engine_status"]["windriver"] = {"status": "completed"}
