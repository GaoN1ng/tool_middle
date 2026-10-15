from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .api_rules import API, TOKEN, SELECTORS, classify, MULTI_API, TERMINAL_RULES_PATH
from .model import evidence,sha256
from .text import decode_source
from .source_reference import DATABASE, load_references


def lex_cpp(text: str):
    """Mask comments and literals without moving any character or newline.

    Handles escaped quotes, backslash-newline, C++ raw literals and URL strings.
    Returns code, comments-only-masked text, and removed ranges with their role.
    This is a lexer, not a C preprocessor or semantic parser.
    """
    code, visible = list(text), list(text)
    removed = []
    i, n = 0, len(text)
    while i < n:
        start = i
        role = None
        if text.startswith("//", i):
            role = "comment"
            i += 2
            while i < n:
                if text[i] == "\n" and (i == 0 or text[i - 1] != "\\"):
                    break
                i += 1
        elif text.startswith("/*", i):
            role = "comment"
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
        elif text.startswith('R"', i):
            match = re.match(r'R"([^\s()\\]{0,16})\(', text[i:])
            if match:
                role = "string"
                terminator = ")" + match[1] + '"'
                end = text.find(terminator, i + len(match[0]))
                i = n if end < 0 else end + len(terminator)
            else:
                i += 1
        elif text[i] in {'"', "'"}:
            role = "string"
            quote = text[i]
            i += 1
            while i < n:
                if text[i] == "\\":
                    i = min(n, i + 2)
                elif text[i] == quote:
                    i += 1
                    break
                else:
                    i += 1
        else:
            i += 1
        if role:
            removed.append((start, i, role))
            for j in range(start, i):
                if text[j] not in "\r\n":
                    code[j] = " "
                    if role == "comment":
                        visible[j] = " "
    return "".join(code), "".join(visible), removed


def closing_paren(code: str, pos: int):
    depth = 0
    for i in range(pos, len(code)):
        if code[i] == "(":
            depth += 1
        elif code[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return None


def source_role(code: str, start: int, opening: int, closing: int) -> str:
    line_start = code.rfind("\n", 0, start) + 1
    # A macro definition may span backslash-newline.
    logical_start = line_start
    while logical_start > 0 and code[:logical_start - 1].rstrip("\r").endswith("\\"):
        logical_start = code.rfind("\n", 0, logical_start - 1) + 1
    if code[logical_start:start].lstrip().startswith("#"):
        return "macro"
    suffix = code[closing + 1:].lstrip()
    boundary = max(code.rfind(c, 0, start) for c in ";{}") + 1
    prefix = re.sub(r"(?m)^\s*#[^\n]*(?:\n|$)", "", code[boundary:start]).strip()
    if suffix.startswith("{"):
        return "definition"
    # Declarations have a type prefix, no expression operators and no return.
    if suffix.startswith(";") and prefix and not re.search(r"[=().,:+\-/?]|\breturn\b", prefix):
        if re.fullmatch(r"[\w\s*&<>]+", prefix):
            return "declaration"
    return "call"


def split_arguments(visible_args: str):
    """Split top-level arguments, preserving literals and nested expressions.

    Comments are already masked by the caller. Mask literals for delimiter
    tracking only, and slice the original visible text for selector lookup.
    Unbalanced delimiters or empty arguments stay unresolved.
    """
    code, _, _ = lex_cpp(visible_args)
    if not visible_args.strip():
        return []
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack, args, start = [], [], 0
    for pos, char in enumerate(code):
        if char in pairs:
            stack.append(pairs[char])
        elif char in ")]}":
            if not stack or stack.pop() != char:
                return None
        elif char == "," and not stack:
            args.append(visible_args[start:pos].strip())
            start = pos + 1
    args.append(visible_args[start:].strip())
    if stack or not all(args):
        return None
    return args


def resolve_selector(name: str, visible_args: str):
    # Only literal selectors / explicit constants; variables and concatenation unresolved.
    args = split_arguments(visible_args)
    if args is None:
        return None
    if name in {"EVP_CIPHER_fetch", "EVP_MD_fetch"} and len(args) > 1:
        literal = re.fullmatch(r'"([A-Za-z0-9_-]+)"', args[1])
        if literal:
            value = literal[1].upper()
            if name == "EVP_CIPHER_fetch" and re.fullmatch(r"AES-(128|192|256)-(ECB|CBC|CFB|OFB|CTR|GCM|CCM|XTS|OCB)", value):
                return "AES"
            return SELECTORS[name].get(value)
    if name == "EVP_PKEY_CTX_new_id" and args:
        return SELECTORS[name].get(args[0])
    if name in {"mbedtls_gcm_setkey", "mbedtls_ccm_setkey"} and len(args)>1 and args[1]=="MBEDTLS_CIPHER_ID_AES":
        return "AES"
    if name == "mbedtls_md_info_from_type" and args:
        return {"MBEDTLS_MD_MD5":"MD5", "MBEDTLS_MD_SHA1":"SHA-1", "MBEDTLS_MD_SHA256":"SHA-256"}.get(args[0])
    if name == "mbedtls_pk_info_from_type" and args:
        return {"MBEDTLS_PK_RSA":"RSA", "MBEDTLS_PK_RSASSA_PSS":"RSA", "MBEDTLS_PK_ECDSA":"ECDSA"}.get(args[0])
    if name == "mbedtls_cipher_info_from_type" and args:
        if re.fullmatch(r"MBEDTLS_CIPHER_AES_(128|192|256)_(ECB|CBC|CFB128|CTR|GCM|CCM)",args[0]):
            return "AES"
    if name in {"mbedtls_sha256", "mbedtls_sha256_ret", "mbedtls_sha256_starts", "mbedtls_sha256_starts_ret"}:
        index = 3 if name in {"mbedtls_sha256", "mbedtls_sha256_ret"} else 1
        if len(args) > index and args[index] == "0":
            return "SHA-256"
    return None


def scan_source(path: Path, report: dict):
    raw = path.read_bytes()
    text, encoding = decode_source(raw)
    report['artifact']['source_encoding'] = encoding
    if encoding != 'utf-8':
        report['coverage_notes'].append('Strict CP1252 fallback used for non-UTF8 source; algorithm tokens are ASCII, non-ASCII text encoding is not independently established.')
    code, visible, removed = lex_cpp(text)
    reference_digest = sha256(DATABASE)
    references = load_references(str(DATABASE), reference_digest)
    source_digest = hashlib.sha256(raw).hexdigest()
    reference = references.get(source_digest)
    tokens = re.compile(TOKEN.pattern + r"|\b(?:" + "|".join(map(re.escape, reference["functions"])) + r")\b") if reference else TOKEN
    for match in tokens.finditer(code):
        name, pos = match[0], match.start()
        algo, generic = classify(name)
        known_definition = reference and pos in reference["definition_offsets"].get(name, [])
        if not algo and not generic and not known_definition:
            continue
        line = text.count("\n", 0, pos) + 1
        line_end = text.find("\n", pos)
        snippet = text[text.rfind("\n", 0, pos) + 1:len(text) if line_end < 0 else line_end].strip()
        after = re.match(r"\s*\(", code[match.end():])
        role = "name_or_type"
        if after:
            opening = match.end() + after.end() - 1
            closing = closing_paren(code, opening)
            if closing is not None:
                role = source_role(code, pos, opening, closing)
                if role == "call":
                    algo = resolve_selector(name, visible[opening + 1:closing]) or algo
        item = evidence(algo, "source", "source_api" if after else "source_keyword", name,
                        line=line, offset=pos, snippet=snippet, source_role=role,
                        confidence="high" if algo and role == "call" else "low",
                        confidence_reason="Explicit algorithm API reference; no runtime proof" if algo and role == "call" else "Declaration, definition, macro or unresolved name is not a call")
        if generic and not algo:
            item.update(clue_category=generic, candidate_algorithms=["SHA-224", "SHA-256"] if generic == "SHA-224/SHA-256" else [])
        if role == "definition":
            item.update(algorithm=None, algorithm_category="unknown", confidence="low",
                        candidate_algorithms=MULTI_API.get(name, [algo]) if algo else item["candidate_algorithms"],
                        clue_category="algorithm_named_definition" if algo else generic,
                        confidence_reason="Function name alone does not establish an implementation; body and module context need independent verification")
            report["clues"].append(item)
            if reference and pos in reference["definition_offsets"].get(name, []):
                for algorithm in reference["functions"].get(name, []):
                    report["findings"].append(evidence(
                        algorithm, "source", "source_implementation", name,
                        line=line, offset=pos, snippet=snippet, source_role="definition",
                        confidence="medium", implementation_verification="pinned_source_sha256",
                        source_sha256=source_digest, reference_source=reference["source"],
                        confidence_reason="Complete source bytes match a pinned upstream implementation module, including its function bodies and local constants; compiled/runtime use remains unknown"))
        elif algo and role == "call":
            if item["algorithm_category"] == "encoding":
                report["clues"].append(item)
            else:
                for algorithm in MULTI_API.get(name, [algo]):
                    report["findings"].append({**item, 'algorithm': algorithm})
        else:
            report["clues"].append(item)
    # Weak text clues stay separate from algorithm predictions.
    for start, end, role in removed:
        for token in re.finditer(r"\b(?:AES|RSA|DES|RC4|ChaCha20|ECDSA|ECDH|SHA[-_ ]?(?:1|256)|MD5|mbedtls_\w+|EVP_\w+)\b", text[start:end], re.I):
            report["clues"].append(evidence(None, "source", "source_keyword", token[0],
                line=text.count("\n", 0, start + token.start()) + 1,
                source_role=role, confidence_reason="Comment or ordinary literal; not an API call"))
    report["artifact"]["format"] = "C/C++ text"
    report["engine_status"]["source"] = {"status": "completed"}
    report["versions"]["source_rules"] = "qcs-source-2"
    report["versions"]["source_rules_sha256"] = sha256(Path(__file__).with_name("api_rules.py"))
    report["versions"]["source_parser_sha256"] = sha256(Path(__file__))
    report["versions"]["source_reference_sha256"] = reference_digest
    report['versions']['terminal_api_mapping_sha256'] = sha256(TERMINAL_RULES_PATH)
    from .guomi import API_PATH
    report['versions']['guomi_api_mapping_sha256'] = sha256(API_PATH)
    report["coverage_notes"].append("Lexical C/C++ analysis; no preprocessing, inactive-branch evaluation, macro expansion, variable-selector or data-flow analysis.")
    report["coverage_notes"].append("The general source reference engine requires an exact pinned module SHA-256. Guomi has a separate bounded operation-witness engine for selected C/C++ bodies; unknown names alone remain clues.")

def scan_plain_text(path: Path, report: dict):
    text = path.read_text(encoding="utf-8")
    for match in TOKEN.finditer(text):
        report["clues"].append(evidence(None, "source", "source_keyword", match[0],
            line=text.count("\n",0,match.start())+1, offset=match.start(), source_role="plain_text",
            confidence_reason="Plain text name is a weak clue; no language-level API call inferred"))
    report["artifact"]["format"]="plain text"
    report["engine_status"]["source"]={"status":"completed"}
