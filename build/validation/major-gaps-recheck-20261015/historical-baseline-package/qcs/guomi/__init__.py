"""SM2/SM3/SM4 evidence module; constants remain clues, APIs remain references."""
from pathlib import Path
import json

ROOT = Path(__file__).parent
API_PATH = ROOT / 'api_mapping.json'
SOURCE_PATH = ROOT / 'source_references.json'
SIGNATURE_PATH = ROOT / 'function_signatures.json'
RULES_PATH = ROOT / 'constants.yar'
DEVELOPMENT_SOURCE_PATH = ROOT / 'development_source_references.json'
DEVELOPMENT_SIGNATURE_PATH = ROOT / 'development_function_signatures.json'
API_RULES = json.loads(API_PATH.read_text(encoding="utf-8"))
API = {name: algorithm for algorithm, names in API_RULES['apis'].items() for name in names}
ALGORITHMS = ['SM2', 'SM3', 'SM4']


def scan_c_source(path, report):
    """Complete pinned upstream bytes establish known source implementations."""
    from ..model import evidence, sha256
    from ..source import lex_cpp
    from ..source_reference import load_references
    from ..text import decode_source
    import re
    digest = report['artifact'].get('sha256') or sha256(path)
    reference_digest = sha256(SOURCE_PATH)
    references = {**load_references(str(SOURCE_PATH), reference_digest),
                  **load_references(str(DEVELOPMENT_SOURCE_PATH), sha256(DEVELOPMENT_SOURCE_PATH))}
    reference = references.get(digest)
    if reference:
        text, _ = decode_source(path.read_bytes())
        code, _, _ = lex_cpp(text)
        for name, algorithms in reference['functions'].items():
            for pos in reference['definition_offsets'][name]:
                if not re.match(re.escape(name)+r'\s*\(', code[pos:]):
                    raise ValueError('Pinned Guomi source offset mismatch')
                for algorithm in algorithms:
                    report['findings'].append(evidence(algorithm, 'guomi_source', 'source_implementation', name,
                        line=text.count('\n',0,pos)+1, offset=pos, source_role='definition',
                        implementation_verification='pinned_source_sha256', source_sha256=digest,
                        reference_source=reference['source'], confidence='medium',
                        confidence_reason='Complete audited upstream module bytes and operation definition match; compiled/runtime use unknown'))
    report['engine_status']['guomi_source'] = {'status':'completed'}
    report['versions']['guomi_source_reference_sha256'] = reference_digest
    report['versions']['guomi_api_mapping_sha256'] = sha256(API_PATH)
    report['versions']['guomi_development_source_reference_sha256'] = sha256(DEVELOPMENT_SOURCE_PATH)


def scan_binary(path, report, timeout, *, regions=None, architectures=None):
    from ..function_signatures import scan_functions
    from ..model import evidence, sha256
    from ..yara_engine import compiled
    import time
    started = time.monotonic()
    # Unlike the supplied extension, inert IV/S-box/curve tables do not become
    # implementation predictions. Preserve them as auditable weak evidence.
    rules = compiled(str(RULES_PATH), sha256(RULES_PATH))
    for match in rules.match(filepath=str(path), timeout=max(1,int(timeout))):
        matches = [{'identifier':s.identifier,'offset':i.offset,'matched_length':i.matched_length}
                   for s in match.strings for i in s.instances]
        report['clues'].append(evidence(None, 'guomi_constants', 'binary_constant', match.rule,
            candidate_algorithms=[match.meta['algorithm']], matches=matches,
            offset=min(m['offset'] for m in matches), confidence='low',
            confidence_reason='Guomi standard constants present; inert data, curve arithmetic or test vectors alone do not establish an implementation'))
    report['engine_status']['guomi_constants'] = {'status':'completed'}
    report['versions']['guomi_constants_sha256'] = sha256(RULES_PATH)
    scan_functions(path,report,max(.001,timeout-(time.monotonic()-started)),
        regions=regions,architectures=architectures,database=SIGNATURE_PATH,engine='guomi_function_signature')
    scan_functions(path,report,max(.001,timeout-(time.monotonic()-started)),
        regions=regions,architectures=architectures,database=DEVELOPMENT_SIGNATURE_PATH,engine='guomi_development_signature')
