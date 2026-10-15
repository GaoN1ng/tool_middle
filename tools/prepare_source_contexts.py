#!/usr/bin/env python3
"""Restore bounded development include context from retained source provenance.

Scanner behavior remains ordinary local include resolution. This builds an
explicit source view, never a hash-conditioned detector or validation lookup.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from evaluate_development import load_cases


def main():
    from qcs.guomi.source_context import load_context,available_code,attach_context
    from qcs.guomi.source_semantics import Analysis
    from qcs.source_linkage import load_callers
    from qcs.text import decode_source
    parser = argparse.ArgumentParser()
    parser.add_argument('--legacy-workspace', type=Path, required=True)
    parser.add_argument('--output',type=Path,default=ROOT/'build/datasets/development-source-context')
    args = parser.parse_args()
    legacy = args.legacy_workspace.resolve()
    out = args.output.resolve()
    if not out.is_relative_to(ROOT/'build/datasets/development-source-context'):
        parser.error('Context output must be below build/datasets/development-source-context')
    out.mkdir(parents=True, exist_ok=True)
    catalog = json.loads((ROOT / 'build/datasets/catalog.json').read_text())
    origins = {e['sha256']: e['origins'] for e in catalog['files']}
    records = []; missing = []
    for case in load_cases():
        if case['kind'] != 'source':
            continue
        original = next((legacy / o for o in origins[case['sha256']]
                         if not o.startswith('validation_set/') and (legacy / o).is_file()), None)
        if original is None:
            missing.append(case['sha256']); continue
        raw = original.read_bytes()
        if hashlib.sha256(raw).hexdigest() != case['sha256']:
            raise ValueError('Original development bytes changed: ' + str(original))
        text, _ = decode_source(raw)
        headers, context = load_context(original, text)
        analysis=Analysis(available_code(text).encode(),original.suffix.lower() in {'.cpp','.cc','.cxx'},
                          declaration_contexts=[c.raw for c in headers])
        attach_context(analysis,headers)
        _,links=load_callers(original,analysis,headers)
        files = [original, *(Path(r['path']) for r in [*context['files'],*links['files']])]
        # Retain the same local checkout boundary used by the scanner.
        for parent in [original.parent, *original.parents]:
            legal = [parent / n for n in ('LICENSE', 'LICENSE.txt', 'COPYING', 'COPYING.LIB', 'COPYING.LESSER', 'LICENCE') if (parent / n).is_file()]
            if legal:
                files += legal; break
            if (parent / '.git').exists():
                break
        copied = []
        for source in files:
            source = source.resolve()
            if not source.is_relative_to(legacy) or source.is_relative_to(legacy / 'validation_set'):
                raise ValueError('Context outside authorized development provenance: ' + str(source))
            target = out / source.relative_to(legacy)
            target.parent.mkdir(parents=True, exist_ok=True)
            data = source.read_bytes()
            if target.exists() and target.read_bytes() != data:
                raise ValueError('Conflicting source context: ' + str(target))
            target.write_bytes(data)
            copied.append({'original_path': str(source.relative_to(legacy)),
                           'path': str(target.relative_to(ROOT)),
                           'sha256': hashlib.sha256(data).hexdigest()})
        records.append({'sha256': case['sha256'], 'path': str((out / original.relative_to(legacy)).relative_to(ROOT)),
                        'project': case.get('project'), 'family': case.get('family'),
                        'files': copied, 'context_limited': context['limited']})
    report = {'development_only': True, 'source_bytes_unchanged': True,
              'purpose': 'Restore local include relationships; headers are not independent positive labels',
              'records': records, 'missing_originals': missing}
    (out / 'index.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print('Prepared development source contexts:', len(records), 'missing:', len(missing))


if __name__ == '__main__':
    main()
