#!/usr/bin/env python3
"""Evaluate the fixed development denominator, with provenance-aware diagnostics.

This entry point intentionally never loads validation manifests. Snapshots use
--package to evaluate frozen scanner code without concurrent-edit ambiguity.
"""
import argparse
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = [
    'samples__operation-development-20261013__manifest.json',
    'samples__guomi-development-20261012__all-manifest.json',
    'samples__guomi-operations-20261012__manifest.json',
    'samples__research-development-20261013__manifest.json',
    'samples__semantic-development-20261013__manifest.json',
    'samples__controlflow-development-20261014__manifest.json',
]


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def package_digest(package):
    entries=[(str(p.relative_to(package)),digest(p)) for p in sorted(package.rglob('*'))
             if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc']
    return hashlib.sha256(json.dumps(entries,separators=(',',':')).encode()).hexdigest()


def load_cases():
    cases = {}
    for name in MANIFESTS:
        manifest = ROOT / 'build/datasets/manifests' / name
        obj = json.loads(manifest.read_text())
        for row in obj['samples']:
            truth = row['truth'].get('implementation_contains')
            if row['split'] != 'development' or truth is None:
                continue
            path = (manifest.parent / row['path']).resolve()
            if not path.is_relative_to(ROOT / 'Samples/test_set'):
                raise ValueError('Development input outside test_set: ' + str(path))
            case = dict(row, path=str(path), known_algorithms=obj['algorithms'],
                        truth=sorted(set(truth)), origins=[{'manifest': name, 'id': row['id']}])
            key = row['sha256']
            if key in cases:
                old = cases[key]
                for a in set(old['known_algorithms']) & set(case['known_algorithms']):
                    if (a in old['truth']) != (a in case['truth']):
                        raise ValueError('Conflicting development truth: ' + key)
                old['truth'] = sorted(set(old['truth']) | set(case['truth']))
                old['known_algorithms'] = sorted(set(old['known_algorithms']) | set(case['known_algorithms']))
                old['origins'] += case['origins']
            else:
                cases[key] = case
    return sorted(cases.values(), key=lambda r: r['sha256'])


def init_worker(package):
    sys.path.insert(0, str(package))


def run(case):
    from qcs.scanner import scan, Options
    from qcs.model import predictions, new_report, error
    started = time.monotonic()
    if digest(case['path']) != case['sha256']:
        raise ValueError('Input digest mismatch: ' + case['path'])
    try:
        report = scan(case['path'], case['kind'], Options())
    except Exception as exc:
        report=new_report(Path(case['path']),case['kind'])
        error(report,'development_evaluation','scan_exception',type(exc).__name__+': '+str(exc))
        report['scan_status']='failed'
    if report['artifact']['sha256'] not in {None,case['sha256']}:
        raise ValueError('Scanner/input digest mismatch: ' + case['path'])
    predicted = sorted(predictions(report, 'implementation_contains').intersection(case['known_algorithms']))
    row = {k: case.get(k) for k in ('id', 'sha256', 'path', 'kind', 'project', 'family',
                                  'architecture', 'compiler_flags', 'symbol_state', 'truth',
                                  'known_algorithms', 'origins')}
    row.update(predicted=predicted, false_negative=sorted(set(case['truth']) - set(predicted)),
               false_positive=sorted(set(predicted) - set(case['truth'])),
               scan_status=report['scan_status'], seconds=time.monotonic() - started)
    return row, report


def summarize(rows):
    counts = defaultdict(Counter)
    groups = defaultdict(Counter)
    for row in rows:
        for a in row['known_algorithms']:
            actual, predicted = a in row['truth'], a in row['predicted']
            key = 'TP' if actual and predicted else 'FN' if actual else 'FP' if predicted else 'TN'
            counts[a][key] += 1
            if actual:
                groups[(a, row.get('project'), row.get('family'))][key] += 1
    def finish(c):
        out = {k: c[k] for k in ('TP', 'FP', 'FN', 'TN')}
        tp, fp, fn = (c[k] for k in ('TP', 'FP', 'FN'))
        out.update(recall=tp / (tp + fn) if tp + fn else None,
                   false_negative_rate=fn / (tp + fn) if tp + fn else None,
                   precision=tp / (tp + fp) if tp + fp else None)
        return out
    total = sum(counts.values(), Counter())
    return {'files': len(rows), 'positive_labels': total['TP'] + total['FN'],
            'scan_status': dict(Counter(r['scan_status'] for r in rows)),
            'micro': finish(total), 'per_algorithm': {a: finish(c) for a, c in sorted(counts.items())},
            'implementation_groups': [dict(algorithm=a, project=p, family=f, **finish(c))
                                      for (a, p, f), c in sorted(groups.items(), key=lambda x: str(x[0]))]}


def diagnose(row, report):
    diag = []
    engines = report.get('engine_status', {})
    for algorithm in row['false_negative']:
        candidate = [c for c in report.get('clues', []) if algorithm in c.get('candidate_algorithms', [])]
        status = row['scan_status']
        detail = report.get('operation_diagnostics', {})
        # This is an observed stage, not an inferred causal explanation.
        reason = ('incomplete_scan' if status != 'completed' else
                  'candidate_without_implementation' if candidate else 'no_implementation_witness')
        diag.append(dict(algorithm=algorithm, observed_stage=reason,
                         causal_reason='requires_development_source_or_symbol_review',
                         clues=candidate[:8], operation_diagnostics=detail,
                         engines=engines, errors=report.get('errors', [])))
    return diag


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--package', type=Path, default=ROOT / 'src')
    parser.add_argument('--workers', type=int, default=12)
    parser.add_argument('--source-contexts', type=Path,
                        help='Explicit prepared development include view; use identically for before/after comparisons')
    parser.add_argument('--kind', choices=['source', 'executable'])
    parser.add_argument('--only', nargs='*', help='Optional focused development pass; does not claim full-set metrics')
    args = parser.parse_args()
    out = args.output.resolve()
    if not out.is_relative_to(ROOT / 'build'):
        parser.error('Output must be inside build/')
    out.mkdir(parents=True, exist_ok=True)
    reports = out / 'reports'; reports.mkdir(exist_ok=True)
    cases = load_cases()
    if args.kind:
        cases = [r for r in cases if r['kind'] == args.kind]
    if args.source_contexts:
        context = json.loads(args.source_contexts.read_text())
        if not context.get('development_only'):
            raise ValueError('Source context must be development-only')
        contexts = {r['sha256']: r for r in context['records']}
        for case in cases:
            if case['kind'] == 'source' and case['sha256'] in contexts:
                case['path'] = str(ROOT / contexts[case['sha256']]['path'])
    if args.only:
        cases = [r for r in cases if set(args.only) & set(r['truth'])]
    context_files={}
    if args.source_contexts:
        for record in context['records']:
            for file in record['files']:
                path=(ROOT/file['path']).resolve()
                if not path.is_relative_to(ROOT/'build/datasets/development-source-context'):
                    raise ValueError('Context input outside the development include view')
                if file['sha256']!=digest(path):raise ValueError('Context input digest mismatch: '+str(path))
                context_files[str(path.relative_to(ROOT))]=file['sha256']
    protocol={'development_only': True, 'manifests': MANIFESTS,
        'manifest_digests':{n:digest(ROOT/'build/datasets/manifests'/n) for n in MANIFESTS},
        'package_sha256':package_digest(args.package.resolve()),
        'runner_sha256':digest(__file__),
        'context_files_sha256':hashlib.sha256(json.dumps(context_files,sort_keys=True).encode()).hexdigest(),
        'files': len(cases), 'package': str(args.package.resolve()), 'focus': args.only,
        'kind_filter': args.kind, 'source_contexts': str(args.source_contexts) if args.source_contexts else None,
        'metric_unit': 'content-deduplicated file/algorithm; declared known scope only; incomplete scans remain in denominators',
        'target_execution': False}
    protocol_path=out/'protocol.json'
    if protocol_path.exists() and json.loads(protocol_path.read_text())!=protocol:
        raise ValueError('Cannot resume with a different package, dataset, context or evaluation protocol; use a new output directory')
    protocol_path.write_text(json.dumps(protocol,ensure_ascii=False,indent=2)+'\n')
    rows = []; started = time.monotonic()
    # Resume only within this frozen run. Each report is hashed to its input.
    pending = []
    for case in cases:
        path = reports / (case['sha256'] + '.json')
        if path.exists():
            stored = json.loads(path.read_text())
            if stored['row']['sha256']!=case['sha256'] or stored['row']['truth']!=case['truth']:
                raise ValueError('Stored report does not match current case: '+str(path))
            rows.append(stored['row'])
        else:
            pending.append(case)
    with ProcessPoolExecutor(max_workers=args.workers, initializer=init_worker,
                             initargs=(args.package.resolve(),)) as pool:
        futures = {pool.submit(run, case): case for case in pending}
        for future in as_completed(futures):
            case = futures[future]
            row, report = future.result()
            report['development_diagnostics'] = diagnose(row, report)
            (reports / (case['sha256'] + '.json')).write_text(json.dumps(
                {'row': row, 'report': report}, ensure_ascii=False, separators=(',', ':')) + '\n')
            rows.append(row)
            if len(rows) % 50 == 0 or len(rows) == len(cases):
                print(f'{len(rows)}/{len(cases)} files, {time.monotonic()-started:.1f}s', flush=True)
    rows.sort(key=lambda r: r['sha256'])
    summary = summarize(rows)
    summary.update(rows=rows, seconds=time.monotonic() - started, focus=args.only)
    (out / 'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({k: v for k, v in summary.items() if k not in {'rows', 'implementation_groups'}}, indent=2), flush=True)


if __name__ == '__main__':
    main()
