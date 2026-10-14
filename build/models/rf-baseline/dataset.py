"""Prepare development-only function annotations and reproducible features."""
from pathlib import Path
import concurrent.futures
import hashlib
import json
import sys
import time
from collections import Counter, defaultdict

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / 'quantum-crypto-scanner'))
from curate import MANIFESTS, ALGORITHMS, ancestry, registry, annotate
from features import extract, SCHEMA

OUT = ROOT / 'quantum-crypto-scanner/artifacts/rf-baseline-20261014'


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def symbols(path):
    from elftools.elf.elffile import ELFFile
    names = defaultdict(list)
    with path.open('rb') as f:
        e = ELFFile(f)
        table = e.get_section_by_name('.symtab')
        if table:
            for s in table.iter_symbols():
                if s['st_info']['type'] == 'STT_FUNC' and s['st_shndx'] != 'SHN_UNDEF':
                    names[s['st_value']].append(s.name)
    return names


def inputs():
    unique = {}
    sources = defaultdict(set)
    exclusions = []
    for mp in MANIFESTS:
        mpath = ROOT / mp
        m = json.loads(mpath.read_text())
        for r in m['samples']:
            p = mpath.parent / r['path']
            if r['kind'] == 'source': sources[r['family']].add(r['sha256'])
            if r['kind'] not in {'source', 'executable'}: continue
            if r['kind'] == 'executable' and r.get('architecture') not in {'x86_64', 'aarch64'}:
                exclusions.append({'id': r['id'], 'reason': 'first RF scope excludes architecture', 'sha256': r['sha256']}); continue
            if ancestry(r) == 'synthetic-or-reference' or 'control' in r['project'].lower() or 'control' in r['family'].lower():
                exclusions.append({'id': r['id'], 'reason': 'synthetic/reference controls excluded from primary ML learning', 'sha256': r['sha256']}); continue
            assert sha(p) == r['sha256'], p
            row = dict(r, absolute_path=str(p), manifest=mp, known_algorithms=m['algorithms'], group=ancestry(r))
            if row['sha256'] not in unique: unique[row['sha256']] = row
            else:
                u = unique[row['sha256']]
                shared = set(u['known_algorithms']) & set(row['known_algorithms'])
                assert set(u['truth']['implementation_contains']) & shared == set(row['truth']['implementation_contains']) & shared
                u['truth']['implementation_contains'] = sorted(set(u['truth']['implementation_contains']) | set(row['truth']['implementation_contains']))
                u['known_algorithms'] = sorted(set(u['known_algorithms']) | set(row['known_algorithms']))
    for r in unique.values(): r['source_hashes'] = sorted(sources[r['family']])
    return list(unique.values()), exclusions


def process(row, reviewed):
    p = Path(row['absolute_path'])
    start = time.monotonic()
    functions, status = extract(p, row['kind'])
    if row['kind'] == 'executable':
        inspected = next((p.parent / n for n in ['inspection.so', 'unstripped.so', 'symbolic.so'] if (p.parent / n).exists()), None)
        named = symbols(inspected) if inspected else {}
    else: named = {}
    annotations = []
    for f in functions:
        names = [f.get('label_key', '')] if row['kind'] == 'source' else named.get(f['offset'], [])
        assignments = [annotate(name, row, row['source_hashes'] or [row['sha256']], reviewed) for name in names]
        positive = [a for a in assignments if a[0]]
        reviewed_negative = [a for a in assignments if a[1] is not None]
        use = positive or reviewed_negative
        labels = sorted(set().union(*(set(a[0]) for a in use))) if use else []
        candidate = max(a[1] for a in use) if use else None
        role = use[0][2] if use else 'unlabeled'
        # Only offline annotations carry names, never the feature dictionary.
        annotation = {'offset': f['offset'], 'size': f['size'], 'names_for_truth_only': names,
                      'algorithms': labels, 'crypto_candidate_truth': candidate, 'role': role,
                      'basis': [basis for a in use for basis in a[3]]}
        annotations.append(annotation)
        f.pop('label_key', None)
        f['annotation'] = annotation
    return {**row, 'functions': functions, 'status': status, 'seconds': time.monotonic()-start}, annotations


def main():
    reviewed, registry_paths = registry()
    rows, excluded = inputs()
    manifest = {'schema': SCHEMA, 'policy': 'Development only; no validation inputs', 'samples': rows,
                'exclusions': excluded, 'reviewed_registry_sources': registry_paths}
    (OUT / 'development-inputs.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2)+'\n')
    print('selected', len(rows), 'excluded', len(excluded), 'groups', Counter(r['group'] for r in rows), flush=True)
    destination = OUT / 'development-functions.jsonl'
    annotations = []
    with destination.open('w', encoding='utf-8') as stream, concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(process, row, reviewed): row for row in rows}
        for n, future in enumerate(concurrent.futures.as_completed(futures), 1):
            row = futures[future]
            try:
                record, labels = future.result()
                annotations.append({'id': row['id'], 'sha256': row['sha256'], 'annotations': labels})
            except Exception as e:
                record = {**row, 'functions': [], 'status': {'status': 'failed', 'reason': str(e)}}
            stream.write(json.dumps(record, ensure_ascii=False)+'\n'); stream.flush()
            if n % 20 == 0: print('extracted', n, '/', len(rows), flush=True)
    (OUT / 'function-truth.json').write_text(json.dumps({'policy': 'Offline source-backed labels; no scanner predictions used as truth',
                'samples': annotations}, ensure_ascii=False, indent=2)+'\n')
    stats = Counter(); algorithms = Counter(); per_group = defaultdict(Counter)
    for line in destination.open(encoding='utf-8'):
        r = json.loads(line)
        stats['files'] += 1; stats[r['status']['status']] += 1
        for f in r['functions']:
            a = f['annotation']; stats['functions'] += 1; stats[a['role']] += 1
            for label in a['algorithms']: algorithms[label] += 1; per_group[r['group']][label] += 1
    summary = {'files': stats['files'], 'statistics': dict(stats), 'labeled_algorithm_functions': dict(algorithms),
               'per_group': {g: dict(c) for g,c in per_group.items()}, 'groups': len(per_group),
               'excluded_files': len(excluded)}
    (OUT / 'dataset-summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(summary,ensure_ascii=False),flush=True)


if __name__ == '__main__': main()
