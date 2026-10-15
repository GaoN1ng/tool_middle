"""Lock the migrated historical denominator without changing labels or scope."""
from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path
from zoneinfo import ZoneInfo

from evaluate_development import MANIFESTS, package_digest

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
NAMES = [
    'validation_set__manifest.json',
    'validation_set__guomi-operations-20261012__manifest.json',
    'validation_set__operations-independent-20261013__manifest.json',
    'validation_set__semantic-independent-20261013__manifest.json',
    'validation_set__controlflow-independent-20261014__manifest.json',
]

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def write(path, data):
    assert not path.exists(), path
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')

freeze = json.loads((ROOT/'build/checks/major-gaps-release-stable-freeze.json').read_text())
assert package_digest(ROOT/freeze['package']) == freeze['package_sha256']
effective = {str(p.relative_to(ROOT/'src')): digest(p) for p in (ROOT/'src').rglob('*')
             if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc'}
# Runtime JSON is deliberately stored under build/, then overlaid by setup.py.
for p in (ROOT/'build/runtime/qcs').rglob('*'):
    if p.is_file():
        effective['qcs/'+str(p.relative_to(ROOT/'build/runtime/qcs'))] = digest(p)
assert effective == freeze['files'], 'Checkout code/runtime differs from frozen release'

cases, files, provenance = {}, {}, []
for name in NAMES:
    manifest = ROOT/'build/datasets/manifests'/name
    obj = json.loads(manifest.read_text())
    files[str(manifest.relative_to(ROOT))] = digest(manifest)
    provenance.append({'manifest': str(manifest.relative_to(ROOT)), 'sha256': digest(manifest),
                       'records': len(obj['samples'])})
    for original in obj['samples']:
        truth = original['truth']['implementation_contains']
        assert truth is not None
        path = (manifest.parent/original['path']).resolve()
        assert path.is_relative_to(ROOT/'Samples'), path
        assert digest(path) == original['sha256'], path
        case = dict(original, path=str(path.relative_to(ROOT)), truth=sorted(set(truth)),
                    known_algorithms=sorted(set(obj['algorithms'])),
                    origins=[{'manifest': name, 'id': original['id']}])
        key = original['sha256']
        if key in cases:
            old = cases[key]
            for algorithm in set(old['known_algorithms']) & set(case['known_algorithms']):
                assert (algorithm in old['truth']) == (algorithm in case['truth']), key
            old['truth'] = sorted(set(old['truth']) | set(case['truth']))
            old['known_algorithms'] = sorted(set(old['known_algorithms']) | set(case['known_algorithms']))
            old['origins'] += case['origins']
        else:
            cases[key] = case
        files[str(path.relative_to(ROOT))] = original['sha256']
        if case['kind'] == 'source':
            # Preserve the archived local include view; do not supply new headers.
            for support in path.parent.rglob('*'):
                if support.is_file():
                    files[str(support.relative_to(ROOT))] = digest(support)

cases = sorted(cases.values(), key=lambda r: r['sha256'])
baseline = json.loads((ROOT/'build/history/default-rules/comparison.json').read_text())['combined_validation']
assert len(cases) == baseline['unique_files'] == 2855
assert sum(len(c['truth']) for c in cases) == 1455
for algorithm, counts in baseline['after']['per_algorithm'].items():
    assert sum(algorithm in c['truth'] for c in cases) == counts['TP']+counts['FN'], algorithm
    assert sum(algorithm in c['known_algorithms'] for c in cases) == sum(counts[k] for k in ('TP','FP','FN','TN')), algorithm
development = set()
for name in MANIFESTS:
    development.update(r['sha256'] for r in json.loads((ROOT/'build/datasets/manifests'/name).read_text())['samples'])
recent = json.loads((ROOT/'build/validation/independent-20261015/manifest.json').read_text())['samples']
assert not (set(c['sha256'] for c in cases) & set(c['sha256'] for c in recent))
manifest = OUT/'history-manifest.json'
write(manifest, {'purpose': 'Observed historical validation recheck; fixed original denominator and truth',
                 'original_manifests': provenance, 'samples': cases})
write(OUT/'history-lock.json', {'manifest_sha256': digest(manifest), 'files': files,
                              'locked_at': datetime.now(ZoneInfo('Asia/Shanghai')).isoformat(),
                              'detector_package_sha256': freeze['package_sha256']})
audit = {'files': len(cases), 'positive_labels': sum(len(c['truth']) for c in cases),
         'kinds': dict(Counter(c['kind'] for c in cases)), 'locked_files': len(files),
         'content_duplicate_records': sum(p['records'] for p in provenance)-len(cases),
         'original_manifests': provenance, 'package_sha256': freeze['package_sha256'],
         'checkout_code_and_runtime_match_freeze': True,
         'truth_and_known_scope_match_historical_baseline': True,
         'historical_development_overlap': [c for c in cases if c['sha256'] in development],
         'note': 'Historical overlap remains visible and in original denominator; no claims of fresh independence.'}
write(OUT/'history-input-audit.json', audit)
print(json.dumps({k:v for k,v in audit.items() if k != 'historical_development_overlap'}, indent=2))
print('historical_development_overlap', len(audit['historical_development_overlap']))
