"""Prepare a source-input boundary control, leaving detector code untouched."""
import hashlib
import json
from pathlib import Path
import shutil
from datetime import datetime
from zoneinfo import ZoneInfo

from evaluate_development import package_digest

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent

def read(path): return json.loads(path.read_text())
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def write(path, data):
    assert not path.exists(), path
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2)+'\n')

history = read(OUT/'history-manifest.json')['samples']
recent = read(ROOT/'build/validation/independent-20261015/manifest.json')['samples']
boundary = 'Evaluation input boundary only; not a license grant. Original source notices and central project licenses apply.\n'
provenance = []
for name, rows in [('history', history), ('recent', recent)]:
    samples, files = [], {}
    for row in rows:
        if row['kind'] != 'source': continue
        original = ROOT/row['path']
        if name == 'history':
            folder = OUT/'isolated-inputs/history'/row['sha256']
            folder.mkdir(parents=True)
            target = folder/original.name
            shutil.copy2(original, target)
        else:
            base = ROOT/'Samples/val_set/code_samples/independent-20261015'/row['project']
            assert original.is_relative_to(base)
            folder = OUT/'isolated-inputs/recent'/row['project']
            if not folder.exists(): shutil.copytree(base, folder)
            target = folder/original.relative_to(base)
        if not (folder/'LICENSE').exists(): (folder/'LICENSE').write_text(boundary)
        assert digest(target) == row['sha256']
        samples.append(dict(row, path=str(target.relative_to(ROOT)),
                            archived_path=row['path'],
                            evaluation_context='single file only' if name=='history' else 'same archived author project only'))
    for file in (OUT/'isolated-inputs'/name).rglob('*'):
        if file.is_file(): files[str(file.relative_to(ROOT))] = digest(file)
    manifest = OUT/(name+'-isolated-source-manifest.json')
    write(manifest, {'purpose':'Source context boundary control; no target byte/label edits',
                     'context_policy':'Historical sources are single-file; recent sources keep their same archived project tree',
                     'samples':samples})
    write(OUT/(name+'-isolated-source-lock.json'), {
        'manifest_sha256':digest(manifest), 'files':files,
        'locked_at':datetime.now(ZoneInfo('Asia/Shanghai')).isoformat()})
    provenance.append({'set':name, 'source_files':len(samples), 'locked_files':len(files)})

old_root = ROOT.parent/'quantum-crypto-scanner/artifacts/controlflow-primitives-20261014'
old_freeze = read(old_root/'freeze.json')
for path, expected in old_freeze['files'].items():
    assert digest(old_root/'frozen'/path) == expected, path
old_package = OUT/'historical-baseline-package'
shutil.copytree(old_root/'frozen', old_package,
                ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
assert package_digest(old_root/'frozen') == package_digest(old_package)
write(OUT/'isolation-protocol.json', {
    'reason':'Observed automatic header lookup traversing workspace and reading other projects/development headers',
    'policy':'Input-boundary control only. No detector rules, thresholds, target bytes, labels or denominators changed.',
    'prepared_at':datetime.now(ZoneInfo('Asia/Shanghai')).isoformat(),
    'sets':provenance,
    'historical_baseline_package_sha256':package_digest(old_package),
    'historical_baseline_origin':str(old_root/'frozen'),
    'historical_baseline_freeze_sha256':digest(old_root/'freeze.json'),
    'recent_baseline_package_sha256':package_digest(ROOT/'build/experiments/semantics-20261015/release-revision-package'),
    'comparison_policy':'Compare both frozen versions under identical isolated source inputs; original binary rows remain separately identified.'})
print(json.dumps(provenance,indent=2))
