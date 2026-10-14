"""Verify this documentation/legal repack against the previous wheel payload."""
import base64
import csv
from io import StringIO
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[2]
baseline = json.loads((ROOT / 'build/checks/metrics-license-before.json').read_text())
wheel = next((ROOT / 'build/dist').glob('*.whl'))
issues = []
with zipfile.ZipFile(wheel) as z:
    current = {n: hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist()}
    old = baseline['old_wheel']['entries']
    payload = [n for n in old if n.startswith(('qcs/', 'qcs_ml/'))]
    for n in payload:
        if old[n] != current.get(n):
            issues.append('Runtime package payload changed: ' + n)
    for n in old:
        if n.endswith(('/METADATA', '/RECORD')):
            continue
        if old[n] != current.get(n):
            issues.append('Previously shipped entry missing/changed: ' + n)
    for n in current.keys() - old.keys():
        if '.dist-info/licenses/' not in n:
            issues.append('Unexpected new wheel payload: ' + n)
    info = next(n.split('/')[0] for n in current if n.endswith('.dist-info/METADATA'))
    included = []
    for folder in ('licenses/components', 'licenses/reference_data', 'licenses/project'):
        for p in (ROOT / folder).rglob('*'):
            if p.is_file():
                included.append(str(p.relative_to(ROOT)))
    included += ['LICENSE', 'licenses/NOTICE.txt', 'licenses/INDEX.txt']
    metadata = z.read(info + '/METADATA').decode('utf-8')
    for p in included:
        n = info + '/licenses/' + p
        if current.get(n) != hashlib.sha256((ROOT / p).read_bytes()).hexdigest():
            issues.append('Legal metadata copy missing/changed: ' + p)
        if 'License-File: ' + p + '\n' not in metadata:
            issues.append('License-File header missing: ' + p)
    readme = (ROOT / 'readme.md').read_text()
    if readme not in metadata:
        issues.append('Wheel metadata lacks the current README')
    if z.testzip() is not None:
        issues.append('Wheel ZIP CRC failed')
    for n, hash_value, size in csv.reader(StringIO(z.read(info + '/RECORD').decode())):
        if not hash_value:
            if n != info + '/RECORD':
                issues.append('Unsigned RECORD entry: ' + n)
            continue
        data = z.read(n)
        expected = 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('=')
        if hash_value != expected or size != str(len(data)):
            issues.append('Wheel RECORD mismatch: ' + n)
report = {
    'passed': not issues,
    'wheel': str(wheel.relative_to(ROOT)),
    'bytes': wheel.stat().st_size,
    'sha256': hashlib.sha256(wheel.read_bytes()).hexdigest(),
    'verified_unchanged_package_entries': len(payload),
    'verified_central_legal_metadata_files': len(included),
    'readme_metadata_current': readme in metadata,
    'issues': issues,
}
(ROOT / 'build/checks/metrics-license-wheel.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
raise SystemExit(0 if report['passed'] else 1)
