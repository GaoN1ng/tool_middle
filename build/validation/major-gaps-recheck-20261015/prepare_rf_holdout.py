"""Prepare the separate historical RF holdout for default-detector recheck."""
import hashlib
import json
from pathlib import Path
import shutil
from datetime import datetime
from zoneinfo import ZoneInfo

ROOT=Path(__file__).resolve().parents[3]
OUT=Path(__file__).resolve().parent
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def write(path,data):
    assert not path.exists(),path
    path.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')

original=ROOT/'build/datasets/manifests/validation_set__rf-independent-20261014__manifest.json'
manifest=json.loads(original.read_text());cases=[];files={str(original.relative_to(ROOT)):digest(original)}
for row in manifest['samples']:
    path=(original.parent/row['path']).resolve();assert digest(path)==row['sha256']
    if row['kind']=='source':
        folder=OUT/'isolated-inputs/rf'/row['sha256'];folder.mkdir(parents=True)
        target=folder/path.name;shutil.copy2(path,target)
        marker=folder/'LICENSE';marker.write_text('Evaluation input boundary only; not a license grant. Original source notices apply.\n')
        files[str(marker.relative_to(ROOT))]=digest(marker)
    else:target=path
    files[str(target.relative_to(ROOT))]=row['sha256']
    cases.append(dict(row,path=str(target.relative_to(ROOT)),archived_path=str(path.relative_to(ROOT)),
                      truth=sorted(set(row['truth']['implementation_contains'])),known_algorithms=manifest['algorithms'],
                      origins=[{'manifest':original.name,'id':row['id']}]))
assert len(cases)==len({r['sha256'] for r in cases})==252
assert sum(len(r['truth']) for r in cases)==233
others=set(r['sha256'] for r in json.loads((OUT/'history-manifest.json').read_text())['samples'])
others.update(r['sha256'] for r in json.loads((ROOT/'build/validation/independent-20261015/manifest.json').read_text())['samples'])
assert not (others&set(r['sha256'] for r in cases))
for name,selected in [('rf-holdout',cases),('rf-isolated-source',[r for r in cases if r['kind']=='source'])]:
    output=OUT/(name+'-manifest.json');write(output,{'purpose':'Observed RF holdout, default detector only; no RF retraining/inference', 'samples':selected})
    write(OUT/(name+'-lock.json'),{'manifest_sha256':digest(output),'files':files,
                                 'locked_at':datetime.now(ZoneInfo('Asia/Shanghai')).isoformat()})
print('252 files / 233 labels; 22 isolated sources, 230 unchanged binaries; no content overlap with other recheck batches')
