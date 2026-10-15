#!/usr/bin/env python3
"""Replay one locked validation build using archived build views and a compiler.

The detector and target program are never run. With no --run, print the command.
Requires the original compiler (Zig 0.13.0) for a meaningful byte comparison.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
COLLECTION = 'independent-20261015'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--id', required=True, help='Exact ELF sample id from the manifest')
    parser.add_argument('--compiler', type=Path, required=True, help='Path to Zig 0.13.0')
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    base=ROOT/'build/validation'/COLLECTION
    lock=json.loads((base/'pre-scan-lock.json').read_text())
    assert digest(base/'manifest.json')==lock['manifest_sha256']
    for relative,want in lock['files'].items():
        if digest(ROOT/relative)!=want:raise ValueError('Locked input changed: '+relative)
    context=ROOT/'build/datasets'/COLLECTION
    for relative,want in json.loads((context/'build-context-lock.json').read_text()).items():
        if digest(context/relative)!=want:raise ValueError('Build context changed: '+relative)
    rows=json.loads((base/'manifest.json').read_text())['samples']
    row=next(r for r in rows if r['id']==args.id and r['kind']=='executable')
    old=list(row['build_command'])
    old_root=old[old.index('-o')+1].split('/build/validation/')[0]
    old_context=old_root+'/build/validation/'+COLLECTION+'/compile'
    output=ROOT/'build/reproduced'/COLLECTION/row['id']/'ordinary.so'
    cmd=[str(args.compiler.resolve()),*[s.replace(old_context,str(context/'build-context')).replace(old_root,str(ROOT)) for s in old[1:]]]
    cmd[cmd.index('-o')+1]=str(output)
    print(json.dumps(cmd,ensure_ascii=False,indent=2))
    if not args.run:return
    output.parent.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(ROOT/'build/cache/zig-replay-global'),
             ZIG_LOCAL_CACHE_DIR=str(output.parent/'cache'),TMPDIR=str(ROOT/'build/tmp'))
    done=subprocess.run(cmd,env=env,capture_output=True,timeout=300)
    (output.parent/'compile.log').write_bytes(done.stdout+done.stderr)
    result={'id':row['id'],'command':cmd,'exit_code':done.returncode,
            'expected_sha256':row['sha256'],'actual_sha256':digest(output) if output.is_file() else None,
            'target_executed':False}
    (output.parent/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    raise SystemExit(done.returncode)


if __name__=='__main__':main()
