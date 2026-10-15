#!/usr/bin/env python3
"""Check frozen major-gap features in an installed wheel without PYTHONPATH."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
CASES={
 'arduinolibs-curve25519-mipsel-O0':'ECDH',
 'libmcrypt-rijndael-128-source':'AES',
 'libmcrypt-rijndael-128-mips_be-O2':'AES',
 'libmcrypt-des-mips_be-O2':'DES',
 'libmcrypt-arcfour-mipsel-O2':'RC4',
 'gmssl-modern-sm2_exch-thumb-Os':'SM2',
 'libecc-ecdh-arm-O0':'ECDH',
 'libecc-sm3-aarch64-O0':'SM3',
}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--python',type=Path,required=True)
    parser.add_argument('--freeze',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();out=args.output.resolve()
    if not out.is_relative_to(ROOT/'build') or out.exists():raise ValueError('Use a new output directory in build/')
    out.mkdir(parents=True)
    baseline=json.loads((ROOT/'build/reports/semantics-20261015/development-summary.json').read_text())
    rows={r['id']:r for r in baseline['rows']}
    contexts=json.loads((ROOT/'build/datasets/development-source-context/major-gaps-20261015/index.json').read_text())
    source_paths={r['sha256']:ROOT/r['path'] for r in contexts['records']}
    env=dict(os.environ,PYTHONPYCACHEPREFIX=str(ROOT/'build/cache/pycache'),TMPDIR=str(ROOT/'build/tmp'),QCS_BUILD_DIR=str(ROOT/'build'))
    env.pop('PYTHONPATH',None);env.pop('QCS_PYTHON',None)
    cwd=ROOT/'build/isolated-install/运行 目录';cwd.mkdir(exist_ok=True,parents=True)
    python=str(args.python.absolute())
    def run(item):
        name,expected=item;row=rows[name];path=source_paths.get(row['sha256'],row['path']) if row['kind']=='source' else row['path']
        done=subprocess.run([python,'-m','qcs','scan',str(path),'--no-windriver'],cwd=cwd,env=env,capture_output=True,text=True,timeout=180)
        report=json.loads(done.stdout) if done.stdout else {}
        evaluate=subprocess.run([python,'-c','import json,sys;from qcs.model import predictions;print(json.dumps(sorted(predictions(json.load(sys.stdin),"implementation_contains"))))'],
            cwd=cwd,env=env,input=done.stdout,capture_output=True,text=True,check=True)
        algorithms=set(json.loads(evaluate.stdout))
        (out/(name+'.json')).write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
        return dict(id=name,passed=expected in algorithms and done.returncode==0,expected=expected,
                    predicted=sorted(algorithms),scan_status=report.get('scan_status'),returncode=done.returncode,stderr=done.stderr)
    with ThreadPoolExecutor(max_workers=4) as pool:checks=list(pool.map(run,CASES.items()))
    location=Path(subprocess.run([python,'-c','import qcs; print(qcs.__file__)'],cwd=cwd,env=env,capture_output=True,text=True,check=True).stdout.strip()).parent
    freeze=json.loads(args.freeze.read_text());mismatches=[]
    for relative,want in freeze['files'].items():
        if not relative.startswith(('qcs/','qcs_ml/')):continue
        path=location.parent/relative
        if not path.is_file():
            mismatches.append(relative);continue
        got=hashlib.file_digest(path.open('rb'),'sha256').hexdigest()
        if got!=want:mismatches.append(relative)
    result=dict(passed=all(c['passed'] for c in checks) and not mismatches,checks=checks,
                installed_package=str(location),code_hash_mismatches=mismatches,freeze_sha256=freeze['package_sha256'],
                verified_frozen_payload_files=len(freeze['files']),
                policy='Installed wheel; no PYTHONPATH; external working directory; development inputs only')
    (out/'summary.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(result,ensure_ascii=False,indent=2));return 0 if result['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
