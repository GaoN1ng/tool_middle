#!/usr/bin/env python3
"""Run regression modules in separate processes; retain module logs under build."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--package', type=Path, default=ROOT/'src')
    parser.add_argument('--modules', nargs='+', help='Optional explicit modules; report is then a subset')
    args=parser.parse_args()
    output=args.output.resolve()
    if not output.is_relative_to(ROOT/'build') or output.exists():
        raise ValueError('Use a new output directory under build/')
    output.mkdir(parents=True)
    modules=args.modules or [p.stem for p in sorted((ROOT/'tests').glob('test_*.py'))]
    if any(not re.fullmatch(r'test_[a-z0-9_]+',m) or not (ROOT/'tests'/(m+'.py')).is_file() for m in modules):
        raise ValueError('Unknown regression module')
    env=dict(os.environ,PYTHONPATH=os.pathsep.join((str(args.package.resolve()),str(ROOT/'tests'))),
             PYTHONPYCACHEPREFIX=str(ROOT/'build/cache/pycache'),TMPDIR=str(ROOT/'build/tmp'))
    def run(module):
        started=time.monotonic();path=output/(module+'.log')
        with path.open('w') as log:
            done=subprocess.run([sys.executable,'-m','unittest',module,'-v'],cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT)
        count=re.search(r'Ran (\d+) tests? in ',path.read_text())
        return {'module':module,'exit_code':done.returncode,'tests':int(count[1]) if count else None,
                'seconds':time.monotonic()-started,'log':str(path.relative_to(ROOT))}
    rows=[]
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for future in as_completed([pool.submit(run,m) for m in modules]):
            row=future.result();rows.append(row);print(row,flush=True)
            (output/'progress.json').write_text(json.dumps(rows,indent=2)+'\n')
    result={'all_passed':all(r['exit_code']==0 for r in rows),'tests':sum(r['tests'] or 0 for r in rows),
            'modules':rows,'subset':bool(args.modules),'package':str(args.package.resolve())}
    (output/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
    raise SystemExit(0 if result['all_passed'] else 1)


if __name__=='__main__':main()
