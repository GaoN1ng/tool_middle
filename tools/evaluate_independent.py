#!/usr/bin/env python3
"""Evaluate a pre-locked independent manifest without changing the detector."""
import argparse
from concurrent.futures import ProcessPoolExecutor,as_completed
import hashlib
import json
from pathlib import Path
import sys
import time
sys.pycache_prefix = str(Path(__file__).resolve().parents[1]/'build/cache/pycache')
from evaluate_development import run,summarize,init_worker,package_digest

ROOT=Path(__file__).resolve().parents[1]

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--manifest',type=Path,required=True);p.add_argument('--lock',type=Path,required=True)
 p.add_argument('--package',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 p.add_argument('--workers',type=int,default=6);args=p.parse_args()
 manifest=args.manifest.resolve();lock=json.loads(args.lock.read_text())
 if digest(manifest)!=lock['manifest_sha256']:raise ValueError('Manifest changed since pre-scan lock')
 for path,want in lock['files'].items():
  if digest(ROOT/path)!=want:raise ValueError('Sample or support context changed: '+path)
 cases=json.loads(manifest.read_text())['samples']
 for case in cases:case['path']=str(ROOT/case['path'])
 out=args.output.resolve()
 if not out.is_relative_to(ROOT/'build') or out.exists():raise ValueError('Use a new output directory under build/')
 (out/'reports').mkdir(parents=True);before=package_digest(args.package);rows=[];started=time.monotonic()
 protocol={'manifest_sha256':digest(manifest),'lock_sha256':digest(args.lock),'package':str(args.package.resolve()),
           'package_sha256':before,'metric_unit':'content-deduplicated file/algorithm; declared known scope',
           'policy':'All locked labelled files including failed/partial scans. No holdout-driven detector changes.'}
 (out/'protocol.json').write_text(json.dumps(protocol,indent=2)+'\n')
 with ProcessPoolExecutor(max_workers=args.workers,initializer=init_worker,initargs=(args.package.resolve(),)) as pool:
  for future in as_completed([pool.submit(run,c) for c in cases]):
   row,report=future.result();rows.append(row)
   (out/'reports'/(row['sha256']+'.json')).write_text(json.dumps({'row':row,'report':report},ensure_ascii=False))
   if len(rows)%25==0:print(len(rows),'/',len(cases),round(time.monotonic()-started,1),flush=True)
 assert package_digest(args.package)==before
 assert digest(manifest)==lock['manifest_sha256']
 for path,want in lock['files'].items():assert digest(ROOT/path)==want,path
 summary=summarize(rows);summary.update(rows=rows,seconds=time.monotonic()-started,
                                      by_kind={k:summarize([r for r in rows if r['kind']==k]) for k in sorted({r['kind'] for r in rows})})
 (out/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({'files':summary['files'],'micro':summary['micro'],'scan_status':summary['scan_status']},indent=2),flush=True)

if __name__=='__main__':main()
