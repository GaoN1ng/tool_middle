#!/usr/bin/env python3
"""Recheck an AArch64-only address-parser correction with explicit result reuse.

All AArch64 ELF inputs are rescanned. Other results are reused only after AST
verification that all changed detector code is inside the AArch64 stub branch.
The parent full evaluation must finish; its denominator is never shortened.
"""
import argparse
import ast
from concurrent.futures import ProcessPoolExecutor, as_completed
import json
from pathlib import Path
import sys
import time

sys.pycache_prefix = str(Path(__file__).resolve().parents[1]/'build/cache/pycache')
from evaluate_development import ROOT, init_worker, package_digest, run, summarize


class WithoutAArch64Stub(ast.NodeTransformer):
    def visit_If(self, node):
        if ast.dump(node.test) == ast.dump(ast.parse("self.domain == 'aarch64'", mode='eval').body):
            return None
        return self.generic_visit(node)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', type=Path, required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--workers', type=int, default=6)
    args = parser.parse_args()
    parent = args.parent.resolve()
    old_protocol = json.loads((parent/'protocol.json').read_text())
    old_package = Path(old_protocol['package'])
    new_package = args.package.resolve()
    def files(base):
        return {str(p.relative_to(base)):p.read_bytes() for p in base.rglob('*')
                if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc'}
    before, after = files(old_package), files(new_package)
    changed = [k for k in sorted(before.keys() | after.keys()) if before.get(k) != after.get(k)]
    assert changed == ['qcs/guomi/binary_bignum.py'], changed
    def stripped(raw):
        return ast.dump(WithoutAArch64Stub().visit(ast.parse(raw)))
    assert stripped(before[changed[0]]) == stripped(after[changed[0]])
    output = args.output.resolve()
    if not output.is_relative_to(ROOT/'build') or output.exists():
        raise ValueError('Use a new output under build/')
    (output/'reports').mkdir(parents=True)
    # The source contexts and case identity come from the running parent.
    from evaluate_development import load_cases
    cases = load_cases()
    if old_protocol['source_contexts']:
        contexts = {r['sha256']:r for r in json.loads(Path(old_protocol['source_contexts']).read_text())['records']}
        for case in cases:
            if case['kind']=='source':case['path']=str(ROOT/contexts[case['sha256']]['path'])
    def affected(case):
        if case['kind'] != 'executable':return False
        with open(case['path'],'rb') as stream:header=stream.read(20)
        # Unknown formats are rescanned conservatively.
        return (not header.startswith(b'\x7fELF') or len(header)<20 or
                int.from_bytes(header[18:20], 'little' if header[5]==1 else 'big')==183)
    pending = [c for c in cases if affected(c)]
    rows=[];started=time.monotonic();digest=package_digest(new_package)
    protocol=dict(old_protocol, package=str(new_package),package_sha256=digest,
                  parent=str(parent),rescan_files=len(pending),reuse_files=len(cases)-len(pending),
                  reuse_proof='Only AArch64 stub branch changed; AST outside that branch identical; all AArch64 ELF and unknown formats rescanned.')
    (output/'protocol.json').write_text(json.dumps(protocol,indent=2)+'\n')
    with ProcessPoolExecutor(max_workers=args.workers,initializer=init_worker,initargs=(new_package,)) as pool:
        for future in as_completed([pool.submit(run,c) for c in pending]):
            row,report=future.result();rows.append(row)
            (output/'reports'/(row['sha256']+'.json')).write_text(json.dumps({'row':row,'report':report},ensure_ascii=False))
            if len(rows)%25==0:print(len(rows),'/',len(pending),'rescans',round(time.monotonic()-started,1),flush=True)
    while not (parent/'summary.json').exists():
        print('Waiting for complete parent denominator',flush=True);time.sleep(20)
    old=json.loads((parent/'summary.json').read_text());mapping={r['sha256']:r for r in old['rows']}
    assert len(old['rows'])==len(cases)
    for case in cases:
        old_row=mapping[case['sha256']]
        for key in ('truth','known_algorithms','path'):
            assert old_row[key]==case[key], (case['id'],key)
        if not affected(case):
            rows.append(old_row)
            # Separate files preserve provenance; never overwrite parent reports.
            (output/'reports'/(case['sha256']+'.json')).write_bytes((parent/'reports'/(case['sha256']+'.json')).read_bytes())
    assert package_digest(new_package)==digest
    assert package_digest(old_package)==old_protocol['package_sha256']
    rows.sort(key=lambda r:r['sha256']);summary=summarize(rows)
    summary.update(rows=rows,seconds=time.monotonic()-started,result_reuse=protocol['reuse_proof'])
    (output/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(summary['micro'],indent=2),flush=True)


if __name__=='__main__':main()
