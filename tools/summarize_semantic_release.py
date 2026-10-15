#!/usr/bin/env python3
"""Publish complete, matched-denominator semantic-release comparisons."""
from collections import Counter
import argparse
import json
from pathlib import Path
import shutil
import sys

sys.pycache_prefix = str(Path(__file__).resolve().parents[1]/'build/cache/pycache')
from evaluate_development import ROOT, summarize

EXPERIMENT=ROOT/'build/experiments/semantics-20261015'
OUTPUT=ROOT/'build/reports/semantics-20261015'
VALIDATION=ROOT/'build/validation/independent-20261015'


def read(path):return json.loads(path.read_text())
def write(name,obj):
    (OUTPUT/name).write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n')


def compare(before,after):
    old={r['sha256']:r for r in before['rows']};new={r['sha256']:r for r in after['rows']}
    assert old.keys()==new.keys()
    gained=[];lost=[]
    for sha,row in sorted(new.items()):
        prior=old[sha]
        assert set(row['truth'])==set(prior['truth'])
        assert set(row['known_algorithms'])==set(prior['known_algorithms'])
        for algorithm in sorted(set(row['truth'])):
            was,now=algorithm in prior['predicted'],algorithm in row['predicted']
            target=gained if now and not was else lost if was and not now else None
            if target is not None:target.append({k:row[k] for k in ('id','sha256','kind','project','family')}|{'algorithm':algorithm})
    return {'before':before['micro'],'after':after['micro'],'gained_true_labels':gained,
            'lost_true_labels':lost,'gained_by_algorithm':dict(Counter(r['algorithm'] for r in gained)),
            'denominator_unchanged':True,'files':len(new),'positive_labels':after['positive_labels']}


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    for path in (EXPERIMENT/'release-full/summary.json', EXPERIMENT/'release-revision-full/summary.json',
                 *(VALIDATION/key/'summary.json' for key in ('baseline','current','revision'))):
        if not path.is_file():raise ValueError('Required complete result missing: '+str(path))
    OUTPUT.mkdir(parents=True,exist_ok=True)
    old=read(ROOT/'build/experiments/sha256-pointer-20261015/release-full/summary.json')
    linked=read(EXPERIMENT/'baseline-linked-source/summary.json')
    overlay={r['sha256']:r for r in linked['rows']}
    assert len(overlay)==154
    before_rows=[overlay[r['sha256']] if r['kind']=='source' else r for r in old['rows']]
    baseline=summarize(before_rows);baseline['rows']=before_rows
    current=read(EXPERIMENT/'release-full/summary.json')
    revised=read(EXPERIMENT/'release-revision-full/summary.json')
    assert revised['files']==2344 and revised['positive_labels']==1572
    write('baseline-summary.json',baseline)
    write('initial-freeze-development-summary.json',current)
    write('development-summary.json',revised)
    comparison=compare(baseline,revised);comparison['initial_freeze']=compare(baseline,current)
    comparison['regression_revision']=compare(current,revised)
    write('comparison.json',comparison)
    misses=[{k:r[k] for k in ('id','sha256','kind','project','family','architecture','truth','predicted','false_negative','false_positive','scan_status')}
            for r in revised['rows'] if r['false_negative'] or r['false_positive'] or r['scan_status']!='completed']
    write('misses.json',{'rows':misses,'groups':[r for r in revised['implementation_groups'] if r['FN']]})
    manifest=read(VALIDATION/'manifest.json');metadata={r['sha256']:r for r in manifest['samples']}
    variants={k:read(VALIDATION/k/'summary.json') for k in ('baseline','current','revision')}
    independent={'input_counts':manifest['input_counts'],'limitations':manifest['limitations'],
                 'build_attempts':manifest['build_attempts'],'build_failures':manifest['build_failures'],
                 'first_unseen_family_test':compare(variants['baseline'],variants['current']),
                 'address_revision_recheck':compare(variants['current'],variants['revision']),
                 'revised_vs_baseline':compare(variants['baseline'],variants['revision']),
                 'policy':'The first frozen run is the independent author-family test. The address revision is a recheck of already observed inputs; no second independent-test claim. Historical 65.43% result is unchanged.'}
    for key,value in variants.items():
        independent[key]={k:v for k,v in value.items() if k!='rows'}
        independent[key]['by_author_family']={family:summarize([r for r in value['rows'] if metadata[r['sha256']]['author_family']==family])
                                             for family in sorted({r['author_family'] for r in manifest['samples']})}
    write('independent-validation-comparison.json',independent)
    for key in variants:
        write('independent-'+key+'-outcomes.json',variants[key])
    for name in ('freeze.json','freeze-revision.json'):
        shutil.copy2(EXPERIMENT/name,OUTPUT/name)
    provenance={'development':{'files':2344,'positive_labels':1572,'truth_changed':False,
                 'source_context':'build/datasets/development-source-context/linked-20261015/index.json',
                 'baseline':'Old full binary rows plus old-code rerun of all 154 source rows in identical linked context',
                 'revision_reuse':read(EXPERIMENT/'release-revision-full/protocol.json')},
                'independent_validation':{'manifest':'build/validation/independent-20261015/manifest.json',
                 'pre_scan_lock':'build/validation/independent-20261015/pre-scan-lock.json',
                 'acquisition':'build/validation/independent-20261015/acquisition.json',
                 'initial_freeze':'build/reports/semantics-20261015/freeze.json',
                 'revision_origin':'Existing development regression AArch64 SM2 O0 fixtures, unresolved address/name TypeError; no holdout-based detection change'},
                'remaining_scope':'Bounded loop/path, API/recognized primitive equations; not general recovery of all unknown static bignum implementations.'}
    write('provenance.json',provenance)
    print(json.dumps({'development':revised['micro'],'gained':len(comparison['gained_true_labels']),
                     'lost':len(comparison['lost_true_labels']),'independent_first':variants['current']['micro'],
                     'independent_revision':variants['revision']['micro']},indent=2))


if __name__=='__main__':main()
