#!/usr/bin/env python3
"""Publish matched-development comparisons without touching validation data."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.pycache_prefix=str(ROOT/'build/cache/pycache')
from evaluate_development import summarize,package_digest
from summarize_semantic_release import compare


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline',type=Path,required=True)
    parser.add_argument('--current',type=Path,required=True,help='Completed frozen evaluation directory')
    parser.add_argument('--context-control',type=Path,help='Old-code source-only evaluation using the new include view')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();out=args.output.resolve()
    if not out.is_relative_to(ROOT/'build/reports') or out.exists():raise ValueError('Use a new report directory below build/reports')
    read=lambda p:json.loads(p.read_text())
    historic=read(args.baseline);current=read(args.current/'summary.json');protocol=read(args.current/'protocol.json')
    if (current['files'],current['positive_labels'])!=(2344,1572):raise ValueError('Incomplete fixed development denominator')
    if not protocol['development_only'] or package_digest(Path(protocol['package']))!=protocol['package_sha256']:
        raise ValueError('Frozen package/protocol mismatch')
    comparison=compare(historic,current);before=historic;source_control=None
    if args.context_control:
        control=read(args.context_control);overlay={r['sha256']:r for r in control['rows']}
        if len(overlay)!=len([r for r in historic['rows'] if r['kind']=='source']):raise ValueError('Incomplete source control')
        source_control=compare(dict(summarize([r for r in historic['rows'] if r['kind']=='source']),rows=[r for r in historic['rows'] if r['kind']=='source']),control)
        rows=[overlay[r['sha256']] if r['kind']=='source' else r for r in historic['rows']]
        before=dict(summarize(rows),rows=rows)
    matched=compare(before,current)
    misses=[{k:r[k] for k in ('id','sha256','kind','project','family','architecture','truth','predicted','false_negative','false_positive','scan_status')}
            for r in current['rows'] if r['false_negative'] or r['false_positive'] or r['scan_status']!='completed']
    errors=Counter();witnesses=Counter();worker_failures=Counter();probe_statuses=Counter();budget_abstentions=Counter()
    for p in (args.current/'reports').glob('*.json'):
        report=read(p)['report']
        probe_statuses[report['engine_status'].get('semantic_probes',{}).get('status','not_run')]+=1
        for e in report['errors']:errors[(e['engine'],e['code'])]+=1
        for f in report['findings']:
            if f['engine']=='semantic_probes':witnesses[f['algorithm']]+=1
        for item in report['engine_status'].get('semantic_probes',{}).get('declined',[]):
            if isinstance(item,dict):worker_failures[(item.get('architecture'),item.get('worker_returncode'),item.get('limit'))]+=1
        for item in report['engine_status'].get('semantic_probes',{}).get('budget_declined',[]):
            budget_abstentions[(item.get('architecture'),item.get('algorithm'))]+=1
    provenance={'development_only':True,'truth_or_denominator_changed':False,'validation_used_for_tuning':False,
                'baseline':str(args.baseline),'current_evaluation':str(args.current),'protocol':protocol,
                'source_context_control':str(args.context_control) if args.context_control else None,
                'target_native_execution':False,'target_instruction_emulation':'Finite private-memory input/output probes in a separate resource-limited Unicorn process',
                'metric_note':'Content-deduplicated file/algorithm labels. Partial/failed scans remain in denominators. Development recall is not new-author generalization accuracy.',
                'probe_limitation':'Three finite vectors are not a proof of equivalence for all inputs. Unsupported ABIs/imports, invalid target instructions and budgets can decline.',
                'witnesses_by_algorithm':dict(witnesses),'errors':[{'engine':e,'code':c,'count':n} for (e,c),n in errors.items()],
                'probe_statuses':dict(probe_statuses),
                'budget_abstentions':[{'architecture':a,'algorithm':algo,'count':n} for (a,algo),n in budget_abstentions.items()],
                'status_policy':'Configured optional probe search timeouts abstain explicitly without accepting worker output; native backend crashes remain partial. Overall scanner timeouts remain partial. Neither abstention nor completed implies cryptographic absence.',
                'failed_workers':[{'architecture':a,'returncode':r,'limit':l,'count':n} for (a,r,l),n in worker_failures.items()]}
    out.mkdir(parents=True)
    for name,obj in {'development-summary.json':current,'baseline-summary.json':before,
                     'comparison.json':dict(matched,historical_comparison=comparison,source_context_effect=source_control),
                     'misses.json':{'rows':misses,'groups':[g for g in current['implementation_groups'] if g['FN']]},
                     'provenance.json':provenance}.items():
        (out/name).write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'micro':current['micro'],'new_labels':len(matched['gained_true_labels']),
                      'lost_labels':len(matched['lost_true_labels']),'status':current['scan_status']},indent=2))

if __name__=='__main__':main()
