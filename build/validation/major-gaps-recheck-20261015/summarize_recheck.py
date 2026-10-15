"""Summarize complete validation runs and their source-boundary controls."""
from collections import Counter, defaultdict
from datetime import datetime
import csv
import hashlib
import json
from pathlib import Path
from zoneinfo import ZoneInfo

from evaluate_development import summarize, package_digest
from summarize_semantic_release import compare

ROOT = Path(__file__).resolve().parents[3]
RUN = Path(__file__).resolve().parent
OUT = ROOT/'build/reports/validation-recheck-20261015'
OLD = ROOT.parent/'quantum-crypto-scanner/artifacts/controlflow-primitives-20261014'
GROUPS = {
    'validation_set__manifest.json': 'conventional',
    'validation_set__guomi-operations-20261012__manifest.json': 'guomi',
    'validation_set__operations-independent-20261013__manifest.json': 'cifra-sodium',
    'validation_set__semantic-independent-20261013__manifest.json': 'axtls',
    'validation_set__controlflow-independent-20261014__manifest.json': 'new-holdout',
}

def read(path): return json.loads(path.read_text())
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def write(name, data):
    path = OUT/name
    assert not path.exists(), path
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2)+'\n')
def full(rows):
    result = summarize(rows)
    result['rows'] = sorted(rows, key=lambda r:r['sha256'])
    result['by_kind'] = {kind:summarize([r for r in rows if r['kind']==kind])
                         for kind in sorted({r['kind'] for r in rows})}
    result['by_architecture'] = {str(arch):summarize([r for r in rows if r.get('architecture')==arch])
                                 for arch in sorted({r.get('architecture') for r in rows},key=str)}
    result['by_project'] = {project:summarize([r for r in rows if r['project']==project])
                            for project in sorted({r['project'] for r in rows})}
    return result
def overlay(raw, source):
    replacement = {r['sha256']:r for r in source['rows']}
    assert set(replacement) == {r['sha256'] for r in raw['rows'] if r['kind']=='source'}
    for prior in raw['rows']:
        if prior['kind']=='source':
            row=replacement[prior['sha256']]
            assert set(prior['truth'])==set(row['truth'])
            assert set(prior['known_algorithms'])==set(row['known_algorithms'])
    return full([replacement.get(r['sha256'],r) for r in raw['rows']])
def comparison(before, after):
    result = compare(before,after)
    old={r['sha256']:r for r in before['rows']};added=[];removed=[]
    for row in after['rows']:
        prior=old[row['sha256']]
        for algorithm in set(row['false_positive'])-set(prior['false_positive']):
            added.append({'id':row['id'],'sha256':row['sha256'],'algorithm':algorithm})
        for algorithm in set(prior['false_positive'])-set(row['false_positive']):
            removed.append({'id':row['id'],'sha256':row['sha256'],'algorithm':algorithm})
    result.update(added_false_positives=added,removed_false_positives=removed)
    result['per_algorithm'] = {a:{'before':before['per_algorithm'][a],'after':after['per_algorithm'][a]}
                                for a in after['per_algorithm']}
    return result

def rf_results():
    current=full(read(RUN/'rf-holdout-current/summary.json')['rows'])
    assert current['files']==252 and current['positive_labels']==233
    historical=read(ROOT/'build/history/rf-baseline/independent-results.json')
    cases=read(RUN/'rf-holdout-manifest.json')['samples']
    old={r['sha256']:r for r in historical['rows']};old_rows=[]
    assert set(old)=={r['sha256'] for r in cases}
    for case in cases:
        previous=old[case['sha256']];predicted=previous['rules']
        assert set(previous['truth'])==set(case['truth'])
        old_rows.append(dict(case,predicted=predicted,
                            false_negative=sorted(set(case['truth'])-set(predicted)),
                            false_positive=sorted(set(predicted)-set(case['truth'])),
                            scan_status=previous['rules_status'],seconds=None))
    baseline=full(old_rows)
    for key in ('TP','FP','FN','TN'):assert baseline['micro'][key]==historical['overall']['rules'][key.lower()]
    paired=overlay(baseline,read(RUN/'rf-isolated-source-baseline/summary.json'))
    write('rf-summary.json',current)
    write('rf-historical-summary.json',baseline)
    write('rf-isolated-baseline-summary.json',paired)
    metrics={'historical_report':{k:v for k,v in baseline.items() if k!='rows'},
             'isolated_baseline':{k:v for k,v in paired.items() if k!='rows'},
             'isolated_current':{k:v for k,v in current.items() if k!='rows'},
             'paired_isolated_comparison':comparison(paired,current),
             'policy':'Default detector only on the historical RF holdout; no retraining or merged ML predictions'}
    write('rf-comparison.json',metrics)
    write('rf-misses.json',{'rows':[r for r in current['rows'] if r['false_negative'] or r['false_positive'] or r['scan_status']!='completed'],
                            'groups':[r for r in current['implementation_groups'] if r['FN']]})
    errors=Counter();probes=Counter();workers=Counter();budgets=Counter();witnesses=Counter()
    lock=read(RUN/'rf-holdout-lock.json')
    for row in current['rows']:
        report=read(RUN/'rf-holdout-current/reports'/(row['sha256']+'.json'))['report']
        for field in ('source_operation_context','source_parameter_linkage'):
            for item in report.get(field,{}).get('files',[]):
                relative=str(Path(item['path']).relative_to(ROOT))
                assert lock['files'].get(relative)==item['sha256'],item
        probe=report.get('engine_status',{}).get('semantic_probes',{})
        probes[probe.get('status','not_run')]+=1
        for item in probe.get('matches',[]):witnesses[item['algorithm']]+=1
        for item in probe.get('declined',[]):workers[json.dumps(item,sort_keys=True)]+=1
        for item in probe.get('budget_declined',[]):budgets[(item.get('architecture'),item.get('algorithm'))]+=1
        for item in report.get('errors',[]):errors[(item.get('engine'),item.get('code'))]+=1
    write('rf-diagnostics.json',{'probe_statuses':dict(probes),'behavioral_matches':dict(witnesses),
                                  'errors':[{'engine':e,'code':c,'count':n} for (e,c),n in errors.items()],
                                  'failed_workers':[{'entry':json.loads(k),'count':v} for k,v in workers.items()],
                                  'budget_abstentions':[{'architecture':a,'algorithm':b,'count':n} for (a,b),n in budgets.items()],
                                  'isolated_source_contexts_all_locked_and_inside_input_boundary':True})
    return metrics
def diagnostics(name, raw, isolated):
    probes=Counter();errors=Counter();workers=Counter();budgets=Counter();witnesses=Counter()
    contexts=[];outside=[];not_locked=[];versions={};engine_statuses=defaultdict(Counter)
    raw_lock = read(ROOT/'build/validation/independent-20261015/pre-scan-lock.json') if name=='recent' else read(RUN/'history-lock.json')
    isolated_lock = read(RUN/(name+'-isolated-source-lock.json'))
    locations={r['sha256']:RUN/(name+'-isolated-source-current')/'reports'/(r['sha256']+'.json')
               if r['kind']=='source' else RUN/('recent-232' if name=='recent' else 'history-2855')/'reports'/(r['sha256']+'.json')
               for r in isolated['rows']}
    for row in raw['rows']:
        payload=read(RUN/('recent-232' if name=='recent' else 'history-2855')/'reports'/(row['sha256']+'.json'))['report']
        for item in payload.get('source_operation_context',{}).get('files',[]):
            path=Path(item['path']);relative=str(path.relative_to(ROOT))
            record={'input_id':row['id'],'input_sha256':row['sha256'],**item}
            assert digest(path)==item['sha256'],path
            contexts.append(record)
            if path.is_relative_to(ROOT/'Samples/test_set'):outside.append(record)
            if relative not in raw_lock['files']:not_locked.append(record)
    for row in isolated['rows']:
        report=read(locations[row['sha256']])['report']
        if row['kind']=='source':
            for item in report.get('source_operation_context',{}).get('files',[]):
                relative=str(Path(item['path']).relative_to(ROOT))
                assert isolated_lock['files'].get(relative)==item['sha256'],item
                assert digest(Path(item['path']))==item['sha256'],item
        for engine,value in report.get('engine_status',{}).items():
            engine_statuses[engine][value.get('status','unknown')]+=1
        probe=report.get('engine_status',{}).get('semantic_probes',{})
        probes[probe.get('status','not_run')]+=1
        for item in probe.get('declined',[]):
            key=(item.get('architecture'),str(item.get('worker_returncode')),str(item.get('limit'))) if isinstance(item,dict) else ('invalid','invalid','invalid')
            workers[key]+=1
        for item in probe.get('budget_declined',[]):budgets[(item.get('architecture'),item.get('algorithm'))]+=1
        for item in probe.get('matches',[]):witnesses[item['algorithm']]+=1
        for item in report.get('errors',[]):errors[(item.get('engine'),item.get('code'))]+=1
        versions.update(report.get('tool',{}))
    return {'probe_statuses':dict(probes),'engine_statuses':dict(engine_statuses),
            'errors':[{'engine':e,'code':c,'count':n} for (e,c),n in errors.items()],
            'failed_workers':[{'architecture':a,'returncode':c,'limit':l,'count':n} for (a,c,l),n in workers.items()],
            'budget_abstentions':[{'architecture':a,'algorithm':b,'count':n} for (a,b),n in budgets.items()],
            'behavioral_matches':dict(witnesses),
            'raw_source_contexts':contexts,'raw_context_references_to_development':outside,
            'raw_context_references_not_in_original_input_lock':not_locked,
            'isolated_source_contexts_all_locked_and_inside_input_boundary':True,
            'scope':'Raw source-context lookup can traverse workspace. Isolated source rows replace every raw source row; binary rows are reused unmodified.'}

def main():
    assert not OUT.exists(), OUT
    # Require every complete run before publishing, including the paired controls.
    runs={name:read(RUN/name/'summary.json') for name in [
        'recent-232','history-2855','history-isolated-source-current','history-isolated-source-baseline',
        'recent-isolated-source-current','recent-isolated-source-baseline',
        'rf-holdout-current','rf-isolated-source-baseline']}
    assert runs['recent-232']['files']==232 and runs['history-2855']['files']==2855
    recent_old=read(ROOT/'build/validation/independent-20261015/revision/summary.json')
    history_cases=read(RUN/'history-manifest.json')['samples']
    historic={g:read(OLD/('final-validation-'+g)/'summary.json') for g in GROUPS.values()}
    indices={g:{r['id']:r for r in value['rows']} for g,value in historic.items()}
    old_rows=[]
    for case in history_cases:
        assert len(case['origins'])==1
        origin=case['origins'][0];previous=indices[GROUPS[origin['manifest']]][origin['id']]
        assert set(previous['truth'])==set(case['truth'])
        prior_report=read(OLD/('final-validation-'+GROUPS[origin['manifest']])/'reports'/(origin['id']+'.json'))
        assert prior_report['artifact']['sha256']==case['sha256'], origin['id']
        old_rows.append(dict(case,**{k:previous[k] for k in ('predicted','false_negative','false_positive','scan_status','seconds')}))
    history_old=full(old_rows)
    historical_expected=read(ROOT/'build/history/default-rules/comparison.json')['combined_validation']['after']
    for algorithm,counts in historical_expected['per_algorithm'].items():
        for key in ('TP','FP','FN','TN'):assert history_old['per_algorithm'][algorithm][key]==counts[key]
    OUT.mkdir(parents=True)
    results={}
    for name,current,baseline in [('recent',runs['recent-232'],recent_old),('history',runs['history-2855'],history_old)]:
        current_isolated=overlay(current,runs[name+'-isolated-source-current'])
        baseline_isolated=overlay(baseline,runs[name+'-isolated-source-baseline'])
        if name=='recent':
            metadata={r['sha256']:r for r in read(ROOT/'build/validation/independent-20261015/manifest.json')['samples']}
            current_isolated['by_author_family']={author:summarize([r for r in current_isolated['rows'] if metadata[r['sha256']]['author_family']==author])
                                                  for author in sorted({r['author_family'] for r in metadata.values()})}
        metrics={'historical_report':{k:v for k,v in baseline.items() if k!='rows'},
                 'raw_current':{k:v for k,v in current.items() if k!='rows'},
                 'isolated_baseline':{k:v for k,v in baseline_isolated.items() if k!='rows'},
                 'isolated_current':{k:v for k,v in current_isolated.items() if k!='rows'},
                 'raw_comparison':comparison(baseline,current),
                 'paired_isolated_comparison':comparison(baseline_isolated,current_isolated),
                 'current_context_control':comparison(current,current_isolated)}
        write(name+'-comparison.json',metrics)
        write(name+'-historical-summary.json',baseline)
        write(name+'-isolated-baseline-summary.json',baseline_isolated)
        write(name+'-summary.json',current_isolated)
        write(name+'-diagnostics.json',diagnostics(name,current,current_isolated))
        write(name+'-misses.json', {'rows':[r for r in current_isolated['rows'] if r['false_negative'] or r['false_positive'] or r['scan_status']!='completed'],
                                    'groups':[r for r in current_isolated['implementation_groups'] if r['FN']]})
        with (OUT/(name+'-algorithms.csv')).open('w') as stream:
            writer=csv.writer(stream);writer.writerow(['algorithm','positive_labels','old_isolated_TP','old_isolated_FP','old_isolated_FN','current_TP','current_FP','current_FN','old_FNR','current_FNR'])
            for algorithm,now in current_isolated['per_algorithm'].items():
                old=baseline_isolated['per_algorithm'][algorithm]
                writer.writerow([algorithm,now['TP']+now['FN'],old['TP'],old['FP'],old['FN'],now['TP'],now['FP'],now['FN'],old['false_negative_rate'],now['false_negative_rate']])
        results[name]=metrics
    results['rf']=rf_results()
    overlap_audit=read(RUN/'catalog-overlap-audit.json')
    overlaps={r['sha256'] for r in overlap_audit['history']['catalog_overlap_entries']}
    history_current=read(OUT/'history-summary.json')
    history_baseline=read(OUT/'history-isolated-baseline-summary.json')
    write('historical-overlap-sensitivity.json', {
        'policy':'Auxiliary sensitivity only; primary 2855-file denominator and labels are unchanged.',
        'catalog_overlap':overlap_audit,
        'excluded_files':len(overlaps),
        'before':summarize([r for r in history_baseline['rows'] if r['sha256'] not in overlaps]),
        'after':summarize([r for r in history_current['rows'] if r['sha256'] not in overlaps])})
    freeze=read(ROOT/'build/checks/major-gaps-release-stable-freeze.json')
    assert package_digest(ROOT/freeze['package'])==freeze['package_sha256']
    write('provenance.json', {
        'completed_at':datetime.now(ZoneInfo('Asia/Shanghai')).isoformat(),
        'package_sha256':freeze['package_sha256'],'package':freeze['package'],
        'new_independent_validation':False,'detector_changes':False,'truth_changes':False,'denominator_changes':False,
        'primary_protocol':'All source rows rescanned under isolated input boundaries. Every executable row from the complete frozen scan is retained without reselection.',
        'baseline_reuse':'Old executable predictions reused from their complete historical frozen runs; all 222 source files rerun in matching isolated contexts for each baseline. This is not a full current-environment rerun of the old binary scanners.',
        'raw_scan_outputs':['build/validation/major-gaps-recheck-20261015/recent-232','build/validation/major-gaps-recheck-20261015/history-2855'],
        'inputs':read(RUN/'history-input-audit.json'),'isolation':read(RUN/'isolation-protocol.json'),
        'catalog_overlap_audit':overlap_audit,
        'environment':read(RUN/'environment.json'),
        'scripts':{p.name:digest(p) for p in RUN.glob('*.py')},
        'limitations':['Repeated evaluation of already observed validation inputs; not a fresh author holdout.',
                       'Recent SM2/SM4 have one JavaScript positive each; no recent DES/RC4/ChaCha20 positives.',
                       'Historical source controls are single-file inputs, with archived headers not reconstructed; recent sources retain only their own archived project.',
                       'Two historical SM4 source inputs have recorded development uses outside the fixed six development manifests; preserved in historical denominator, with a separate overlap sensitivity report.',
                       'Optional budgets and incomplete scans are retained; completed does not prove algorithm absence.',
                       'Raw source header lookup crosses workspace boundaries; this behavior is recorded and not repaired using validation outputs.']})
    print(json.dumps({name:{'historical':value['historical_report']['micro'],
                            'raw_current':value.get('raw_current',value['isolated_current'])['micro'],
                            'isolated_baseline':value['isolated_baseline']['micro'],
                            'isolated_current':value['isolated_current']['micro'],
                            'scan_status':value['isolated_current']['scan_status']}
                      for name,value in results.items()},indent=2))

if __name__=='__main__':main()
