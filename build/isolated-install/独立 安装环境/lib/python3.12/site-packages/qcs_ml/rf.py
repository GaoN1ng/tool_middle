"""Optional static RF shadow scanner. Predictions are ML inferences, not proofs."""
import argparse,hashlib,json,time
from pathlib import Path
import joblib
import numpy as np
from .features import extract,feature_view,SCHEMA
from qcs.paths import BUILD, output_path


def probabilities(model,x):
    p=model.predict_proba(x)
    if not isinstance(p,list):p=[p]
    classes=model.classes_ if isinstance(model.classes_,list) else [model.classes_]
    return np.column_stack([v[:,list(c).index(1)] if 1 in c else np.zeros(x.shape[0]) for v,c in zip(p,classes)])


def load_model(path):
    lock=path.parent/'freeze.json'
    if lock.exists():
        expected=json.loads(lock.read_text())['files'].get(path.name)
        if expected and hashlib.sha256(path.read_bytes()).hexdigest()!=expected:raise ValueError('Frozen model digest mismatch')
    bundle=joblib.load(path)
    if bundle['schema']!=SCHEMA:raise ValueError('Incompatible RF feature schema')
    return bundle


def predict_functions(bundle,functions,kind,relaxed=False):
    domain='source' if kind=='source' else 'binary';m=bundle['domains'][domain]
    if not functions:return {},[],[]
    x=m['vectorizer'].transform([feature_view(f['features'],m['view']) for f in functions]).astype(np.float32)
    p=probabilities(m['classifier'],x);cp=probabilities(m['candidate'],x)[:,0]
    scores=dict(zip(bundle['algorithms'],p.max(axis=0).tolist()))
    thresholds=m['relaxed_thresholds'] if relaxed else m['thresholds']
    predicted=[a for a in bundle['algorithms'] if scores[a]>=thresholds[a]['threshold']]
    order=np.argsort(-cp)[:20]
    candidates=[{'offset':functions[i]['offset'],'size':functions[i]['size'],'candidate_vote':float(cp[i]),
                 'above_candidate_threshold':bool(cp[i]>=m['candidate_threshold']['threshold']),
                 'algorithm_votes':dict(zip(bundle['algorithms'],p[i].tolist()))} for i in order]
    return scores,predicted,candidates


def scan(bundle,path,kind,relaxed=False):
    start=time.monotonic()
    try:
        functions,status=extract(path,kind);scores,predicted,candidates=predict_functions(bundle,functions,kind,relaxed)
    except Exception as e:
        status={'status':'failed','reason':type(e).__name__+': '+str(e)};scores={};predicted=[];candidates=[]
    return {'artifact_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'feature_schema':SCHEMA,
        'scan_status':status,'evidence_type':'ml_inference','predicted':predicted,'algorithm_votes':scores,
        'candidate_ranking':candidates,'operating_point':'relaxed-2-percent-development-FPR' if relaxed else 'primary-0.5-percent-development-FPR',
        'seconds':time.monotonic()-start,'limitations':['Static experimental RF; raw tree votes are not calibrated probabilities',
            'No execution or mathematical proof of algorithm semantics','Only C/C++ source and x86_64/AArch64 ELF in first baseline',
            'Development FPR constraint does not guarantee holdout FPR','Candidate ranking does not gate algorithm predictions']}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('path',type=Path);p.add_argument('--kind',choices=['source','executable'],required=True)
    p.add_argument('--model',type=Path,default=BUILD/'models/rf-baseline/model.joblib');p.add_argument('--relaxed',action='store_true');p.add_argument('--output',type=Path);a=p.parse_args()
    if not a.path.is_file():p.error('Input file does not exist')
    result=scan(load_model(a.model),a.path,a.kind,a.relaxed);raw=json.dumps(result,ensure_ascii=False,indent=2)+'\n'
    if a.output:
        try: destination=output_path(a.output)
        except ValueError as exc: p.error(str(exc))
        destination.parent.mkdir(parents=True,exist_ok=True);destination.write_text(raw,encoding='utf-8')
    else:print(raw,end='')
    return {'completed':0,'partial':2,'unsupported':3,'failed':4}.get(result['scan_status']['status'],4)
if __name__=='__main__':raise SystemExit(main())
