"""Grouped development-only RF selection. Holdout paths are never opened."""
from pathlib import Path
import collections, hashlib, json, time
import numpy as np
import joblib
from sklearn.feature_extraction import DictVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupKFold
from curate import ALGORITHMS
from features import feature_view, SCHEMA

OUT = Path(__file__).resolve().parents[1] / 'artifacts/rf-baseline-20261014'
SEED = 20261014


def probabilities(model, x):
    p = model.predict_proba(x)
    if not isinstance(p, list): p = [p]
    classes = model.classes_ if isinstance(model.classes_, list) else [model.classes_]
    return np.column_stack([v[:, list(c).index(1)] if 1 in c else np.zeros(x.shape[0])
                            for v, c in zip(p, classes)])


def choose_threshold(scores, truth, known, budget):
    negative = known & ~truth; positive = known & truth
    best = (0, -1, 1.000001, 0)
    for t in np.unique(np.r_[scores[known], 1.000001]):
        pred = scores >= t
        fp = int(np.sum(pred & negative)); tp = int(np.sum(pred & positive))
        if fp / max(1, int(negative.sum())) <= budget:
            key = (tp, -fp, float(t), fp)
            if key[:3] > best[:3]: best = key
    return {'threshold': best[2], 'tp': best[0], 'fp': best[3], 'fn': int(positive.sum()) - best[0],
            'positives': int(positive.sum()), 'negatives': int(negative.sum()),
            'fpr': best[3] / max(1, int(negative.sum())), 'disabled': best[2] > 1}


def threshold_all(scores, truth, known, budget):
    return {a: choose_threshold(scores[:, j], truth[:, j], known[:, j], budget)
            for j, a in enumerate(ALGORITHMS)}


def select_training(records, domain):
    entries = []; fingerprints = collections.defaultdict(set)
    for i, r in enumerate(records):
        if r['domain'] != domain: continue
        for f in r['functions']:
            ann = f['annotation']
            if ann['crypto_candidate_truth'] is None: continue
            signature = hashlib.sha256(json.dumps(f['features'], sort_keys=True).encode()).hexdigest()
            label = tuple(ann['algorithms'])
            fingerprints[signature].add((label, ann['crypto_candidate_truth']))
            entries.append((i, f, signature))
    # Identical features with incompatible algorithm truth remain candidate-only.
    # Shared runtime is never spread across training and group holdout folds.
    groups_by_sig = collections.defaultdict(set)
    groups_by_body = collections.defaultdict(set)
    for i, f, sig in entries:
        groups_by_sig[sig].add(records[i]['group'])
        groups_by_body[f['body_sha256']].add(records[i]['group'])
    selected = []; seen = set(); counts = collections.Counter()
    for i, f, sig in entries:
        r = records[i]; ann = f['annotation']; key = (r['group'], sig, tuple(ann['algorithms']))
        if key in seen: counts['within_group_duplicate'] += 1; continue
        seen.add(key)
        if len(groups_by_sig[sig]) > 1 or len(groups_by_body[f['body_sha256']]) > 1:
            counts['cross_group_shared_feature_background'] += 1; continue
        if len(fingerprints[sig]) > 1:
            counts['conflicting_feature_truth'] += 1; continue
        selected.append((i, f))
    return selected, dict(counts)


def weights(selected, records):
    counts = collections.Counter((records[i]['group'], f['annotation']['crypto_candidate_truth']) for i,f in selected)
    return np.asarray([1 / counts[records[i]['group'], f['annotation']['crypto_candidate_truth']] for i,f in selected])


def file_scores(model, vectorizer, records, indices, view):
    result = np.zeros((len(indices), len(ALGORITHMS)))
    batch = []; owners = []
    def flush():
        if batch:
            x = vectorizer.transform(batch).astype(np.float32)
            np.maximum.at(result, owners, probabilities(model, x))
            batch.clear(); owners.clear()
    for j, i in enumerate(indices):
        for f in records[i]['functions']:
            batch.append(feature_view(f['features'], view)); owners.append(j)
            if len(batch) >= 4096: flush()
    flush()
    return result


def model(depth, leaf):
    return RandomForestClassifier(n_estimators=160, max_depth=depth, min_samples_leaf=leaf,
        class_weight='balanced_subsample', n_jobs=8, random_state=SEED)


def main():
    start=time.monotonic(); records=[]
    for line in (OUT/'development-functions.jsonl').open():
        r=json.loads(line); r['group']={'libecc-generic':'libecc'}.get(r['group'],r['group'])
        r['domain']='source' if r['kind']=='source' else 'binary'
        records.append(r)
    truth=np.asarray([[a in r['truth']['implementation_contains'] for a in ALGORITHMS] for r in records])
    known=np.asarray([[a in r['known_algorithms'] for a in ALGORITHMS] for r in records])
    summaries={}; oof_rows={}; bundle={'schema':SCHEMA, 'algorithms':ALGORITHMS,'domains':{}}
    for domain in ['source','binary']:
        indices=np.asarray([i for i,r in enumerate(records) if r['domain']==domain])
        selected, exclusions=select_training(records,domain)
        y=np.asarray([[a in f['annotation']['algorithms'] for a in ALGORITHMS] for i,f in selected],dtype=int)
        cy=np.asarray([f['annotation']['crypto_candidate_truth'] for i,f in selected],dtype=int)
        groups=np.asarray([records[i]['group'] for i,f in selected]); sw=weights(selected,records)
        group_names=sorted(set(records[i]['group'] for i in indices))
        folds=list(GroupKFold(n_splits=4).split(indices, groups=[records[i]['group'] for i in indices]))
        print(domain,'training functions',len(selected),'groups',len(group_names),flush=True)
        grid=[]; best=None
        for view in ['statistics','structure','context']:
            for depth in [14,22]:
                for leaf in [2,5]:
                    scores=np.zeros((len(indices),len(ALGORITHMS)))
                    for fold,(fitfile,testfile) in enumerate(folds):
                        tg=set(records[i]['group'] for i in indices[fitfile])
                        train=np.asarray([j for j,g in enumerate(groups) if g in tg])
                        vec=DictVectorizer(sparse=True)
                        x=vec.fit_transform([feature_view(selected[j][1]['features'],view) for j in train]).astype(np.float32)
                        rf=model(depth,leaf);rf.fit(x,y[train],sample_weight=sw[train])
                        scores[testfile]=file_scores(rf,vec,records,indices[testfile],view)
                    primary=threshold_all(scores,truth[indices],known[indices],.005)
                    relaxed=threshold_all(scores,truth[indices],known[indices],.02)
                    score=sum(t['tp'] for t in primary.values()); fp=sum(t['fp'] for t in primary.values())
                    row={'view':view,'max_depth':depth,'min_samples_leaf':leaf,'tp':score,'fp':fp,
                         'primary':primary,'relaxed':relaxed};grid.append(row)
                    print(domain,view,depth,leaf,'OOF',score,fp,flush=True)
                    key=(score,-fp,-depth,-leaf)
                    if best is None or key>best[0]:best=(key,row,scores)
        chosen=best[1];view=chosen['view']; cand_oof=np.zeros(len(selected)); cand_unseen=np.zeros(len(selected),dtype=bool)
        for fitfile,testfile in folds:
            tg=set(records[i]['group'] for i in indices[fitfile]); train=np.asarray([j for j,g in enumerate(groups) if g in tg]); test=np.asarray([j for j,g in enumerate(groups) if g not in tg])
            vec=DictVectorizer(); x=vec.fit_transform([feature_view(selected[j][1]['features'],view) for j in train]).astype(np.float32)
            rf=model(chosen['max_depth'],chosen['min_samples_leaf']);rf.fit(x,cy[train],sample_weight=sw[train])
            if len(test):cand_oof[test]=probabilities(rf,vec.transform([feature_view(selected[j][1]['features'],view) for j in test]).astype(np.float32))[:,0];cand_unseen[test]=True
        ct=choose_threshold(cand_oof,cy.astype(bool),cand_unseen,.02)
        vec=DictVectorizer();x=vec.fit_transform([feature_view(f['features'],view) for i,f in selected]).astype(np.float32)
        rf=model(chosen['max_depth'],chosen['min_samples_leaf']);rf.fit(x,y,sample_weight=sw)
        crf=model(chosen['max_depth'],chosen['min_samples_leaf']);crf.fit(x,cy,sample_weight=sw)
        bundle['domains'][domain]={'view':view,'vectorizer':vec,'classifier':rf,'candidate':crf,
            'thresholds':chosen['primary'],'relaxed_thresholds':chosen['relaxed'],'candidate_threshold':ct}
        summaries[domain]={'training_functions':len(selected),'groups':group_names,'excluded':exclusions,
            'class_functions':dict(zip(ALGORITHMS,y.sum(axis=0).tolist())),
            'class_groups':{a:sorted(set(groups[y[:,j]>0])) for j,a in enumerate(ALGORITHMS)},
            'candidate_positive':int(cy.sum()),'candidate_negative':int((cy==0).sum()),
            'candidate_oof':ct,'selected':chosen,'grid':grid,'feature_count':len(vec.feature_names_)}
        oof_rows[domain]=[{'id':records[i]['id'],'sha256':records[i]['sha256'],'group':records[i]['group'],
            'truth':records[i]['truth']['implementation_contains'],'known':records[i]['known_algorithms'],
            'scores':dict(zip(ALGORITHMS,best[2][j].tolist()))} for j,i in enumerate(indices)]
    joblib.dump(bundle,OUT/'model.joblib',compress=3)
    summary={'policy':'Four ancestry-group folds. Thresholds selected only from development OOF. No holdout reads.',
        'calibration':'Raw RF votes; thresholds calibrated to development file FPR only. Scores are not calibrated probabilities.',
        'candidate_policy':'Candidate model is a ranking output, never a hard gate on algorithm predictions.',
        'seconds':time.monotonic()-start,'domains':summaries}
    (OUT/'training-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    (OUT/'development-oof.json').write_text(json.dumps(oof_rows,indent=2)+'\n')
    print('TRAINING COMPLETE',summary['seconds'],flush=True)

if __name__=='__main__':main()
