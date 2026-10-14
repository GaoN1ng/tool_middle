"""Freeze tested RF code/model before any independent evaluation."""
from pathlib import Path
import datetime,hashlib,json,os,shutil,subprocess,sys
import joblib
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1];OUT=HERE.parent/'artifacts/rf-baseline-20261014'

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
 assert (OUT/'training-summary.json').exists()
 for name in ['learning-tests.log','feature-tests-isolated-env.log']:
  assert (OUT/name).read_text().rstrip().endswith('OK')
 audit=json.loads((OUT/'annotation-audit.json').read_text())
 assert all(r['allocated_bytes_match'] for r in audit['binary_checks'])
 assert json.loads((OUT/'symbol-invariance-test.json').read_text())['passed']
 dest=OUT/'frozen'
 if dest.exists():raise SystemExit('Frozen artifacts immutable')
 dest.mkdir()
 for name in ['features.py','rf.py','learn.py','curate.py','dataset.py','audit_dataset.py','freeze.py','requirements.txt','README.md','test_features.py','test_learning.py']:
  shutil.copy2(HERE/name,dest/name)
 for name in ['model.joblib','training-summary.json','protocol.json','annotation-audit.json']:
  shutil.copy2(OUT/name,dest/name)
 pip=HERE.parent/'artifacts/linux-portability-20261012/新环境 with spaces/bin/python'
 r=subprocess.run([str(pip),'-m','pip','--python',sys.executable,'freeze'],capture_output=True,text=True,check=True)
 (dest/'environment.txt').write_text(r.stdout)
 bundle=joblib.load(dest/'model.joblib')
 features={d:m['vectorizer'].feature_names_ for d,m in bundle['domains'].items()}
 thresholds={d:{k:m[k] for k in ['view','thresholds','relaxed_thresholds','candidate_threshold']} for d,m in bundle['domains'].items()}
 (dest/'feature-dictionary.json').write_text(json.dumps(features,indent=2)+'\n')
 (dest/'thresholds.json').write_text(json.dumps(thresholds,indent=2)+'\n')
 importance={d:sorted(zip(m['vectorizer'].feature_names_,m['classifier'].feature_importances_.tolist()),key=lambda r:-r[1])[:30] for d,m in bundle['domains'].items()}
 (dest/'feature-importance.json').write_text(json.dumps(importance,indent=2)+'\n')
 files={str(p.relative_to(dest)):sha(p) for p in dest.iterdir() if p.is_file()}
 lock={'timestamp':datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat(),
  'files':files,'digest':hashlib.sha256(json.dumps(files,sort_keys=True).encode()).hexdigest(),
  'development_inputs_sha256':sha(OUT/'development-inputs.json'),'development_features_sha256':sha(OUT/'development-functions.jsonl'),
  'holdout_manifest_sha256':sha(ROOT/'validation_set/rf-independent-20261014/manifest.json'),
  'holdout_lock_sha256':sha(ROOT/'validation_set/rf-independent-20261014/metadata/pre-scan-lock.json'),
  'policy':'Code/model/features/thresholds immutable before holdout scoring. No holdout tuning. Raw RF votes not probability calibration.'}
 (dest/'freeze.json').write_text(json.dumps(lock,indent=2)+'\n');print('FROZEN',lock['digest'],flush=True)
if __name__=='__main__':main()
