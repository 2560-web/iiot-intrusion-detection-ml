"""Meaningful consistency and HTTP checks; start server.py before running."""
from pathlib import Path
import json, urllib.request, urllib.error
import pandas as pd
root=Path(__file__).resolve().parent
r=json.loads((root/'evidence/results.json').read_text())
examples=json.loads((root/'data/demo_samples.json').read_text())
def post(payload,kind='application/json',origin=None):
 h={'Content-Type':kind}
 if origin:h['Origin']=origin
 req=urllib.request.Request('http://127.0.0.1:8765/api/predict',data=payload,headers=h)
 try:
  with urllib.request.urlopen(req,timeout=20) as res:return res.status,json.load(res)
 except urllib.error.HTTPError as e:return e.code,json.load(e)
checks={}
status,d=post(json.dumps([x['features'] for x in examples]).encode())
checks['saved_model_replays_match']=status==200 and len(d['predictions'])==len(examples) and all((z['label']=='Attack')==bool(x['predicted']) and abs(z['attack_probability']-x['probability'])<1e-12 for z,x in zip(d['predictions'],examples))
status,d=post((root/'data/prediction_sample.csv').read_bytes(),'text/csv');checks['csv_100_rows']=status==200 and d['rows']==100
checks['missing_schema_rejected']=post(b'[{"x":1}]')[0]==400
checks['empty_rows_rejected']=post(b'[]')[0]==400
checks['invalid_json_rejected']=post(b'not json')[0]==400
checks['cross_origin_rejected']=post(b'[{}]',origin='https://example.com')[0]==403
checks['annotation_columns_excluded']=not any(c in r['columns'] for c in ['Attack_label','Attack_type','frame.time','ip.src_host','ip.dst_host','mqtt.topic'])
checks['zero_exact_group_overlap']=r['train_test_group_overlap']==0
pred=pd.read_csv(root/'evidence/holdout_predictions.csv');checks['holdout_accuracy_recomputes']=abs(float((pred.actual==pred.predicted).mean())-r['models']['Random Forest']['accuracy'])<1e-12
checks['all_cv_scores_recorded']=len(r['training_group_cv_f1'])==3
checks['preview_embedded_results']='__RESULTS__' not in (root/'web/index.html').read_text()
report={'checked_utc':'2026-10-24','checks':checks,'all_passed':all(checks.values()),'browser_visual_qa':'Not completed; local browser executable unavailable and cloud-browser file URL access is blocked. JavaScript syntax and HTTP inference were checked.','original_source_recovery':'Recovered 406 messages across three relevant conversations; historical notebook binary and attachments were not exported.'}
(root/'evidence/verification.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2));assert all(checks.values())
