"""Reconstructed IIoT experiment. See docs/METHOD.md for its scope."""
from pathlib import Path
import argparse, hashlib, json, platform, time
import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (accuracy_score, balanced_accuracy_score, precision_score,
 recall_score, f1_score, roc_auc_score, confusion_matrix)
from sklearn.model_selection import GroupShuffleSplit, StratifiedGroupKFold, cross_val_score
from sklearn.pipeline import Pipeline

ROOT = Path(__file__).resolve().parent
# Explicit numeric allow-list: annotation columns cannot enter by accident.
CANDIDATES = ['arp.opcode','arp.hw.size','icmp.checksum','icmp.seq_le',
 'icmp.transmit_timestamp','icmp.unused','http.content_length','http.response',
 'http.tls_port','tcp.ack','tcp.ack_raw','tcp.checksum','tcp.connection.fin',
 'tcp.connection.rst','tcp.connection.syn','tcp.connection.synack','tcp.flags',
 'tcp.flags.ack','tcp.len','tcp.seq','udp.stream','udp.time_delta',
 'dns.qry.name.len','dns.qry.qu','dns.qry.type','dns.retransmission',
 'dns.retransmit_request','dns.retransmit_request_in','mqtt.conflag.cleansess',
 'mqtt.conflags','mqtt.hdrflags','mqtt.len','mqtt.msg_decoded_as',
 'mqtt.msgtype','mqtt.proto_len','mqtt.ver','mbtcp.len','mbtcp.trans_id','mbtcp.unit_id']


def numeric_frame(raw, columns=None):
    """Convert only approved measurements; never use labels or identities."""
    raw = raw.rename(columns=lambda c: str(c).strip())
    selected = columns or [c for c in CANDIDATES if c in raw]
    if columns:
        missing = [c for c in columns if c != 'tcp_ack_len_ratio' and c not in raw]
        if missing:
            raise ValueError('Missing required columns: ' + ', '.join(missing))
    data = pd.DataFrame(index=raw.index)
    for col in selected:
        if col == 'tcp_ack_len_ratio':
            continue
        data[col] = pd.to_numeric(raw[col], errors='coerce')
    if 'tcp.ack' in data and 'tcp.len' in data:
        data['tcp_ack_len_ratio'] = data['tcp.ack'].div(data['tcp.len'] + 1)
    data = data.replace([np.inf, -np.inf], np.nan)
    if columns:
        return data[columns]
    return data


def model():
    return Pipeline([('imputer', SimpleImputer(strategy='median',keep_empty_features=True)),
      ('forest', RandomForestClassifier(n_estimators=50,max_depth=None,
       min_samples_split=2,min_samples_leaf=1,bootstrap=True,
       class_weight='balanced_subsample',random_state=42,n_jobs=2))])


def evaluate(estimator, X, y):
    start=time.perf_counter(); pred=estimator.predict(X)
    elapsed=time.perf_counter()-start
    prob=estimator.predict_proba(X)[:,list(estimator.classes_).index(1)]
    return {'accuracy':float(accuracy_score(y,pred)),
      'balanced_accuracy':float(balanced_accuracy_score(y,pred)),
      'precision':float(precision_score(y,pred,zero_division=0)),
      'recall':float(recall_score(y,pred,zero_division=0)),
      'f1':float(f1_score(y,pred,zero_division=0)),
      'roc_auc':float(roc_auc_score(y,prob)),
      'confusion_matrix':confusion_matrix(y,pred,labels=[0,1]).tolist(),
      'inference_seconds':elapsed,'predictions':pred,'probabilities':prob}


def serial_metrics(d):
    return {k:v for k,v in d.items() if k not in ('predictions','probabilities')}


def train(csv_path, cv=True):
    start=time.perf_counter()
    raw=pd.read_csv(csv_path,low_memory=False)
    raw.columns=raw.columns.str.strip()
    if raw.columns.duplicated().any(): raise ValueError('Duplicate column names')
    if 'Attack_label' not in raw: raise ValueError('Attack_label is required')
    y=pd.to_numeric(raw['Attack_label'],errors='raise')
    if y.isna().any() or set(y.unique())!={0,1}: raise ValueError('Labels must contain 0 and 1 only')
    y=y.astype(int)
    X=numeric_frame(raw)
    all_missing=[c for c in X if X[c].isna().all()]
    X=X.drop(columns=all_missing)
    if X.shape[1]<2: raise ValueError('Too few supported numeric features')
    # Hash the actual model input, not raw rows. Identical feature vectors stay together.
    groups=pd.util.hash_pandas_object(X,index=False).astype(str)
    split=GroupShuffleSplit(n_splits=1,test_size=.2,random_state=42)
    tr,te=next(split.split(X,y,groups))
    if y.iloc[tr].nunique()!=2 or y.iloc[te].nunique()!=2:
        raise ValueError('The group holdout must contain both classes')
    train_groups=set(groups.iloc[tr]);test_groups=set(groups.iloc[te])
    assert not train_groups.intersection(test_groups)
    target_counts=pd.DataFrame({'g':groups,'y':y}).groupby('g')['y'].nunique()
    estimator=model()
    fit_start=time.perf_counter();estimator.fit(X.iloc[tr],y.iloc[tr]);fit_seconds=time.perf_counter()-fit_start
    rf=evaluate(estimator,X.iloc[te],y.iloc[te])
    baseline=DummyClassifier(strategy='prior').fit(X.iloc[tr],y.iloc[tr])
    dummy=evaluate(baseline,X.iloc[te],y.iloc[te])
    # Planned feature ablation, same held-out rows; no tuning on these results.
    tcp_cols=[c for c in X if c.startswith('tcp.') or c=='tcp_ack_len_ratio']
    tcp=model().fit(X.iloc[tr][tcp_cols],y.iloc[tr])
    tcp_result=evaluate(tcp,X.iloc[te][tcp_cols],y.iloc[te])
    folds=[]
    if cv:
        folds=cross_val_score(model(),X.iloc[tr],y.iloc[tr],
          groups=groups.iloc[tr],cv=StratifiedGroupKFold(3,shuffle=True,random_state=42),
          scoring='f1',n_jobs=1).tolist()
    ROOT.joinpath('evidence').mkdir(exist_ok=True)
    ROOT.joinpath('models').mkdir(exist_ok=True)
    schema=X.columns.tolist()
    joblib.dump({'model':estimator,'columns':schema},ROOT/'models/traffic_model.joblib',compress=3)
    pd.DataFrame({'source_row':te,'actual':y.iloc[te].to_numpy(),
      'predicted':rf['predictions'],'attack_probability':rf['probabilities']}).to_csv(ROOT/'evidence/holdout_predictions.csv',index=False)
    # Public demo uses only the numeric allow-list; no hosts, labels or payloads as input.
    examples=[]
    for label in (0,1):
        positions=np.flatnonzero(y.iloc[te].to_numpy()==label)[:6]
        for pos in positions:
            row=X.iloc[te[pos]].replace({np.nan:None}).to_dict()
            examples.append({'name':f'{"Normal" if label==0 else "Attack"} example {len(examples)+1}',
              'actual':label,'predicted':int(rf['predictions'][pos]),
              'probability':float(rf['probabilities'][pos]),'features':row})
    (ROOT/'data/demo_samples.json').write_text(json.dumps(examples,indent=2,allow_nan=False))
    X.iloc[te[:100]].to_csv(ROOT/'data/prediction_sample.csv',index=False)
    importance=estimator.named_steps['forest'].feature_importances_
    ranked=sorted([{'feature':c,'importance':float(v)} for c,v in zip(schema,importance)],key=lambda a:-a['importance'])
    source=json.loads((ROOT/'data/provenance.json').read_text()) if (ROOT/'data/provenance.json').exists() else {}
    report={'title':'IIoT Traffic Lab','owner':'Prem Armstrong D',
      'implementation':'2026 controlled evaluation, separate from the recovered historical source and executable restoration',
      'data_kind':'Public Edge-IIoTset network traffic; no synthetic training data',
      'source':source,'seed':42,'rows':len(X),'features':len(schema),
      'raw_columns':len(raw.columns),'class_counts':{str(k):int(v) for k,v in y.value_counts().items()},
      'train_rows':len(tr),'test_rows':len(te),
      'train_class_counts':{str(k):int(v) for k,v in y.iloc[tr].value_counts().items()},
      'test_class_counts':{str(k):int(v) for k,v in y.iloc[te].value_counts().items()},
      'unique_feature_vectors':int(groups.nunique()),'repeated_feature_rows':int(groups.duplicated().sum()),
      'conflicting_label_groups':int((target_counts>1).sum()),'train_test_group_overlap':0,
      'split':'80/20 split of unique feature-vector groups; row counts may differ from 80/20',
      'dropped_all_missing':all_missing,
      'excluded_columns':[c for c in raw if c not in schema and c!='Attack_label'],
      'columns':schema,'fit_seconds':fit_seconds,
      'models':{'Random Forest':serial_metrics(rf),'Majority baseline':serial_metrics(dummy),
                'TCP-only Random Forest':serial_metrics(tcp_result)},
      'training_group_cv_f1':folds,'feature_importance':ranked,
      'versions':{'python':platform.python_version(),'sklearn':sklearn.__version__,
                  'pandas':pd.__version__,'numpy':np.__version__},
      'limitations':['One public testbed dataset; no independent-site or future-capture validation.',
        'Grouping prevents exact feature-vector overlap, not session, device or temporal leakage.',
        'Protocol and capture artefacts may still make labels easier to predict.',
        'No joule, watt or device-power measurements; energy savings are not measured.',
        'Random Forest probabilities are uncalibrated model scores.',
        'Timing is a local wall-clock observation, not an energy benchmark.'],
      'total_seconds':time.perf_counter()-start}
    (ROOT/'evidence/results.json').write_text(json.dumps(report,indent=2,allow_nan=False))
    print(json.dumps({k:report[k] for k in ['rows','features','train_rows','test_rows','repeated_feature_rows','conflicting_label_groups','models','training_group_cv_f1','total_seconds']},indent=2))
    return report

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--csv',type=Path,default=ROOT/'data/ML-EdgeIIoT-dataset.csv')
    parser.add_argument('--skip-cv',action='store_true')
    args=parser.parse_args();train(args.csv,cv=not args.skip_cv)
