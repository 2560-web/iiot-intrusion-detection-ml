"""Executable restoration assembled from recovered user messages, not a byte-identical notebook.

Historical preprocessing is retained for comparison, including whole-dataset encoding
and imputation. Use pipeline.py for the separately controlled modern evaluation.
See docs/RESTORATION.md for sources, changes and limitations.
"""
from pathlib import Path
import hashlib,json,time,warnings
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split,cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report,confusion_matrix,accuracy_score,f1_score,roc_auc_score
import joblib
ROOT=Path(__file__).resolve().parent

def restore():
    started=time.perf_counter()
    ml_data=pd.read_csv(ROOT/'data/ML-EdgeIIoT-dataset.csv',low_memory=False)
    numeric_cols=ml_data.select_dtypes(include=['number']).columns
    non_numeric_cols=ml_data.select_dtypes(exclude=['number']).columns
    ml_data[numeric_cols]=ml_data[numeric_cols].fillna(ml_data[numeric_cols].mean())
    ml_data[non_numeric_cols]=ml_data[non_numeric_cols].fillna('Unknown')
    duplicates=int(ml_data.duplicated().sum())
    ml_data.drop_duplicates(inplace=True)
    # Exact expression recovered from the user's final complete code paste.
    ml_data['tcp_ack_len_ratio']=ml_data['tcp.ack']/(ml_data['tcp.len']+1)
    high_cardinality_cols=['ip.src_host','ip.dst_host','tcp.srcport','dns.qry.name.len','mqtt.topic']
    for col in high_cardinality_cols:
        if col in ml_data:
            ml_data[col]=LabelEncoder().fit_transform(ml_data[col].astype(str))
    for col in ml_data.select_dtypes(include=['object']).columns:
        if ml_data[col].nunique()<10:
            ml_data=pd.get_dummies(ml_data,columns=[col],drop_first=True)
    X=ml_data.drop(columns=['Attack_label'])
    y=ml_data['Attack_label']
    X_train,X_test,y_train,y_test=train_test_split(X,y,test_size=.2,random_state=42)
    def preprocess_data(df):
        df=df.copy()
        if 'frame.time' in df:
            # Explicit format='mixed' is a pandas 2 compatibility change.
            with warnings.catch_warnings():
                warnings.simplefilter('ignore',UserWarning)
                parsed=pd.to_datetime(df['frame.time'],errors='coerce',format='mixed')
            for component in ['year','month','day','hour','minute','second']:
                df[component]=getattr(parsed.dt,component)
            df=df.drop(columns=['frame.time'])
        columns_to_drop=['http.file_data','http.request.uri.query','http.request.full_uri',
          'tcp.options','tcp.payload','mqtt.msg','Attack_type']
        return df.drop(columns=[c for c in columns_to_drop if c in df])
    X_train=preprocess_data(X_train);X_test=preprocess_data(X_test)
    encoders={}
    for col in X_train.select_dtypes(include=['object']).columns:
        enc=LabelEncoder().fit(X_train[col].astype(str));encoders[col]=enc
        X_train[col]=enc.transform(X_train[col].astype(str))
        # Original transform() failed on unseen categories. Retain -1 for unknowns.
        mapping={v:i for i,v in enumerate(enc.classes_)}
        X_test[col]=X_test[col].astype(str).map(mapping).fillna(-1).astype(int)
    # Frozen historical best settings from the user's posted GridSearchCV output.
    model=RandomForestClassifier(n_estimators=50,max_depth=None,min_samples_split=2,
      min_samples_leaf=1,bootstrap=True,random_state=42,n_jobs=2)
    model.fit(X_train,y_train)
    pred=model.predict(X_test);prob=model.predict_proba(X_test)[:,1]
    cv=cross_val_score(model,X_train,y_train,cv=5,scoring='accuracy',n_jobs=1)
    importance=sorted([{'feature':c,'importance':float(v)} for c,v in zip(X_train.columns,model.feature_importances_)],key=lambda d:-d['importance'])
    result={'implementation':'Executable restoration from recovered 2024 user code; assembled in 2026',
      'source_chat':'https://chatgpt.com/c/7eea1afd-509b-4b6d-9474-ddbad19792fe?src=history_search',
      'source_message':'aaa27469-f2b5-47f8-9960-f10c75fbeae0','rows':len(ml_data),
      'duplicates_removed':duplicates,'features':X_train.shape[1],'train_rows':len(X_train),'test_rows':len(X_test),
      'ratio_expression':'tcp.ack / (tcp.len + 1)','accuracy':float(accuracy_score(y_test,pred)),
      'attack_f1':float(f1_score(y_test,pred)),'roc_auc':float(roc_auc_score(y_test,prob)),
      'confusion_matrix':confusion_matrix(y_test,pred,labels=[0,1]).tolist(),
      'five_fold_cv_accuracy':cv.tolist(),'feature_importance':importance,
      'limitations':['Historical whole-dataset preprocessing retained; this is a legacy replay, not leakage-controlled validation.',
        'Host identities, MQTT topics and temporal capture patterns remain predictors.',
        'Source contains repeated attempts and outputs, not an exported notebook with execution state.',
        'No external testbed validation or energy measurements.'],
      'elapsed_seconds':time.perf_counter()-started}
    (ROOT/'evidence/restored_results.json').write_text(json.dumps(result,indent=2))
    pd.DataFrame({'source_row':y_test.index,'actual':y_test.to_numpy(),'predicted':pred,'attack_probability':prob}).to_csv(ROOT/'evidence/restored_holdout_predictions.csv',index=False)
    print(json.dumps({k:v for k,v in result.items() if k!='feature_importance'},indent=2))
    print(classification_report(y_test,pred))
    return result
if __name__=='__main__':restore()
