"""Local prediction server. Run python server.py, then open http://127.0.0.1:8765."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
import argparse, io, json
import joblib
import pandas as pd
from pipeline import numeric_frame
ROOT=Path(__file__).resolve().parent
MAX_BYTES=2*1024*1024
MAX_ROWS=2000

class Handler(BaseHTTPRequestHandler):
    bundle=None
    def send(self,status,body,kind='application/json'):
        if not isinstance(body,bytes):body=json.dumps(body,allow_nan=False).encode()
        self.send_response(status)
        self.send_header('Content-Type',kind)
        self.send_header('Content-Length',str(len(body)))
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Cache-Control','no-store')
        self.end_headers();self.wfile.write(body)
    def do_GET(self):
        path=urlparse(self.path).path
        routes={'/':('web/index.html','text/html; charset=utf-8'),
          '/api/results':('evidence/results.json','application/json'),
          '/api/examples':('data/demo_samples.json','application/json'),
          '/sample.csv':('data/prediction_sample.csv','text/csv'),
          '/evidence/results.json':('evidence/results.json','application/json'),
          '/evidence/holdout_predictions.csv':('evidence/holdout_predictions.csv','text/csv')}
        if path not in routes:return self.send(404,{'error':'Not found'})
        filename,kind=routes[path]
        try:self.send(200,(ROOT/filename).read_bytes(),kind)
        except FileNotFoundError:self.send(503,{'error':'Run python pipeline.py first'})
    def do_POST(self):
        if urlparse(self.path).path!='/api/predict':return self.send(404,{'error':'Not found'})
        # A localhost demo: require same-origin browser requests, never accept arbitrary model files.
        origin=self.headers.get('Origin')
        expected='http://'+self.headers.get('Host','')
        if origin and origin!=expected:return self.send(403,{'error':'Origin not allowed'})
        try:
            length=int(self.headers.get('Content-Length','0'))
            if not 0<length<=MAX_BYTES:return self.send(413,{'error':'Input must be between 1 byte and 2 MiB'})
            payload=self.rfile.read(length)
            if self.headers.get('Content-Type','').startswith('text/csv'):
                data=pd.read_csv(io.BytesIO(payload),low_memory=False)
            else:
                items=json.loads(payload)
                if not isinstance(items,list):raise ValueError('Send a list of input records')
                data=pd.DataFrame(items)
            if not 1<=len(data)<=MAX_ROWS:raise ValueError('Send 1 to 2,000 rows')
            if data.columns.duplicated().any():raise ValueError('Duplicate column names')
            if self.bundle is None:
                # This file is created by pipeline.py; user-supplied joblib files are not accepted.
                Handler.bundle=joblib.load(ROOT/'models/traffic_model.joblib')
            X=numeric_frame(data,self.bundle['columns'])
            if X.isna().all(axis=1).any():raise ValueError('A row has no usable numeric measurements')
            pred=self.bundle['model'].predict(X)
            probs=self.bundle['model'].predict_proba(X)[:,1]
            self.send(200,{'rows':len(X),'missing_cells_imputed':int(X.isna().sum().sum()),
              'predictions':[{'row':i+1,'label':'Attack' if p else 'Normal',
                 'attack_probability':float(s)} for i,(p,s) in enumerate(zip(pred,probs))]})
        except (ValueError,TypeError,KeyError,UnicodeError,pd.errors.ParserError) as e:
            self.send(400,{'error':str(e)[:300]})
        except FileNotFoundError:self.send(503,{'error':'Model missing; run python pipeline.py'})
        except Exception:
            self.send(500,{'error':'Prediction failed. Check the local server console.'})
            raise

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--port',type=int,default=8765)
    args=p.parse_args()
    print(f'IIoT Traffic Lab: http://127.0.0.1:{args.port}',flush=True)
    ThreadingHTTPServer(('127.0.0.1',args.port),Handler).serve_forever()
