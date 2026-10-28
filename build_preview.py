"""Embed measured evidence in a standalone preview; never substitute invented scores."""
import json
from pathlib import Path
root=Path(__file__).resolve().parent
results=json.loads((root/'evidence/results.json').read_text())
examples=json.loads((root/'data/demo_samples.json').read_text())
def js(v):return json.dumps(v,allow_nan=False).replace('<','\\u003c')
html=(root/'web/template.html').read_text().replace('__RESULTS__',js(results)).replace('__EXAMPLES__',js(examples))
(root/'web/index.html').write_text(html)
print(root/'web/index.html')
