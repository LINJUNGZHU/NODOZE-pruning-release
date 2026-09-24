"""Post-selection pool audit; reference is read only after pool construction."""
import argparse,gzip,json
from pathlib import Path
import numpy as np
from tc_pruning.frequency_diffusion import load_ledger,score
from tc_pruning.temporal_diffusion import temporal_affinity
from tc_pruning.marginal_witness import make_pool
from tc_pruning.rasp import temporal_routes,temporal_fork_routes
from tc_pruning.sparse_edge_evaluation import sha256_file
p=argparse.ArgumentParser();p.add_argument('--case',type=int,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
if a.output.exists():raise ValueError('refuse overwrite')
with gzip.open(f'/root/NODOZE-pruning-release/output/tc/marginal-witness-v5/case{a.case}.json.gz','rt') as f:report=json.load(f)
for source,h in report['source_sha256'].items():assert sha256_file(Path(source))==h
cfg=report['config'];d=load_ledger(Path(report['ledger']));value,_=score(d,cfg);value*=temporal_affinity(d['timestamp'],d['timestamp'][d['poi']],cfg['temporal_scale_ns'])
back=temporal_routes(d['src'],d['dst'],d['timestamp'],d['poi'])[0][0];parent,pivot,_,_=temporal_fork_routes(d['src'],d['dst'],d['timestamp'],d['poi'],back)
pool=make_pool(value,d['relation'],d['poi'],cfg['primary_budget'],d['tie'],(back,parent,pivot),cfg['marginal_pool_minimum'])
anchor_ids={d['ids'][i] for i in pool.anchors};event_ids={d['ids'][i] for i in pool.events};eligible={d['ids'][i] for i in np.flatnonzero((pivot>=0)&(value>0))}
ref=json.loads(Path('docs/sparse-five-local-critical-reference.json').read_text())['cases'][a.case]
positive=set(ref['critical_event_ids']);selected=next(r for r in report['results'] if r['method']=='marginal_rerank' and r['scenario']=='all' and r['track']=='poi_only' and r['raw_cap']==cfg['primary_budget'])
assert selected['pool']==pool.diagnostics
result=dict(case=a.case,name=ref['name'],budget=cfg['primary_budget'],scope='post-selection local-positive diagnostic, not used for selecting',pool=pool.diagnostics,positive_events=len(positive),eligible_positive_events=len(positive&eligible),anchor_positive_events=len(positive&anchor_ids),pool_union_positive_events=len(positive&event_ids),selected_positive_events=len(positive&set(selected['selected_ids'])),reference_sha256=sha256_file(Path('docs/sparse-five-local-critical-reference.json')))
a.output.write_text(json.dumps(result,indent=2));print(result,flush=True)
