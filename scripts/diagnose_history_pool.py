"""Post-selection diagnostics of the new candidate pool, never a selector input."""
import argparse,gzip,json
from pathlib import Path
import numpy as np
from tc_pruning.frequency_diffusion import load_ledger
from tc_pruning.history_channel import interaction_groups,expanded_pool
from tc_pruning.rasp import temporal_routes,temporal_fork_routes
from tc_pruning.sparse_edge_evaluation import sha256_file
from scripts.history_channel_common import load_history,prepare_scores
p=argparse.ArgumentParser();p.add_argument('--case',type=int,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
if a.output.exists():raise ValueError('refuse overwrite')
with gzip.open(f'/root/NODOZE-pruning-release/output/tc/history-channel-v6/case{a.case}.json.gz','rt') as f:report=json.load(f)
for source,h in report['source_sha256'].items():assert sha256_file(Path(source))==h
cfg=report['config'];d=load_ledger(Path(report['ledger']));history,_=load_history(a.case,cfg,d)
groups=interaction_groups(d['src'],d['dst'],d['timestamp'],cfg['channel_window_ns'])
values,_,_=prepare_scores(d,cfg,history,groups,['history']);v=values['history_channel']
back=temporal_routes(d['src'],d['dst'],d['timestamp'],d['poi'])[0][0];parent,pivot,_,_=temporal_fork_routes(d['src'],d['dst'],d['timestamp'],d['poi'],back)
pool=expanded_pool(v,d['relation'],d['poi'],cfg['primary_budget'],d['tie'],(back,parent,pivot),groups,cfg['marginal_pool_minimum'],cfg['channel_pool_minimum'],cfg['channel_pool_multiplier'])
ids={d['ids'][i] for i in pool.events};eligible={d['ids'][i] for i in np.flatnonzero((pivot>=0)&(v>0))}
refpath=Path('docs/sparse-five-local-critical-reference.json');ref=json.loads(refpath.read_text())['cases'][a.case];positive=set(ref['critical_event_ids'])
r=next(r for r in report['results'] if r['method']=='history_channel' and r['scenario']=='all' and r['track']=='poi_only' and r['raw_cap']==cfg['primary_budget']);assert pool.diagnostics==r['pool']
result=dict(case=a.case,budget=cfg['primary_budget'],positive_events=len(positive),eligible_positive_events=len(positive&eligible),pool_positive_events=len(positive&ids),selected_positive_events=len(positive&set(r['selected_ids'])),pool=pool.diagnostics,reference_sha256=sha256_file(refpath),scope='post-selection local-positive diagnostic, no selection use')
tmp=a.output.with_suffix('.pending');tmp.write_text(json.dumps(result,indent=2));tmp.replace(a.output);print(a.case,result['pool_positive_events'],result['selected_positive_events'],flush=True)
