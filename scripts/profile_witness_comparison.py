"""Fresh-process load/score/temporal routes/selection measurements for v4."""
import argparse,gzip,json,resource,time
from pathlib import Path
import numpy as np
from tc_pruning.frequency_diffusion import load_ledger,score
from tc_pruning.temporal_diffusion import temporal_score,temporal_affinity
from tc_pruning.witness_portfolio import witness_portfolio
from tc_pruning.rasp import temporal_routes,temporal_fork_routes
from tc_pruning.sparse_edge_evaluation import sha256_file

p=argparse.ArgumentParser(description=__doc__);p.add_argument('--case',type=int,required=True);p.add_argument('--method',choices=['witness_static','witness_rerank','witness_temporal','witness_time_only','witness_global'],required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
if a.output.exists():raise ValueError('refuse overwrite')
cfg=json.loads(Path('configs/temporal_diffusion_v4.json').read_text());ledger=Path(json.loads(Path('configs/sparse_five_local_critical_variants.json').read_text())['variants'][a.case]['ledger'])
start=time.perf_counter();d=load_ledger(ledger);loaded=time.perf_counter()
if a.method=='witness_temporal':value,_=temporal_score(d,cfg,cfg['temporal_scale_ns'])
elif a.method=='witness_time_only':value=temporal_affinity(d['timestamp'],d['timestamp'][d['poi']],cfg['temporal_scale_ns'])
else:
 value,_=score(d,cfg)
 if a.method!='witness_static':value*=temporal_affinity(d['timestamp'],d['timestamp'][d['poi']],cfg['temporal_scale_ns'])
back=temporal_routes(d['src'],d['dst'],d['timestamp'],d['poi'])[0][0];parent,pivot,_,_=temporal_fork_routes(d['src'],d['dst'],d['timestamp'],d['poi'],back)
kept=witness_portfolio(value,d['relation'],d['poi'],cfg['primary_budget'],d['tie'],(back,parent,pivot),1. if a.method=='witness_global' else cfg['portfolio_fraction'])
end=time.perf_counter();rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024
with gzip.open(f'/root/NODOZE-pruning-release/output/tc/temporal-diffusion-v4/case{a.case}.json.gz','rt') as f:r=json.load(f)
expected=next(x for x in r['results'] if x['scenario']=='all' and x['method']==a.method and x['track']=='poi_only' and x['raw_cap']==cfg['primary_budget'])
assert {d['ids'][i] for i in np.flatnonzero(kept)}==set(expected['selected_ids'])
result=dict(case=a.case,method=a.method,raw_events=int(kept.sum()),raw_cap=cfg['primary_budget'],track='poi_only',load_seconds=loaded-start,after_load_seconds=end-loaded,frozen_candidate_pipeline_seconds=end-start,peak_rss_mib=rss,selection_matches_main=True,ledger_sha256=sha256_file(ledger),scope='fresh single-thread process; one sample; cases concurrent; includes routes; excludes raw-CDM/history model/evaluation/export')
a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2));print(a.case,a.method,'matched',round(end-start,2),flush=True)
