"""Fresh-process candidate pipeline including scoring/routes/pool/optimization."""
import argparse,gzip,json,resource,time
from pathlib import Path
import numpy as np
from tc_pruning.frequency_diffusion import load_ledger,score
from tc_pruning.temporal_diffusion import temporal_affinity
from tc_pruning.marginal_witness import make_pool,greedy_select,milp_select
from tc_pruning.rasp import temporal_routes,temporal_fork_routes
from tc_pruning.sparse_edge_evaluation import sha256_file

p=argparse.ArgumentParser(description=__doc__);p.add_argument('--case',type=int,required=True);p.add_argument('--method',choices=['marginal_rerank','marginal_linear','marginal_milp'],required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
if a.output.exists():raise ValueError('refuse overwrite')
cfg=json.loads(Path('configs/marginal_witness_v5.json').read_text());ledger=Path(json.loads(Path('configs/sparse_five_local_critical_variants.json').read_text())['variants'][a.case]['ledger'])
start=time.perf_counter();d=load_ledger(ledger);loaded=time.perf_counter()
value,diag=score(d,cfg);value*=temporal_affinity(d['timestamp'],d['timestamp'][d['poi']],cfg['temporal_scale_ns']);scored=time.perf_counter()
back=temporal_routes(d['src'],d['dst'],d['timestamp'],d['poi'])[0][0];parent,pivot,_,_=temporal_fork_routes(d['src'],d['dst'],d['timestamp'],d['poi'],back);routed=time.perf_counter()
pool=make_pool(value,d['relation'],d['poi'],cfg['primary_budget'],d['tie'],(back,parent,pivot),cfg['marginal_pool_minimum']);pooled=time.perf_counter()
if a.method=='marginal_milp':kept,meta=milp_select(pool,cfg['primary_budget'],cfg['milp_time_limit'],cfg['milp_relative_gap'])
else:kept,meta=greedy_select(pool,cfg['primary_budget'],cfg['marginal_diversity'] if a.method=='marginal_rerank' else 0.)
end=time.perf_counter();rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024
with gzip.open(f'/root/NODOZE-pruning-release/output/tc/marginal-witness-v5/case{a.case}.json.gz','rt') as f:r=json.load(f)
for path,h in r['source_sha256'].items():assert sha256_file(Path(path))==h
expected=next(x for x in r['results'] if x['scenario']=='all' and x['method']==a.method and x['track']=='poi_only' and x['raw_cap']==cfg['primary_budget'])
ids=[d['ids'][i] for i in np.flatnonzero(kept)] if kept is not None else None
matches=set(ids or [])==set(expected.get('selected_ids',[])) and meta['status']==expected['status']
# A time-limited MILP can return a different incumbent; record, don't hide it.
if a.method!='marginal_milp':assert matches
result=dict(case=a.case,method=a.method,raw_events=len(ids) if ids is not None else None,raw_cap=cfg['primary_budget'],track='poi_only',load_seconds=loaded-start,scoring_seconds=scored-loaded,route_seconds=routed-scored,pool_seconds=pooled-routed,optimization_seconds=end-pooled,frozen_candidate_pipeline_seconds=end-start,peak_rss_mib=rss,selection_matches_main=matches,optimizer=meta,selected_ids=ids,ledger_sha256=sha256_file(ledger),scope='fresh process; one sample; concurrent cases; BLAS/OMP env=1, HiGHS internal thread default; includes routes and pool; excludes raw-CDM/history/evaluation/export')
a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2));print(a.case,a.method,'match',matches,round(end-start,2),flush=True)
