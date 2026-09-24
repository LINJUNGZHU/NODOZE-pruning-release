"""Fresh-process warm-history-cache profiling of v6, including all retrieval costs."""
import argparse,gzip,json,resource,time
from pathlib import Path
import numpy as np
from tc_pruning.frequency_diffusion import load_ledger
from tc_pruning.history_channel import interaction_groups,expanded_pool
from tc_pruning.marginal_witness import greedy_select
from tc_pruning.rasp import temporal_routes,temporal_fork_routes
from tc_pruning.sparse_edge_evaluation import sha256_file
from scripts.history_channel_common import load_history,prepare_scores
p=argparse.ArgumentParser();p.add_argument('--case',type=int,required=True);p.add_argument('--method',choices=['history_channel','channel_only','channel_heat'],required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
if a.output.exists():raise ValueError('refuse overwrite')
cfg=json.loads(Path('configs/history_channel_v6.json').read_text());ledger=Path(json.loads(Path('configs/sparse_five_local_critical_variants.json').read_text())['variants'][a.case]['ledger'])
start=time.perf_counter();d=load_ledger(ledger);loaded=time.perf_counter();history,hmeta=load_history(a.case,cfg,d);cached=time.perf_counter()
groups=interaction_groups(d['src'],d['dst'],d['timestamp'],cfg['channel_window_ns']);grouped=time.perf_counter()
kind={'history_channel':'history','channel_only':'original','channel_heat':'heat'}[a.method]
values,_,_=prepare_scores(d,cfg,history,groups,[kind]);value=values[kind+'_channel'];scored=time.perf_counter()
back=temporal_routes(d['src'],d['dst'],d['timestamp'],d['poi'])[0][0];parent,pivot,_,_=temporal_fork_routes(d['src'],d['dst'],d['timestamp'],d['poi'],back);routed=time.perf_counter()
pool=expanded_pool(value,d['relation'],d['poi'],cfg['primary_budget'],d['tie'],(back,parent,pivot),groups,cfg['marginal_pool_minimum'],cfg['channel_pool_minimum'],cfg['channel_pool_multiplier']);pooled=time.perf_counter()
kept,meta=greedy_select(pool,cfg['primary_budget'],1.);end=time.perf_counter();rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024
with gzip.open(f'/root/NODOZE-pruning-release/output/tc/history-channel-v6/case{a.case}.json.gz','rt') as f:report=json.load(f)
for source,h in report['source_sha256'].items():assert sha256_file(Path(source))==h
expected=next(r for r in report['results'] if r['method']==a.method and r['scenario']=='all' and r['track']=='poi_only' and r['raw_cap']==cfg['primary_budget'])
assert {d['ids'][i] for i in np.flatnonzero(kept)}==set(expected['selected_ids'])
result=dict(case=a.case,method=a.method,load_seconds=loaded-start,cache_load_verify_seconds=cached-loaded,group_seconds=grouped-cached,score_seconds=scored-grouped,route_seconds=routed-scored,pool_seconds=pooled-routed,select_seconds=end-pooled,warm_candidate_pipeline_seconds=end-start,cold_history_build_seconds=hmeta['total_seconds'],peak_rss_mib=rss,selection_matches_main=True,pool=pool.diagnostics,
 scope='fresh process, one sample, concurrent cases, BLAS/OMP1; warm conditional-history cache; excludes raw CDM/import/history rebuild/export/evaluation. All three methods verify/load same cache even if original/heat do not use its rarity.')
a.output.parent.mkdir(parents=True,exist_ok=True);tmp=a.output.with_suffix('.pending');tmp.write_text(json.dumps(result,indent=2));tmp.replace(a.output)
print(a.case,a.method,'matched',round(end-start,2),flush=True)
