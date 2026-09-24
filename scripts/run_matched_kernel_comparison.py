"""Matched-selection PPR/heat formula adapters; frozen before v5 evaluation."""
import argparse,gzip,json,resource,time
from pathlib import Path
import numpy as np
from tc_pruning.frequency_diffusion import load_ledger,semantic_continuations
from tc_pruning.degree_diffusion import degree_normalized_score
from tc_pruning.temporal_diffusion import temporal_affinity
from tc_pruning.marginal_witness import make_pool,greedy_select
from tc_pruning.rasp import temporal_routes,temporal_fork_routes
from tc_pruning.sparse_edge_evaluation import sha256_file
from scripts.run_cross_domain_comparison import structure


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--case',type=int,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if a.output.exists():raise ValueError('refuse overwrite')
 path=Path(f'/root/NODOZE-pruning-release/output/tc/marginal-witness-v5/case{a.case}.json.gz')
 with gzip.open(path,'rt') as f:prior=json.load(f)
 cfg=prior['config']
 for source,h in prior['source_sha256'].items():
  if sha256_file(Path(source))!=h:raise ValueError('prior source changed: '+source)
 ledger=Path(prior['ledger'])
 if sha256_file(ledger)!=prior['ledger_sha256']:raise ValueError('ledger changed')
 start=time.perf_counter();d=load_ledger(ledger);loaded=time.perf_counter();results=list(prior['results']);scenarios=[]
 for old in prior['scenarios']:
  name=old['scenario'];data=dict(d);poi_set=set(old['poi_ids']);data['poi']=np.array([e in poi_set for e in d['ids']],bool)
  context_ids=semantic_continuations(ledger,poi_ids=poi_set);context=np.array([e in context_ids for e in d['ids']],bool)
  tick=time.perf_counter();back=temporal_routes(d['src'],d['dst'],d['timestamp'],data['poi'])[0][0];parent,pivot,_,_=temporal_fork_routes(d['src'],d['dst'],d['timestamp'],data['poi'],back);routes=(back,parent,pivot);route_seconds=time.perf_counter()-tick
  kernels={};diags={}
  for kind in ['ppr','heat']:
   method='marginal_'+kind;tick=time.perf_counter();values,diag=degree_normalized_score(data,cfg,kind);values*=temporal_affinity(d['timestamp'],d['timestamp'][data['poi']],cfg['temporal_scale_ns']);kernels[method]=time.perf_counter()-tick;diags[method]=diag
   for track in ['poi_only','shared_context']:
    mandatory=data['poi']|(context if track=='shared_context' else False)
    for cap in cfg['raw_budgets'] if name=='all' else [cfg['primary_budget']]:
     header=dict(scenario=name,track=track,method=method,raw_cap=cap,mandatory_events=int(mandatory.sum()),witness_extension=True,route_seconds=route_seconds)
     if mandatory.sum()>cap:results.append(header|dict(status='infeasible_mandatory'));continue
     tick=time.perf_counter();pool=make_pool(values,d['relation'],mandatory,cap,d['tie'],routes,cfg['marginal_pool_minimum']);pool_seconds=time.perf_counter()-tick
     tick=time.perf_counter();kept,meta=greedy_select(pool,cap,cfg['marginal_diversity']);elapsed=time.perf_counter()-tick
     assert kept[mandatory].all() and kept.sum()<=cap
     results.append(header|dict(status='ok',pool=pool.diagnostics,pool_seconds=pool_seconds,raw_events=int(kept.sum()),optimizer=meta,selection_seconds=[elapsed],**structure(data,kept),selected_ids=[d['ids'][j] for j in np.flatnonzero(kept)]))
   print(a.case,name,kind,'done',flush=True)
  scenarios.append(old|dict(method_kernel_seconds=old['method_kernel_seconds']|kernels,matched_walk_diagnostics=diags))
 report=prior|dict(results=results,scenarios=scenarios,matched_load_seconds=loaded-start,matched_elapsed_seconds=time.perf_counter()-start,matched_peak_rss_mib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024,
  reused_marginal_report=str(path),reused_marginal_sha256=sha256_file(path),source_sha256=prior['source_sha256']|{'scripts/run_matched_kernel_comparison.py':sha256_file(Path('scripts/run_matched_kernel_comparison.py'))})
 a.output.parent.mkdir(parents=True,exist_ok=True)
 with gzip.open(a.output,'wt') as f:json.dump(report,f)
 print('SAVED',a.output,flush=True)

if __name__=='__main__':main()
