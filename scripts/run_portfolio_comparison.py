"""Frozen global/typed budget portfolio comparison, independent of labels."""
import argparse,gzip,json,resource,time
from pathlib import Path
import numpy as np
from tc_pruning.frequency_diffusion import load_ledger,score,semantic_continuations
from tc_pruning.temporal_diffusion import temporal_score,temporal_affinity
from tc_pruning.diffusion_portfolio import portfolio_budget
from tc_pruning.sparse_edge_evaluation import sha256_file
from scripts.run_cross_domain_comparison import structure


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--case',type=int,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if a.output.exists():raise ValueError('refuse overwrite')
 cfg=json.loads(Path('configs/temporal_diffusion_v3.json').read_text());path=Path(f'/root/NODOZE-pruning-release/output/tc/temporal-diffusion-v2/case{a.case}.json.gz')
 with gzip.open(path,'rt') as f:prior=json.load(f)
 for key,val in prior['config'].items():
  if key not in ['protocol','primary_method'] and cfg[key]!=val:raise ValueError('shared configuration changed: '+key)
 for source,h in prior['source_sha256'].items():
  if sha256_file(Path(source))!=h:raise ValueError('prior source changed: '+source)
 ledger=Path(prior['ledger'])
 if sha256_file(ledger)!=prior['ledger_sha256']:raise ValueError('ledger changed')
 start=time.perf_counter();d=load_ledger(ledger);loaded=time.perf_counter();results=list(prior['results']);scenarios=[]
 for old in prior['scenarios']:
  name=old['scenario'];data=dict(d);poi_set=set(old['poi_ids']);data['poi']=np.array([e in poi_set for e in d['ids']],bool)
  tick=time.perf_counter();context_ids=semantic_continuations(ledger,poi_ids=poi_set);context=np.array([e in context_ids for e in d['ids']],bool);prep=time.perf_counter()-tick
  tick=time.perf_counter();base,bd=score(data,cfg);bt=time.perf_counter()-tick
  tick=time.perf_counter();temporal,td=temporal_score(data,cfg,cfg['temporal_scale_ns']);tt=time.perf_counter()-tick
  tick=time.perf_counter();rerank=base*temporal_affinity(d['timestamp'],d['timestamp'][data['poi']],cfg['temporal_scale_ns']);rt=bt+time.perf_counter()-tick
  methods={'temporal_portfolio':(temporal,tt,.5),'static_portfolio':(base,bt,.5),'rerank_portfolio':(rerank,rt,.5)}
  if name=='all':methods|={'portfolio_quarter':(temporal,tt,.25),'portfolio_three_quarters':(temporal,tt,.75)}
  for track in ['poi_only','shared_context']:
   mandatory=data['poi']|(context if track=='shared_context' else False)
   for method,(value,seconds,fraction) in methods.items():
    for cap in cfg['raw_budgets'] if name=='all' else [cfg['primary_budget']]:
     header=dict(scenario=name,track=track,method=method,raw_cap=cap,mandatory_events=int(mandatory.sum()),portfolio_extension=True)
     if mandatory.sum()>cap:results.append(header|dict(status='infeasible_mandatory'));continue
     times=[];previous=None
     for _ in range(3 if name=='all' and cap==cfg['primary_budget'] else 1):
      tick=time.perf_counter();kept=portfolio_budget(value,d['relation'],mandatory,cap,d['tie'],fraction);times.append(time.perf_counter()-tick)
      if previous is not None:assert np.array_equal(previous,kept)
      previous=kept.copy()
     assert kept[mandatory].all() and kept.sum()<=cap
     results.append(header|dict(status='ok',raw_events=int(kept.sum()),selection_seconds=times,**structure(data,kept),selected_ids=[d['ids'][j] for j in np.flatnonzero(kept)]))
   print(a.case,name,track,'done',flush=True)
  scenarios.append(old|dict(portfolio_preprocessing_seconds=prep,method_kernel_seconds=old['method_kernel_seconds']|{m:t for m,(v,t,f) in methods.items()},portfolio_walk_diagnostics={'base':bd,'temporal':td}))
 report=prior|dict(config=cfg,protocol=cfg['protocol'],results=results,scenarios=scenarios,load_seconds=loaded-start,elapsed_seconds=time.perf_counter()-start,peak_rss_mib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024,
  reused_typed_report=str(path),reused_typed_sha256=sha256_file(path),reused_typed_config=prior['config'],source_sha256=prior['source_sha256']|{p:sha256_file(Path(p)) for p in ['tc_pruning/diffusion_portfolio.py','scripts/run_portfolio_comparison.py']})
 a.output.parent.mkdir(parents=True,exist_ok=True)
 with gzip.open(a.output,'wt') as f:json.dump(report,f)
 print('SAVED',a.output,flush=True)

if __name__=='__main__':main()
