"""Label-independent frozen marginal witness / MILP comparison, v5."""
import argparse,gzip,json,resource,time
from pathlib import Path
import numpy as np
from tc_pruning.frequency_diffusion import load_ledger,score,semantic_continuations
from tc_pruning.temporal_diffusion import temporal_affinity
from tc_pruning.marginal_witness import make_pool,greedy_select,milp_select
from tc_pruning.rasp import temporal_routes,temporal_fork_routes
from tc_pruning.sparse_edge_evaluation import sha256_file
from scripts.run_cross_domain_comparison import structure


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--case',type=int,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if a.output.exists():raise ValueError('refuse overwrite')
 cfg=json.loads(Path('configs/marginal_witness_v5.json').read_text());path=Path(f'/root/NODOZE-pruning-release/output/tc/temporal-diffusion-v4/case{a.case}.json.gz')
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
  tick=time.perf_counter();context_ids=semantic_continuations(ledger,poi_ids=poi_set);context=np.array([e in context_ids for e in d['ids']],bool);context_seconds=time.perf_counter()-tick
  tick=time.perf_counter();base,bd=score(data,cfg);bt=time.perf_counter()-tick
  tick=time.perf_counter();affinity=temporal_affinity(d['timestamp'],d['timestamp'][data['poi']],cfg['temporal_scale_ns']);rerank=base*affinity;rt=bt+time.perf_counter()-tick
  tick=time.perf_counter();nofreq,nd=score(data,cfg,frequency=False);nofreq*=affinity;nt=time.perf_counter()-tick
  tick=time.perf_counter();back=temporal_routes(d['src'],d['dst'],d['timestamp'],data['poi'])[0][0];parent,pivot,_,_=temporal_fork_routes(d['src'],d['dst'],d['timestamp'],data['poi'],back);routes=(back,parent,pivot);route_seconds=time.perf_counter()-tick
  kernels={'marginal_rerank':rt,'marginal_linear':rt,'marginal_diverse4':rt,'marginal_milp':rt,'marginal_static':bt,'marginal_nofrequency':nt}
  for track in ['poi_only','shared_context']:
   mandatory=data['poi']|(context if track=='shared_context' else False)
   for cap in cfg['raw_budgets'] if name=='all' else [cfg['primary_budget']]:
    for kind,values in [('rerank',rerank),('static',base),('nofrequency',nofreq)]:
     methods=[('marginal_rerank',cfg['marginal_diversity']),('marginal_linear',0.),('marginal_diverse4',cfg['marginal_sensitivity'])] if kind=='rerank' else [('marginal_'+kind,1.)]
     if kind=='rerank' and name=='all' and cap in cfg['milp_budgets']:methods.append(('marginal_milp',None))
     if mandatory.sum()>cap:
      for method,lam in methods:results.append(dict(scenario=name,track=track,method=method,raw_cap=cap,mandatory_events=int(mandatory.sum()),status='infeasible_mandatory'))
      continue
     tick=time.perf_counter();pool=make_pool(values,d['relation'],mandatory,cap,d['tie'],routes,cfg['marginal_pool_minimum']);pool_seconds=time.perf_counter()-tick
     for method,lam in methods:
      header=dict(scenario=name,track=track,method=method,raw_cap=cap,mandatory_events=int(mandatory.sum()),witness_extension=True,pool=pool.diagnostics,pool_seconds=pool_seconds,route_seconds=route_seconds)
      tick=time.perf_counter()
      if lam is None:kept,meta=milp_select(pool,cap,cfg['milp_time_limit'],cfg['milp_relative_gap'])
      else:kept,meta=greedy_select(pool,cap,lam)
      elapsed=time.perf_counter()-tick
      if kept is None:results.append(header|dict(status='no_incumbent',optimizer=meta,selection_seconds=[elapsed]));continue
      assert kept[mandatory].all() and kept.sum()<=cap
      results.append(header|dict(status='ok',raw_events=int(kept.sum()),optimizer=meta,selection_seconds=[elapsed],**structure(data,kept),selected_ids=[d['ids'][j] for j in np.flatnonzero(kept)]))
    print(a.case,name,track,cap,'done',flush=True)
  scenarios.append(old|dict(marginal_context_seconds=context_seconds,marginal_route_seconds=route_seconds,method_kernel_seconds=old['method_kernel_seconds']|kernels,marginal_walk_diagnostics={'base':bd,'nofrequency':nd}))
 sources=['tc_pruning/marginal_witness.py','scripts/run_marginal_comparison.py','scripts/evaluate_marginal_witness.py','configs/marginal_witness_v5.json']
 report=prior|dict(config=cfg,protocol=cfg['protocol'],results=results,scenarios=scenarios,load_seconds=loaded-start,elapsed_seconds=time.perf_counter()-start,peak_rss_mib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024,
  reused_witness_report=str(path),reused_witness_sha256=sha256_file(path),reused_witness_config=prior['config'],source_sha256=prior['source_sha256']|{p:sha256_file(Path(p)) for p in sources})
 a.output.parent.mkdir(parents=True,exist_ok=True)
 with gzip.open(a.output,'wt') as f:json.dump(report,f)
 print('SAVED',a.output,flush=True)

if __name__=='__main__':main()
