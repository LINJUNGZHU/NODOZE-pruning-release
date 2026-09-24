"""Frozen historical conditional frequency / channel retrieval comparison."""
import argparse,gzip,json,resource,time
from pathlib import Path
import numpy as np
from tc_pruning.frequency_diffusion import load_ledger,semantic_continuations
from tc_pruning.history_channel import interaction_groups,expanded_pool
from tc_pruning.marginal_witness import make_pool,greedy_select,milp_select
from tc_pruning.witness_portfolio import witness_portfolio
from tc_pruning.rasp import temporal_routes,temporal_fork_routes
from tc_pruning.sparse_edge_evaluation import sha256_file
from scripts.run_cross_domain_comparison import structure
from scripts.history_channel_common import load_history,prepare_scores


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--case',type=int,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if a.output.exists():raise ValueError('refuse overwrite')
 cfg=json.loads(Path('configs/history_channel_v6.json').read_text());path=Path(f'/root/NODOZE-pruning-release/output/tc/marginal-witness-v5-matched/case{a.case}.json.gz')
 with gzip.open(path,'rt') as f:prior=json.load(f)
 for key,val in prior['config'].items():
  if key not in ['protocol','primary_method'] and cfg[key]!=val:raise ValueError('shared configuration changed: '+key)
 for source,h in prior['source_sha256'].items():
  if sha256_file(Path(source))!=h:raise ValueError('prior source changed: '+source)
 ledger=Path(prior['ledger'])
 if sha256_file(ledger)!=prior['ledger_sha256']:raise ValueError('ledger changed')
 start=time.perf_counter();d=load_ledger(ledger);loaded=time.perf_counter();history,hmeta=load_history(a.case,cfg,d)
 if hmeta['ledger_sha256']!=prior['ledger_sha256']:raise ValueError('history ledger mismatch')
 tick=time.perf_counter();groups=interaction_groups(d['src'],d['dst'],d['timestamp'],cfg['channel_window_ns']);group_seconds=time.perf_counter()-tick
 results=list(prior['results']);scenarios=[]
 families=[('original',[('entry_pool','expanded',1.)]),('history',[('history_only','base',1.)]),('original_channel',[('channel_only','expanded',1.)]),
  ('history_channel',[('history_channel','expanded',1.),('history_channel_linear','expanded',0.),('history_channel_portfolio','portfolio',1.),('history_channel_milp','expanded',None)]),
  ('nofrequency_channel',[('channel_nofrequency','expanded',1.)]),('ppr_channel',[('channel_ppr','expanded',1.)]),('heat_channel',[('channel_heat','expanded',1.)])]
 for old in prior['scenarios']:
  name=old['scenario'];data=dict(d);poi_set=set(old['poi_ids']);data['poi']=np.array([e in poi_set for e in d['ids']],bool)
  tick=time.perf_counter();context_ids=semantic_continuations(ledger,poi_ids=poi_set);context=np.array([e in context_ids for e in d['ids']],bool);context_seconds=time.perf_counter()-tick
  tick=time.perf_counter();back=temporal_routes(d['src'],d['dst'],d['timestamp'],data['poi'])[0][0];parent,pivot,_,_=temporal_fork_routes(d['src'],d['dst'],d['timestamp'],data['poi'],back);routes=(back,parent,pivot);route_seconds=time.perf_counter()-tick
  values,times,diags=prepare_scores(data,cfg,history,groups)
  for track in ['poi_only','shared_context']:
   mandatory=data['poi']|(context if track=='shared_context' else False)
   for cap in cfg['raw_budgets'] if name=='all' else [cfg['primary_budget']]:
    for kind,methods in families:
     pools={};value=values[kind]
     for method,pool_kind,lam in methods:
      if lam is None and (name!='all' or cap not in cfg['history_milp_budgets']):continue
      header=dict(scenario=name,track=track,method=method,raw_cap=cap,mandatory_events=int(mandatory.sum()),witness_extension=True,route_seconds=route_seconds,channel_group_seconds=group_seconds)
      if mandatory.sum()>cap:results.append(header|dict(status='infeasible_mandatory'));continue
      if pool_kind!='portfolio' and pool_kind not in pools:
       tick=time.perf_counter()
       if pool_kind=='base':pool=make_pool(value,d['relation'],mandatory,cap,d['tie'],routes,cfg['marginal_pool_minimum'])
       else:pool=expanded_pool(value,d['relation'],mandatory,cap,d['tie'],routes,groups,cfg['marginal_pool_minimum'],cfg['channel_pool_minimum'],cfg['channel_pool_multiplier'])
       pools[pool_kind]=(pool,time.perf_counter()-tick)
      if pool_kind=='portfolio':
       tick=time.perf_counter();kept=witness_portfolio(value,d['relation'],mandatory,cap,d['tie'],routes,cfg['portfolio_fraction']);meta=dict(status='ok',full_candidate_selector=True);elapsed=time.perf_counter()-tick
      else:
       pool,pool_seconds=pools[pool_kind];header.update(pool=pool.diagnostics,pool_seconds=pool_seconds);tick=time.perf_counter()
       if lam is None:kept,meta=milp_select(pool,cap,cfg['milp_time_limit'],cfg['milp_relative_gap'])
       else:kept,meta=greedy_select(pool,cap,lam)
       elapsed=time.perf_counter()-tick
      if kept is None:results.append(header|dict(status='no_incumbent',optimizer=meta,selection_seconds=[elapsed]));continue
      assert kept[mandatory].all() and kept.sum()<=cap
      results.append(header|dict(status='ok',raw_events=int(kept.sum()),optimizer=meta,selection_seconds=[elapsed],**structure(data,kept),selected_ids=[d['ids'][j] for j in np.flatnonzero(kept)]))
    print(a.case,name,track,cap,'done',flush=True)
  kernels={m:times[kind] for kind,methods in families for m,pk,lam in methods}
  scenarios.append(old|dict(history_context_seconds=context_seconds,history_route_seconds=route_seconds,method_kernel_seconds=old['method_kernel_seconds']|kernels,history_channel_walk_diagnostics=diags))
 sources=['tc_pruning/history_channel.py','scripts/prepare_conditional_history.py','scripts/history_channel_common.py','scripts/run_history_channel.py','configs/history_channel_v6.json']
 report=prior|dict(config=cfg,protocol=cfg['protocol'],results=results,scenarios=scenarios,history_preparation=hmeta,history_channel_group_seconds=group_seconds,
  history_load_seconds=loaded-start,history_elapsed_seconds=time.perf_counter()-start,history_peak_rss_mib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024,
  reused_v5_report=str(path),reused_v5_sha256=sha256_file(path),reused_v5_config=prior['config'],source_sha256=prior['source_sha256']|{p:sha256_file(Path(p)) for p in sources})
 a.output.parent.mkdir(parents=True,exist_ok=True);tmp=a.output.with_suffix('.pending')
 with gzip.open(tmp,'wt') as f:json.dump(report,f)
 tmp.replace(a.output);print('SAVED',a.output,flush=True)

if __name__=='__main__':main()
