"""Frozen graph-kernel comparison; no label input. Reuses audited v2 baselines."""
import argparse,gzip,json,resource,time
from pathlib import Path
import numpy as np
from tc_pruning.frequency_diffusion import load_ledger,score,episodes,semantic_continuations,select_episodes
from tc_pruning.temporal_diffusion import temporal_score,plain_score,temporal_affinity,stratified_budget
from tc_pruning.cross_domain_pruning import top_budget,group_members
from tc_pruning.paper_baselines import pcst_edges
from tc_pruning.rasp import temporal_routes,temporal_fork_routes
from tc_pruning.sparse_edge_evaluation import sha256_file
from scripts.run_cross_domain_comparison import structure


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--case',type=int,required=True);p.add_argument('--output',type=Path,required=True)
 a=p.parse_args();cfg=json.loads(Path('configs/temporal_diffusion_v1.json').read_text())
 if a.output.exists():raise ValueError('refuse overwrite')
 prior_path=Path(f'/root/NODOZE-pruning-release/output/tc/cross-domain-v2/case{a.case}.json.gz')
 with gzip.open(prior_path,'rt') as f:prior=json.load(f)
 for path,digest in prior['source_sha256'].items():
  if sha256_file(Path(path))!=digest:raise ValueError('reused baseline source changed: '+path)
 ledger=Path(prior['ledger'])
 if sha256_file(ledger)!=prior['ledger_sha256']:raise ValueError('candidate changed')
 start=time.perf_counter();d=load_ledger(ledger);load_seconds=time.perf_counter()-start
 tick=time.perf_counter();group=episodes(d['src'],d['dst'],d['relation'],d['timestamp'],cfg['episode_window_ns']);members=group_members(group)
 group_seconds=time.perf_counter()-tick;representatives=np.array([m[0] for m in members]);costs=np.array([len(m) for m in members])
 results=[r|{'reused_v2':True} for r in prior['results']];scenarios=[]
 for old in prior['scenarios']:
  name=old['scenario'];data=dict(d);data['poi']=np.array([e in set(old['poi_ids']) for e in d['ids']],bool)
  tick=time.perf_counter();context_ids=semantic_continuations(ledger,poi_ids=set(old['poi_ids']));context=np.array([e in context_ids for e in d['ids']],bool)
  back=temporal_routes(d['src'],d['dst'],d['timestamp'],data['poi'])[0][0];parent,pivot,_,_=temporal_fork_routes(d['src'],d['dst'],d['timestamp'],data['poi'],back)
  prep=time.perf_counter()-tick;scores={};cost={};diagnostics={}
  tick=time.perf_counter();base,diag=score(data,cfg);base_seconds=time.perf_counter()-tick;diagnostics['base']=diag
  tick=time.perf_counter();scores['time_rerank']=base*temporal_affinity(d['timestamp'],d['timestamp'][data['poi']],cfg['temporal_scale_ns']);cost['time_rerank']=base_seconds+time.perf_counter()-tick
  settings={'temporal_top':{},'temporal_nofreq':{'frequency':False},'temporal_nocontrast':{'contrast':False},'temporal_short':{'scale_ns':cfg['temporal_sensitivity_ns'][0]},'temporal_long':{'scale_ns':cfg['temporal_sensitivity_ns'][1]}}
  if name!='all':settings={'temporal_top':{}}
  for method,settings_for_method in settings.items():
   tick=time.perf_counter();scores[method],diagnostics[method]=temporal_score(data,cfg,**({'scale_ns':cfg['temporal_scale_ns']}|settings_for_method));cost[method]=time.perf_counter()-tick
  if name=='all':
   for method,kernel in [('plain_ppr','ppr'),('heat_kernel','heat')]:
    tick=time.perf_counter();scores[method],diagnostics[method]=plain_score(data,cfg,kernel);cost[method]=time.perf_counter()-tick
   scores['relation_stratified']=base;cost['relation_stratified']=base_seconds
   scores['temporal_episode']=scores['temporal_top'];cost['temporal_episode']=cost['temporal_top']
   tick=time.perf_counter();prizes=np.zeros(len(members));np.maximum.at(prizes,group,scores['temporal_top']);pcst=[]
   for multiplier in cfg['pcst_multipliers']:
    chosen=pcst_edges(d['src'][representatives],d['dst'][representatives],prizes,costs,np.r_[d['src'][data['poi']],d['dst'][data['poi']]],multiplier)
    pcst.append((float(prizes[chosen].sum()),multiplier,chosen[group]))
   cost['temporal_pcst']=cost['temporal_top']+time.perf_counter()-tick;scores['temporal_pcst']=scores['temporal_top']
  for track in ['poi_only','shared_context']:
   mandatory=data['poi']|(context if track=='shared_context' else False)
   mandatory_ids={d['ids'][j] for j in np.flatnonzero(mandatory)}
   # Verify actual mandatory IDs on every reused baseline row, and rerun old top-K.
   for r in results:
    if not r.get('reused_v2') or r['scenario']!=name or r['track']!=track or r['status']!='ok':continue
    selected=set(r['selected_ids']);assert mandatory_ids<=selected
    if r['method']=='diffusion_top' and r['raw_cap']==cfg['primary_budget']:
     chosen=top_budget(base,mandatory,r['raw_cap'],d['tie']);assert selected=={d['ids'][j] for j in np.flatnonzero(chosen)}
   for method,value in scores.items():
    for cap in cfg['raw_budgets'] if name=='all' else [cfg['primary_budget']]:
     header=dict(scenario=name,track=track,method=method,raw_cap=cap,reused_v2=False,mandatory_events=int(mandatory.sum()))
     if mandatory.sum()>cap:results.append(header|dict(status='infeasible_mandatory'));continue
     times=[];previous=None;extra={}
     for _ in range(3 if cap==cfg['primary_budget'] and name=='all' and method!='temporal_pcst' else 1):
      tick=time.perf_counter()
      if method=='temporal_episode':kept=select_episodes(value,data['poi'],back,parent,pivot,group,cap,d['tie'],mandatory)
      elif method=='relation_stratified':kept=stratified_budget(value,d['relation'],mandatory,cap,d['tie'])
      elif method=='temporal_pcst':
       options=[(prize,-int((mask|mandatory).sum()),mult,mask|mandatory) for prize,mult,mask in pcst if (mask|mandatory).sum()<=cap]
       if options:
        prize,neg,mult,kept=max(options,key=lambda x:(x[0],x[1],-x[2]));extra={'pcst_multiplier':mult}
       else:kept=mandatory.copy();extra={'pcst_multiplier':None}
      else:kept=top_budget(value,mandatory,cap,d['tie'])
      times.append(time.perf_counter()-tick)
      if previous is not None:assert np.array_equal(previous,kept)
      previous=kept.copy()
     assert kept[mandatory].all() and kept.sum()<=cap
     results.append(header|dict(status='ok',raw_events=int(kept.sum()),episodes=len(np.unique(group[kept])),selection_seconds=times,**structure(data,kept),**extra,selected_ids=[d['ids'][j] for j in np.flatnonzero(kept)]))
   print(a.case,name,track,'done',flush=True)
  scenarios.append(old|dict(new_preprocessing_seconds=prep,method_kernel_seconds=cost,new_walk_diagnostics=diagnostics))
 report=prior|dict(protocol=cfg['protocol'],config=cfg,results=results,scenarios=scenarios,load_seconds=load_seconds,group_seconds=group_seconds,elapsed_seconds=time.perf_counter()-start,peak_rss_mib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024,
  reused_baseline_report=str(prior_path),reused_baseline_sha256=sha256_file(prior_path),reused_baseline_source=prior['source_sha256'],reused_context_independently_checked=True,
  source_sha256={path:sha256_file(Path(path)) for path in list(prior['source_sha256'])+['tc_pruning/temporal_diffusion.py','scripts/run_temporal_comparison.py']})
 a.output.parent.mkdir(parents=True,exist_ok=True)
 with gzip.open(a.output,'wt') as f:json.dump(report,f)
 print('SAVED',a.output,flush=True)

if __name__=='__main__':main()
