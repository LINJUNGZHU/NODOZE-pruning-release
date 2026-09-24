"""Fresh-process temporal diffusion comparison; candidate load through selection."""
import argparse,gzip,json,resource,time
from pathlib import Path
import numpy as np
from tc_pruning.frequency_diffusion import load_ledger,score,episodes
from tc_pruning.temporal_diffusion import temporal_score,plain_score,temporal_affinity
from tc_pruning.diffusion_portfolio import portfolio_budget
from tc_pruning.degree_diffusion import degree_normalized_score
from tc_pruning.cross_domain_pruning import top_budget,group_members
from tc_pruning.paper_baselines import pcst_edges
from tc_pruning.sparse_edge_evaluation import sha256_file

p=argparse.ArgumentParser(description=__doc__);p.add_argument('--case',type=int,required=True);p.add_argument('--method',required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--reference-dir',type=Path,default=Path('/root/NODOZE-pruning-release/output/tc/temporal-diffusion-v3'))
a=p.parse_args();cfg=json.loads(Path('configs/temporal_diffusion_v1.json').read_text());cap=cfg['primary_budget']
ledger=Path(json.loads(Path('configs/sparse_five_local_critical_variants.json').read_text())['variants'][a.case]['ledger'])
if a.output.exists():raise ValueError('refuse overwrite')
start=time.perf_counter();d=load_ledger(ledger);loaded=time.perf_counter();m=d['poi']
if a.method in ['diffusion_top','time_rerank','static_portfolio','rerank_portfolio']:
 value,_=score(d,cfg)
 if a.method in ['time_rerank','rerank_portfolio']:value*=temporal_affinity(d['timestamp'],d['timestamp'][m],cfg['temporal_scale_ns'])
elif a.method in ['plain_ppr','heat_kernel']:value,_=plain_score(d,cfg,'heat' if a.method=='heat_kernel' else 'ppr')
elif a.method in ['degree_ppr','degree_heat']:value,_=degree_normalized_score(d,cfg,'heat' if a.method=='degree_heat' else 'ppr')
elif a.method=='time_only':value=temporal_affinity(d['timestamp'],d['timestamp'][m],cfg['temporal_scale_ns'])
elif a.method in ['temporal_top','temporal_pcst','temporal_portfolio']:value,_=temporal_score(d,cfg,cfg['temporal_scale_ns'])
else:raise ValueError('unknown method')
if a.method=='temporal_pcst':
 group=episodes(d['src'],d['dst'],d['relation'],d['timestamp'],cfg['episode_window_ns']);members=group_members(group)
 reps=np.array([g[0] for g in members]);cost=np.array([len(g) for g in members]);prize=np.zeros(len(members));np.maximum.at(prize,group,value);options=[]
 for mult in cfg['pcst_multipliers']:
  chosen=pcst_edges(d['src'][reps],d['dst'][reps],prize,cost,np.r_[d['src'][m],d['dst'][m]],mult);mask=chosen[group]|m
  if mask.sum()<=cap:options.append((float(prize[chosen].sum()),-int(mask.sum()),mult,mask))
 kept=max(options,key=lambda x:(x[0],x[1],-x[2]))[3] if options else m.copy()
elif a.method in ['static_portfolio','temporal_portfolio','rerank_portfolio']:kept=portfolio_budget(value,d['relation'],m,cap,d['tie'],.5)
else:kept=top_budget(value,m,cap,d['tie'])
end=time.perf_counter();rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024
with gzip.open(a.reference_dir/f'case{a.case}.json.gz','rt') as f:r=json.load(f)
expected=next(x for x in r['results'] if x['scenario']=='all' and x['method']==a.method and x['track']=='poi_only' and x['raw_cap']==cap)
assert {d['ids'][i] for i in np.flatnonzero(kept)}==set(expected['selected_ids'])
result=dict(case=a.case,method=a.method,raw_events=int(kept.sum()),raw_cap=cap,track='poi_only',load_seconds=loaded-start,after_load_seconds=end-loaded,frozen_candidate_pipeline_seconds=end-start,peak_rss_mib=rss,selection_matches_main=True,ledger_sha256=sha256_file(ledger),scope='fresh process single thread one sample; case jobs concurrent; excludes raw CDM/history model/evaluation/export')
a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2));print(a.case,a.method,'matched',round(end-start,2),flush=True)
