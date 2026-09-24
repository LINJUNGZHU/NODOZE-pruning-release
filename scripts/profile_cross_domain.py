"""One method/case in a fresh process: frozen-ledger load through selection."""
from __future__ import annotations
import argparse,gzip,json,resource,time
from pathlib import Path
import numpy as np
from tc_pruning.frequency_diffusion import load_ledger,episodes,score,select_episodes,semantic_continuations
from tc_pruning.cross_domain_pruning import top_budget,select_coverage,group_members
from tc_pruning.paper_baselines import local_degree_scores,pcst_edges
from tc_pruning.rasp import temporal_routes,temporal_fork_routes
from tc_pruning.sparse_edge_evaluation import sha256_file

p=argparse.ArgumentParser(description=__doc__);p.add_argument('--case',type=int,required=True);p.add_argument('--method',required=True)
p.add_argument('--reference-dir',type=Path,default=Path('/root/NODOZE-pruning-release/output/tc/cross-domain-v2'));p.add_argument('--track',default='poi_only',choices=['poi_only','shared_context']);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();cfg=json.loads(Path('configs/cross_domain_v2.json').read_text());cap=cfg['primary_budget']
variants=json.loads(Path('configs/sparse_five_local_critical_variants.json').read_text())['variants'];ledger=Path(variants[a.case]['ledger'])
if a.output.exists():raise ValueError('refusing to overwrite profile')
start=time.perf_counter();d=load_ledger(ledger);loaded=time.perf_counter()
mandatory=d['poi'].copy()
if a.track=='shared_context':
 ids=semantic_continuations(ledger);mandatory|=np.asarray([e in ids for e in d['ids']],bool)
if a.method=='localdegree_top':
 values=local_degree_scores(d['src'],d['dst'],len(d['semantic']));kept=top_budget(values,mandatory,cap,d['tie'])
else:
 values,_=score(d,cfg)
 if a.method=='diffusion_top':kept=top_budget(values,mandatory,cap,d['tie'])
 else:
  group=episodes(d['src'],d['dst'],d['relation'],d['timestamp'],cfg['episode_window_ns'])
  if a.method=='pcst_native':
   members=group_members(group);reps=np.array([m[0] for m in members]);costs=np.array([len(m) for m in members])
   prizes=np.zeros(len(members));np.maximum.at(prizes,group,values);options=[]
   for mult in cfg['pcst_multipliers']:
    chosen=pcst_edges(d['src'][reps],d['dst'][reps],prizes,costs,np.r_[d['src'][d['poi']],d['dst'][d['poi']]],mult)
    mask=chosen[group]|mandatory
    if mask.sum()<=cap:options.append((float(prizes[chosen].sum()),-int(mask.sum()),mult,mask))
   kept=max(options,key=lambda x:(x[0],x[1],-x[2]))[3] if options else mandatory.copy()
  else:
   back=temporal_routes(d['src'],d['dst'],d['timestamp'],d['poi'])[0][0]
   parent,pivot,_,_=temporal_fork_routes(d['src'],d['dst'],d['timestamp'],d['poi'],back)
   if a.method=='episode':kept=select_episodes(values,d['poi'],back,parent,pivot,group,cap,d['tie'],mandatory=mandatory)
   elif a.method=='coverage_semantic':kept=select_coverage(d,values,group,(back,parent,pivot),cap,mandatory=mandatory)
   else:raise ValueError('unknown method')
end=time.perf_counter();rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024
# Independent fresh-process selection must exactly match the frozen main run.
with gzip.open(a.reference_dir/f'case{a.case}.json.gz','rt') as f:reference=json.load(f)
expected=next(r for r in reference['results'] if r['scenario']=='all' and r['method']==a.method and r['track']==a.track and r['raw_cap']==cap)
selected={d['ids'][i] for i in np.flatnonzero(kept)}
assert selected==set(expected['selected_ids']) and int(kept.sum())<=cap
r=dict(case=a.case,method=a.method,track=a.track,raw_cap=cap,raw_events=int(kept.sum()),
 load_seconds=loaded-start,after_load_seconds=end-loaded,frozen_candidate_pipeline_seconds=end-start,
 peak_rss_mib=rss,selection_matches_main=True,ledger_sha256=sha256_file(ledger),
 scope='fresh process, one run, one thread; frozen-ledger load through selection; excludes raw-CDM import/historical-model construction and evaluation/export')
a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(r,indent=2));print(json.dumps(r),flush=True)
