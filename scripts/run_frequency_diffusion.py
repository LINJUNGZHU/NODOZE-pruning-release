"""Run frozen five-case frequency/diffusion ablations without reading labels."""
from __future__ import annotations
import argparse,hashlib,json,resource,time
from pathlib import Path
import numpy as np
from tc_pruning.frequency_diffusion import load_ledger,episodes,score,select_episodes,semantic_continuations
from tc_pruning.rasp import temporal_routes,temporal_fork_routes
from tc_pruning.sparse_edge_evaluation import sha256_file


def run_case(ledger,config,output):
    start=time.perf_counter();d=load_ledger(ledger);load_seconds=time.perf_counter()-start
    n=len(d['ids']);src,dst,ts,poi=d['src'],d['dst'],d['timestamp'],d['poi']
    tick=time.perf_counter()
    group=episodes(src,dst,d['relation'],ts,config['episode_window_ns'])
    backward=temporal_routes(src,dst,ts,poi)[0][0]
    parent,pivot,reachable,depth=temporal_fork_routes(src,dst,ts,poi,backward)
    mandatory=np.zeros(n,bool)
    if config.get('semantic_hybrid'):
        continuation_ids=semantic_continuations(ledger)
        mandatory=np.asarray([e in continuation_ids for e in d['ids']],bool)
    preprocessing=time.perf_counter()-tick
    results=[];diagnostics={};scoring={}
    full=None
    for method,kwargs in config['methods'].items():
        tick=time.perf_counter();values,diag=score(d,config,**kwargs);scoring[method]=time.perf_counter()-tick
        diagnostics[method]=diag
        if method=='full':full=values
        for cap in config['raw_budgets']:
            tick=time.perf_counter();kept=select_episodes(values,poi,backward,parent,pivot,group,cap,d['tie'])
            results.append(record(d,group,kept,method,cap,time.perf_counter()-tick))
        if config.get('semantic_hybrid') and method in ('full','classic'):
            for cap in config['raw_budgets']:
                if int((mandatory|poi).sum())>cap:
                    continue
                tick=time.perf_counter()
                kept=select_episodes(values,poi,backward,parent,pivot,group,cap,d['tie'],mandatory=mandatory)
                results.append(record(d,group,kept,method+'_hybrid',cap,time.perf_counter()-tick))
        print(f'{output.name} {method} done',flush=True)
    for method,values in [('no_episode_expansion',full),('old_score_top',d['old_score'])]:
        for cap in config['raw_budgets']:
            tick=time.perf_counter()
            if method=='old_score_top':
                kept=poi.copy();order=np.lexsort((d['tie'],-values));kept[order[~kept[order]][:cap-int(kept.sum())]]=True
            else:
                kept=select_episodes(values,poi,backward,parent,pivot,np.arange(n),cap,d['tie'])
            results.append(record(d,group,kept,method,cap,time.perf_counter()-tick))
    report=dict(ledger=str(ledger),ledger_sha256=sha256_file(ledger),config=config,
        source_sha256={p:sha256_file(Path(p)) for p in ['tc_pruning/frequency_diffusion.py','tc_pruning/rasp.py','tc_pruning/poi_semantic_continuation.py','scripts/run_frequency_diffusion.py']},
        mandatory_continuations=int(mandatory.sum()),candidate_events=n,candidate_episodes=int(group.max())+1,poi_ids=[d['ids'][i] for i in np.flatnonzero(poi)],
        labels_used_for_selection=False,load_seconds=load_seconds,preprocessing_seconds=preprocessing,
        scoring_seconds=scoring,diagnostics=diagnostics,results=results,
        elapsed_seconds=time.perf_counter()-start,peak_rss_mib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024)
    output.write_text(json.dumps(report,ensure_ascii=False,indent=2))
    print(f'SAVED {output}',flush=True)


def record(data,group,kept,method,cap,seconds):
    assert kept.sum()<=cap and kept[data['poi']].all()
    return dict(method=method,raw_cap=cap,raw_events=int(kept.sum()),episodes=len(np.unique(group[kept])),
                selection_seconds=seconds,selected_ids=[data['ids'][i] for i in np.flatnonzero(kept)])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--case',type=int,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--config',type=Path,default=Path('configs/frequency_diffusion_v1.json'))
    a=p.parse_args();config=json.loads(a.config.read_text())
    variants=json.loads(Path('configs/sparse_five_local_critical_variants.json').read_text())['variants']
    a.output.parent.mkdir(parents=True,exist_ok=True)
    if a.output.exists():raise ValueError('refusing to overwrite experiment')
    run_case(Path(variants[a.case]['ledger']),config,a.output)
