"""Run graph/NLP-inspired pruning with public kernels; never read labels."""
from __future__ import annotations
import argparse,gzip,importlib.metadata,json,platform,resource,time
from pathlib import Path
import numpy as np
from scipy.sparse import coo_matrix
from scipy.sparse.csgraph import connected_components
from tc_pruning.frequency_diffusion import load_ledger,episodes,score,select_episodes,semantic_continuations
from tc_pruning.cross_domain_pruning import top_budget,select_coverage,group_members
from tc_pruning.paper_baselines import local_degree_scores,pcst_edges
from tc_pruning.rasp import temporal_routes,temporal_fork_routes
from tc_pruning.sparse_edge_evaluation import sha256_file


def structure(d,mask):
    src,dst,ts,poi=(d[k][mask] for k in ('src','dst','timestamp','poi'))
    nodes,inv=np.unique(np.r_[src,dst],return_inverse=True);n=len(src)
    a,b=inv[:n],inv[n:]
    graph=coo_matrix((np.ones(n),(a,b)),shape=(len(nodes),len(nodes))).tocsr()
    count,labels=connected_components(graph,directed=False)
    seeded=np.unique(np.r_[labels[a[poi]],labels[b[poi]]])
    seeded_fraction=float(np.isin(labels[a],seeded).mean())
    reach=temporal_fork_routes(src,dst,ts,poi)[2]
    return dict(components=int(count),poi_component_fraction=seeded_fraction,temporal_fork_fraction=float(reach.mean()))


def run_case(case_index,config,output):
    start=time.perf_counter();variants=json.loads(Path('configs/sparse_five_local_critical_variants.json').read_text())['variants']
    ledger=Path(variants[case_index]['ledger']);d=load_ledger(ledger);load_time=time.perf_counter()-start
    tick=time.perf_counter();group=episodes(d['src'],d['dst'],d['relation'],d['timestamp'],config['episode_window_ns'])
    members=group_members(group);representatives=np.array([ids[0] for ids in members]);costs=np.array([len(ids) for ids in members])
    group_time=time.perf_counter()-tick
    tick=time.perf_counter();degree=local_degree_scores(d['src'],d['dst'],len(d['semantic']));degree_time=time.perf_counter()-tick
    original_pois=np.flatnonzero(d['poi']);scenarios=[('all',None)]
    if len(original_pois)>1:scenarios += [(f'drop-{j}',int(i)) for j,i in enumerate(original_pois)]
    results=[];metadata=[]
    for scenario,removed in scenarios:
        data=dict(d);data['poi']=d['poi'].copy()
        if removed is not None:data['poi'][removed]=False
        poi_ids={d['ids'][i] for i in np.flatnonzero(data['poi'])}
        tick=time.perf_counter();context_ids=semantic_continuations(ledger,poi_ids=poi_ids)
        context=np.asarray([e in context_ids for e in d['ids']],bool)
        backward=temporal_routes(d['src'],d['dst'],d['timestamp'],data['poi'])[0][0]
        parent,pivot,_,_=temporal_fork_routes(d['src'],d['dst'],d['timestamp'],data['poi'],backward)
        routes=(backward,parent,pivot);prep_time=time.perf_counter()-tick
        tick=time.perf_counter();full,diag=score(data,config);full_time=time.perf_counter()-tick
        tick=time.perf_counter();nofreq,nodiag=score(data,config,frequency=False);nofreq_time=time.perf_counter()-tick
        pcst=[];pcst_time=0.
        if scenario=='all':
            tick=time.perf_counter();prize=np.zeros(len(members));np.maximum.at(prize,group,full)
            for multiplier in config['pcst_multipliers']:
                chosen=pcst_edges(d['src'][representatives],d['dst'][representatives],prize,costs,
                                  np.r_[d['src'][data['poi']],d['dst'][data['poi']]],multiplier)
                mask=chosen[group]
                pcst.append((multiplier,mask,float(prize[chosen].sum())))
            pcst_time=time.perf_counter()-tick
        metadata.append(dict(scenario=scenario,poi_ids=sorted(poi_ids),removed_poi=d['ids'][removed] if removed is not None else None,
            context_events=int(context.sum()),preprocessing_seconds=prep_time,scoring_seconds=full_time,
            nofrequency_seconds=nofreq_time,pcst_grid_seconds=pcst_time,
            pcst_grid_sizes=[dict(multiplier=m,raw_events=int(mask.sum()),prize=p) for m,mask,p in pcst],
            all_walks_converged=all(x['converged'] for z in (diag,nodiag) for x in z['walks'])))
        methods=['old_score_top','rarity_top','diffusion_top','localdegree_top','episode','coverage_exact',
                 'coverage_semantic','coverage_no_frequency','pcst_native']
        methods += [f'random_{seed}' for seed in config['random_seeds']]
        if scenario!='all':methods=config['sensitivity_methods']
        budgets=config['raw_budgets'] if scenario=='all' else [config['primary_budget']]
        for track in ('poi_only','shared_context'):
            mandatory=data['poi'] | (context if track=='shared_context' else False)
            for method in methods:
                for cap in budgets:
                    base=dict(scenario=scenario,track=track,method=method,raw_cap=cap)
                    if int(mandatory.sum())>cap:
                        results.append(base|dict(status='infeasible_mandatory',mandatory_events=int(mandatory.sum())));continue
                    repeats=config['timing_repeats'] if scenario=='all' and cap==config['primary_budget'] and method!='pcst_native' and not method.startswith('random_') else 1
                    timings=[];previous=None;extra={}
                    for _ in range(repeats):
                        tick=time.perf_counter()
                        if method=='pcst_native':
                            feasible=[]
                            for mult,mask,value in pcst:
                                lifted=mask|mandatory
                                if lifted.sum()<=cap:feasible.append((value,-int(lifted.sum()),mult,lifted))
                            if feasible:
                                value,neg,mult,kept=max(feasible,key=lambda x:(x[0],x[1],-x[2]));extra=dict(pcst_multiplier=mult,pcst_prize=value)
                            else:kept=mandatory.copy();extra=dict(pcst_multiplier=None,pcst_prize=0.,pcst_status='no_feasible_grid_solution')
                        elif method=='episode':
                            kept=select_episodes(full,data['poi'],*routes,group,cap,d['tie'],mandatory=mandatory)
                        elif method.startswith('coverage_'):
                            values=nofreq if method=='coverage_no_frequency' else full
                            kept=select_coverage(data,values,group,routes,cap,mandatory=mandatory,semantic=method!='coverage_exact')
                        else:
                            values={'old_score_top':d['old_score'],'rarity_top':d['rarity'],'diffusion_top':full,'localdegree_top':degree}.get(method)
                            if method.startswith('random_'):values=np.random.default_rng(int(method.split('_')[1])).random(len(group))
                            kept=top_budget(values,mandatory,cap,d['tie'])
                        timings.append(time.perf_counter()-tick)
                        if previous is not None and not np.array_equal(previous,kept):raise ValueError('nondeterministic repeated selector')
                        previous=kept.copy()
                    assert int(kept.sum())<=cap and kept[mandatory].all()
                    results.append(base|dict(status='ok',raw_events=int(kept.sum()),episodes=len(np.unique(group[kept])),
                        mandatory_events=int(mandatory.sum()),selection_seconds=timings,**structure(data,kept),**extra,
                        selected_ids=[d['ids'][i] for i in np.flatnonzero(kept)]))
                print(f'case{case_index} {scenario} {track} {method} done',flush=True)
    files=['tc_pruning/frequency_diffusion.py','tc_pruning/cross_domain_pruning.py','tc_pruning/paper_baselines.py',
           'tc_pruning/rasp.py','tc_pruning/rasp_diverse.py','tc_pruning/poi_semantic_continuation.py','scripts/run_cross_domain_comparison.py']
    report=dict(protocol=config['protocol'],case_index=case_index,ledger=str(ledger),ledger_sha256=sha256_file(ledger),
        config=config,source_sha256={p:sha256_file(Path(p)) for p in files},labels_used_for_selection=False,
        versions={p:importlib.metadata.version(p) for p in ('numpy','scipy','networkit','pcst_fast')},python=platform.python_version(),
        candidate_events=len(group),candidate_episodes=len(members),load_seconds=load_time,group_seconds=group_time,
        localdegree_seconds=degree_time,scenarios=metadata,results=results,
        elapsed_seconds=time.perf_counter()-start,peak_rss_mib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024)
    with gzip.open(output,'wt') as f:json.dump(report,f)
    print(f'SAVED {output}',flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--case',type=int,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--config',type=Path,default=Path('configs/cross_domain_v1.json'))
    a=p.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True)
    if a.output.exists():raise ValueError('refusing to overwrite experiment')
    run_case(a.case,json.loads(a.config.read_text()),a.output)
