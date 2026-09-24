"""Run frozen P0/E2/E3 development comparisons without reading labels."""
import argparse,gzip,hashlib,json,resource,subprocess,time
from pathlib import Path
import numpy as np
from tc_pruning.frequency_diffusion import load_ledger,score
from tc_pruning.temporal_diffusion import temporal_affinity
from tc_pruning.history_channel import interaction_groups
from tc_pruning.deferred_event_groups import GroupIndex
from tc_pruning.canonical_event_order_v7 import canonical_event_order
from tc_pruning.rasp import temporal_routes,temporal_fork_routes
from tc_pruning.witness_portfolio import witness_portfolio
from tc_pruning.evidence_objective import CandidateSnapshot,select
from tc_pruning.budget_evidence_v7 import build_snapshot,expand_alternatives,atomic_gzip_json,verify_unique_ids
from tc_pruning.sparse_edge_evaluation import sha256_file
from scripts.history_channel_common import load_history,prepare_scores

SOURCE_FILES=['tc_pruning/candidate_views.py','tc_pruning/deferred_event_groups.py','tc_pruning/canonical_event_order_v7.py','tc_pruning/alternative_witnesses.py',
 'tc_pruning/evidence_objective.py','tc_pruning/budget_evidence_v7.py','scripts/run_budget_evidence_v7.py',
 'tc_pruning/frequency_diffusion.py','tc_pruning/history_channel.py','tc_pruning/rasp.py','tc_pruning/witness_portfolio.py',
 'scripts/history_channel_common.py','configs/budget_evidence_v7.json']


def checked_case(case,cfg,audit):
    info=audit['cases'][case]
    path=Path(info['inputs']['frozen_v6_decisions']['path'])
    if sha256_file(path)!=info['inputs']['frozen_v6_decisions']['sha256']:raise ValueError('v6 decision report changed')
    with gzip.open(path,'rt') as f:report=json.load(f)
    ledger=Path(report['ledger'])
    if sha256_file(ledger)!=info['inputs']['ledger']['sha256'] or report['ledger_sha256']!=info['reported_ledger_sha256']:raise ValueError('ledger changed')
    for p,h in report['source_sha256'].items():
        if sha256_file(Path(p))!=h:raise ValueError('frozen source changed: '+p)
    if report['config']!=json.loads(Path(cfg['source_v6_config']).read_text()):raise ValueError('v6 config changed')
    return report,ledger


def pool_payload(pool,data,diag,pool_id):
    cert={w.digest:w for w in pool.certificates}
    return dict(pool_id=pool_id,diagnostics=diag,materialized_ids=[data['ids'][i] for i in pool.materialized_events],
        actions=[dict(anchor_id=data['ids'][a.anchor],group_id=a.group,event_ids=[data['ids'][j] for j in a.events],score=a.score,witness_id=a.witness_id,
                      forward_chain=[data['ids'][j] for j in cert[a.witness_id].forward_chain],
                      backward_chain=[data['ids'][j] for j in cert[a.witness_id].backward_chain],rule=cert[a.witness_id].rule) for a in pool.actions])


def selection_payload(run_id,case,method,budget,kept,anchors,witnesses,objective,status,pool_hash,data,mandatory,config_hash,source_hashes,elapsed):
    selected=[data['ids'][i] for i in kept] if status=='ok' else None
    return dict(run_id=run_id,case_index=case,method=method,track='poi_only',budget=budget,status=status,
        selected_ids=selected,anchor_ids=[data['ids'][i] for i in anchors] if status=='ok' and anchors is not None else None,
        witness_ids=list(witnesses) if status=='ok' and witnesses is not None else None,
        mandatory_ids=[data['ids'][i] for i in sorted(mandatory)],n_selected_ledger=len(kept) if status=='ok' else None,
        n_selected_synthetic=sum(x.startswith('LINEAGE:') for x in selected) if selected is not None else None,
        n_selected_cdm=sum(not x.startswith('LINEAGE:') for x in selected) if selected is not None else None,
        objective=objective,objective_value=None if status!='ok' else None,
        pool_sha256=pool_hash,ledger_sha256=sha256_file(Path(data['ledger_path'])),config_sha256=config_hash,
        source_sha256=source_hashes,selection_seconds=elapsed)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--case',type=int,required=True);p.add_argument('--output-dir',type=Path,required=True);p.add_argument('--dry-run',action='store_true')
    a=p.parse_args();cfgpath=Path('configs/budget_evidence_v7.json');cfg=json.loads(cfgpath.read_text())
    if a.case not in cfg['cases']:raise ValueError('case outside fixed design')
    case_dir=a.output_dir/f'case{a.case}';manifest=case_dir/'manifest.json.gz'
    if manifest.exists():raise FileExistsError(manifest)
    expected=dict(case=a.case,e0=4,e2=8,e3=12,total=24,budgets=cfg['core_budgets'],output_dir=str(case_dir))
    if a.dry_run:print(json.dumps(expected,indent=2));return
    audit=json.loads(Path(cfg['input_audit']).read_text());start=time.perf_counter()
    report,ledger=checked_case(a.case,cfg,audit)
    d=load_ledger(ledger);verify_unique_ids(d['ids']);d['ledger_path']=str(ledger)
    if not np.array_equal(d['poi'],np.array([e in set(next(s for s in report['scenarios'] if s['scenario']=='all')['poi_ids']) for e in d['ids']],bool)):
        raise ValueError('POI mismatch')
    mandatory=set(map(int,np.flatnonzero(d['poi'])))
    history,hmeta=load_history(a.case,report['config'],d)
    g=interaction_groups(d['src'],d['dst'],d['timestamp'],cfg['group_window_ns'])
    groups=GroupIndex.from_events(d['src'],d['dst'],d['relation'],d['timestamp'],d['tie'],cfg['group_window_ns'],cfg['group_relation_policy'])
    vals,score_times,score_diags=prepare_scores(d,report['config'],history,g,['original','history'])
    primary=vals['history_channel'];v4score=vals['original']
    affinity=temporal_affinity(d['timestamp'],d['timestamp'][d['poi']],report['config']['temporal_scale_ns'])
    back=temporal_routes(d['src'],d['dst'],d['timestamp'],d['poi'])[0][0]
    parent,pivot,_,depth=temporal_fork_routes(d['src'],d['dst'],d['timestamp'],d['poi'],back)
    routes=(back,parent,pivot)
    path_view=affinity/(1+np.minimum(depth,len(d['ids'])));path_view[pivot<0]=0
    source_hashes={f:sha256_file(Path(f)) for f in SOURCE_FILES}
    config_hash=sha256_file(cfgpath);runs=[];pools=[]
    def save_selection(run_id,method,budget,kept,anchors=None,witnesses=None,objective=None,status='ok',pool_path=None,selection_seconds=0.,extra=None):
        poolhash=sha256_file(pool_path) if pool_path else None
        item=selection_payload(run_id,a.case,method,budget,kept,anchors,witnesses,objective,status,poolhash,d,mandatory,config_hash,source_hashes,selection_seconds)
        if extra:item.update(extra)
        path=case_dir/'selections'/f'{run_id}.json.gz';atomic_gzip_json(path,item)
        runs.append(dict(run_id=run_id,path=str(path),sha256=sha256_file(path),method=method,budget=budget,status=status,pool_path=str(pool_path) if pool_path else None,pool_sha256=poolhash))
    # E0: rerun both frozen selectors and require identical selected ID sets.
    for budget in cfg['core_budgets']:
        for method,value in [('witness_rerank',v4score),('history_channel_portfolio',primary)]:
            old=next(r for r in report['results'] if r['scenario']=='all' and r['track']=='poi_only' and r['method']==method and r['raw_cap']==budget)
            tick=time.perf_counter();kept=witness_portfolio(value,d['relation'],d['poi'],budget,d['tie'],routes,report['config']['portfolio_fraction'])
            ids={d['ids'][i] for i in np.flatnonzero(kept)}
            if ids!=set(old['selected_ids']):raise ValueError(f'E0 selection ID regression {a.case} {method} {budget}')
            run_id=f'e0-c{a.case}-b{budget}-{method}'
            save_selection(run_id,method,budget,np.flatnonzero(kept),objective='legacy_portfolio',selection_seconds=time.perf_counter()-tick,extra={'matched_frozen_ids':True})
    # The legacy ID regression above retains its historical row order. New
    # retrieval, fork witnesses and tie breaks use a fixed event-ID order.
    legacy_scoring_seconds=score_times
    d,history=canonical_event_order(d,history)
    mandatory=set(map(int,np.flatnonzero(d['poi'])))
    g=interaction_groups(d['src'],d['dst'],d['timestamp'],cfg['group_window_ns'])
    groups=GroupIndex.from_events(d['src'],d['dst'],d['relation'],d['timestamp'],d['tie'],cfg['group_window_ns'],cfg['group_relation_policy'])
    vals,score_times,score_diags=prepare_scores(d,report['config'],history,g,['history'])
    primary=vals['history_channel']
    affinity=temporal_affinity(d['timestamp'],d['timestamp'][d['poi']],report['config']['temporal_scale_ns'])
    back=temporal_routes(d['src'],d['dst'],d['timestamp'],d['poi'])[0][0]
    parent,pivot,_,depth=temporal_fork_routes(d['src'],d['dst'],d['timestamp'],d['poi'],back)
    routes=(back,parent,pivot)
    path_view=affinity/(1+np.minimum(depth,len(d['ids'])));path_view[pivot<0]=0
    # E2: exactly four representation/ranking cells, one frozen pool per cell reused across both budgets.
    selected_base=None
    for representation in ['event','group']:
        for rank_policy in ['primary','rrf']:
            pool_id=f'e2-c{a.case}-{representation}-{rank_policy}'
            pool,diag=build_snapshot(d,primary,history,path_view,groups,routes,mandatory,representation,rank_policy,
                cfg['materialized_event_cap'],cfg['max_examined_events'],cfg['rrf_c'])
            if not set(mandatory)<=set(pool.materialized_events):raise ValueError('pool omitted mandatory')
            pool_path=case_dir/'pools'/f'{pool_id}.json.gz';atomic_gzip_json(pool_path,pool_payload(pool,d,diag,pool_id))
            pools.append(dict(pool_id=pool_id,path=str(pool_path),sha256=sha256_file(pool_path),diagnostics=diag))
            for budget in cfg['core_budgets']:
                tick=time.perf_counter();s=select(pool,mandatory,budget,'edge_score')
                run_id=f'{pool_id}-b{budget}'
                save_selection(run_id,pool_id,budget,s.selected_events,s.selected_anchors,s.selected_witnesses,'edge_score',s.status,pool_path,time.perf_counter()-tick,
                    {'objective_value':s.objective_value,'steps':s.steps,'candidate_diagnostics':diag})
            if representation=='group' and rank_policy=='rrf':selected_base=pool
    if selected_base is None:raise ValueError('missing E3 source pool')
    # E3: same first N label-free anchors, same scoring, two path variants, each pool frozen across objectives/budgets.
    target=list(dict.fromkeys(a.anchor for a in selected_base.actions))[:cfg['e3_anchor_limit']]
    target_set=set(target)
    base_actions=tuple(a for a in selected_base.actions if a.anchor in target_set)
    base_certs=tuple(w for w in selected_base.certificates if w.anchor in target_set)
    base_events=tuple(sorted(set(mandatory)|{e for x in base_actions for e in x.events}))
    base_weights=np.zeros(len(groups),float)
    for x in base_actions:base_weights[x.group]=max(base_weights[x.group],x.score)
    base=CandidateSnapshot(base_actions,primary,base_weights,len(d['ids']),base_events,base_certs)
    for k in cfg['path_alternatives']:
        pool,diag=(base,dict(k=1,anchors=len(target),witnesses=len(base_actions),materialized_events=len(base_events),seconds=0.)) if k==1 else expand_alternatives(base,d,routes,groups,k)
        pool_id=f'e3-c{a.case}-k{k}';pool_path=case_dir/'pools'/f'{pool_id}.json.gz'
        atomic_gzip_json(pool_path,pool_payload(pool,d,diag,pool_id));pools.append(dict(pool_id=pool_id,path=str(pool_path),sha256=sha256_file(pool_path),diagnostics=diag))
        for objective in cfg['objectives']:
            for budget in cfg['core_budgets']:
                tick=time.perf_counter();s=select(pool,mandatory,budget,objective,cfg['eta'])
                run_id=f'{pool_id}-{objective}-b{budget}'
                save_selection(run_id,pool_id,budget,s.selected_events,s.selected_anchors,s.selected_witnesses,objective,s.status,pool_path,time.perf_counter()-tick,
                    {'objective_value':s.objective_value,'steps':s.steps,'candidate_diagnostics':diag,'eta':cfg['eta']})
    if len(runs)!=24:raise ValueError('incomplete core matrix')
    manifest_content=dict(protocol=cfg['protocol'],case_index=a.case,case_name=audit['cases'][a.case]['name'],
        execution_git_commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
        source_sha256=source_hashes,config_sha256=config_hash,ledger_sha256=report['ledger_sha256'],v6_sha256=audit['cases'][a.case]['inputs']['frozen_v6_decisions']['sha256'],
        history_supported_events=hmeta['supported_events'],legacy_scoring_seconds=legacy_scoring_seconds,
        scoring_seconds=score_times,walk_diagnostics=score_diags,event_order='lexicographic_event_id_for_E2_E3',
        candidate_groups=len(groups),runs=runs,pools=pools,elapsed_seconds=time.perf_counter()-start,
        peak_rss_mib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024,labels_used_for_selection=False)
    atomic_gzip_json(manifest,manifest_content)
    print('SAVED',manifest,'runs',len(runs),'elapsed',manifest_content['elapsed_seconds'],'rss',manifest_content['peak_rss_mib'],flush=True)


if __name__=='__main__':main()
