"""Frozen V8 development comparisons. This module never opens a label file."""
import argparse
import gzip
import hashlib
import json
import resource
import subprocess
import time
from pathlib import Path
import numpy as np
from tc_pruning.frequency_diffusion import load_ledger
from tc_pruning.history_channel import interaction_groups
from tc_pruning.canonical_event_order_v7 import canonical_event_order
from tc_pruning.deferred_event_groups import GroupIndex
from tc_pruning.rasp import temporal_routes,temporal_fork_routes
from tc_pruning.alternative_witnesses import build_witnesses,validate_witness
from tc_pruning.witness_portfolio import witness_portfolio
from tc_pruning.budget_evidence_v7 import build_snapshot,atomic_gzip_json
from tc_pruning.evidence_objective import select as edge_select
from tc_pruning.group_completion import build_pool,select,utility
from tc_pruning.temporal_diffusion import temporal_affinity
from tc_pruning.sparse_edge_evaluation import sha256_file
from scripts.history_channel_common import prepare_scores

SOURCE_FILES=['tc_pruning/group_completion.py','tc_pruning/temporal_diffusion.py','tc_pruning/candidate_views.py','tc_pruning/budget_evidence_v7.py','tc_pruning/evidence_objective.py',
 'tc_pruning/deferred_event_groups.py','tc_pruning/alternative_witnesses.py','tc_pruning/canonical_event_order_v7.py',
 'tc_pruning/frequency_diffusion.py','tc_pruning/history_channel.py','tc_pruning/rasp.py','tc_pruning/witness_portfolio.py',
 'scripts/history_channel_common.py','scripts/run_group_completion_v8.py','configs/group_completion_v8.json','configs/history_channel_v6.json']


def read(path):
    with gzip.open(path,'rt') as f:return json.load(f)


def load_history(prefix,data,score_config_path):
    meta=json.loads(prefix.with_suffix('.json').read_text())
    if meta['config_sha256']!=sha256_file(score_config_path):raise ValueError('historical config mismatch')
    for path,digest in meta['source_sha256'].items():
        if sha256_file(Path(path))!=digest:raise ValueError('historical source mismatch: '+path)
    if sha256_file(prefix.with_suffix('.npz'))!=meta['npz_sha256']:raise ValueError('historical cache hash mismatch')
    if sha256_file(prefix.with_suffix('.history.json.gz'))!=meta['history_sha256']:raise ValueError('historical records hash mismatch')
    ids=hashlib.sha256(''.join(e+'\n' for e in data['ids']).encode()).hexdigest()
    with np.load(prefix.with_suffix('.npz'),allow_pickle=False) as cache:
        if str(cache['ids_sha256'])!=ids:raise ValueError('historical event order mismatch')
        rarity=cache['rarity'].copy()
    if len(rarity)!=len(data['ids']) or not np.isfinite(rarity).all() or np.any((rarity<0)|(rarity>1)):raise ValueError('bad historical rarity')
    return rarity,meta


def witness_json(w,d):
    return dict(anchor=d['ids'][w.anchor],events=[d['ids'][e] for e in w.events],
                forward=[d['ids'][e] for e in w.forward_chain],backward=[d['ids'][e] for e in w.backward_chain],rule=w.rule,digest=w.digest)


def baseline_witnesses(selected,data,routes):
    selected=set(map(int,selected));cert=[];closed=set(map(int,np.flatnonzero(data['poi'])))
    for i in sorted(selected):
        ws=build_witnesses(i,data['src'],data['dst'],data['timestamp'],data['poi'],*routes,None,1)
        if ws and set(ws[0].events)<=selected:cert.append(ws[0]);closed.update(ws[0].events)
    if closed!=selected:raise ValueError('baseline could not certify complete event union')
    return cert


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--case',type=int,required=True)
    p.add_argument('--data-root',type=Path,default=Path('/root/NODOZE-pruning-release'))
    p.add_argument('--output-dir',type=Path,required=True);p.add_argument('--profile-only',action='store_true')
    a=p.parse_args();cfg_path=Path('configs/group_completion_v8.json');cfg=json.loads(cfg_path.read_text())
    info=next((c for c in cfg['cases'] if c['case_index']==a.case),None)
    if info is None:raise ValueError('unknown case')
    out=a.output_dir/f'case{a.case}';manifest_path=out/'manifest.json.gz'
    if manifest_path.exists():raise FileExistsError(manifest_path)
    tick=time.perf_counter();ledger=a.data_root/info['ledger']
    if sha256_file(ledger)!=info['ledger_sha256']:raise ValueError('ledger hash mismatch')
    data=load_ledger(ledger);raw_id_hash=hashlib.sha256(''.join(e+'\n' for e in data['ids']).encode()).hexdigest()
    scorecfg=json.loads(Path(cfg['score_config']).read_text());history,hmeta=load_history(a.data_root/info['history_prefix'],data,Path(cfg['score_config']))
    data,history=canonical_event_order(data,history)
    groups=GroupIndex.from_events(data['src'],data['dst'],data['relation'],data['timestamp'],data['tie'],cfg['group_window_ns'],cfg['group_relation_policy'])
    channels=interaction_groups(data['src'],data['dst'],data['timestamp'],cfg['group_window_ns'])
    scores,score_times,diags=prepare_scores(data,scorecfg,history,channels,['history','nofrequency'])
    primary=scores['history_channel'];back=temporal_routes(data['src'],data['dst'],data['timestamp'],data['poi'])[0][0]
    parent,pivot,_,depth=temporal_fork_routes(data['src'],data['dst'],data['timestamp'],data['poi'],back);routes=(back,parent,pivot)
    mandatory=set(map(int,np.flatnonzero(data['poi'])))
    source_hashes={p:sha256_file(Path(p)) for p in SOURCE_FILES}
    decisions=[];pool_records=[]
    def save(method,budget,selected,certificates,seconds,pool=None,extra=None):
        selected=set(map(int,selected));closed=set(mandatory)
        for w in certificates:
            if not validate_witness(w,data['src'],data['dst'],data['timestamp'],data['poi']):raise ValueError('illegal temporal witness')
            closed.update(w.events)
        if selected!=closed or len(selected)>budget or not mandatory<=selected:raise ValueError('invalid closure/budget')
        content=dict(case_index=a.case,method=method,budget=budget,selected_ids=sorted(data['ids'][i] for i in selected),
            mandatory_ids=sorted(data['ids'][i] for i in mandatory),certificates=[witness_json(w,data) for w in certificates],
            ledger_sha256=info['ledger_sha256'],labels_used=False,selection_seconds=seconds,pool_sha256=sha256_file(pool) if pool else None)
        if extra:content.update(extra)
        path=out/'decisions'/f'{method}-b{budget}.json.gz'
        if not a.profile_only:atomic_gzip_json(path,content)
        decisions.append(dict(method=method,budget=budget,selected_events=len(selected),selection_seconds=seconds,
            path=str(path),sha256=sha256_file(path) if not a.profile_only else None,**(extra or {})))
        print('DECISION',a.case,method,budget,len(selected),round(seconds,3),flush=True)
    def record_pool(method,pool,diag):
        path=out/'pools'/f'{method}.json.gz'
        if not a.profile_only:
            atomic_gzip_json(path,dict(method=method,diag=diag,materialized_ids=[data['ids'][e] for e in pool.materialized_events],
                group_of={data['ids'][e]:int(pool.group_of[e]) for e in pool.materialized_events},
                group_weights={str(int(pool.group_of[e])):float(pool.group_weights[int(pool.group_of[e])]) for e in pool.materialized_events},
                event_scores={data['ids'][e]:float(pool.event_scores[e]) for e in pool.materialized_events},
                actions=[dict(anchors=[data['ids'][e] for e in x.anchors],events=[data['ids'][e] for e in x.events],witness_ids=list(x.witness_ids),group=x.group,level=x.level) for x in pool.actions],
                certificates=[witness_json(w,data) for w in pool.certificates]))
        pool_records.append(dict(method=method,path=str(path),sha256=sha256_file(path) if not a.profile_only else None,diag=diag))
        return path if not a.profile_only else None
    # Strong original scoring/path portfolio: full ledger scope, explicitly different candidate resource.
    for budget in cfg['budgets']:
        t=time.perf_counter();mask=witness_portfolio(primary,data['relation'],data['poi'],budget,data['tie'],routes,scorecfg['portfolio_fraction'])
        seconds=time.perf_counter()-t;ct=time.perf_counter()
        cert=baseline_witnesses(np.flatnonzero(mask),data,routes)
        save('history_portfolio',budget,np.flatnonzero(mask),cert,seconds,extra={'candidate_scope':'full_ledger','certificate_seconds':time.perf_counter()-ct})
    affinity=temporal_affinity(data['timestamp'],data['timestamp'][data['poi']],scorecfg['temporal_scale_ns'])
    path_view=affinity/(1+np.minimum(depth,len(data['ids'])));path_view[pivot<0]=0
    legacy,diag=build_snapshot(data,primary,history,path_view,groups,routes,mandatory,'group','rrf',cfg['materialized_cap'],cfg['max_examined'])
    # Save original V7 candidate identity and real certificates, never imply free members.
    v7path=out/'pools'/'v7_group_edge.json.gz'
    if not a.profile_only:
        atomic_gzip_json(v7path,dict(method='v7_group_edge',diag=diag,materialized_ids=[data['ids'][e] for e in legacy.materialized_events],certificates=[witness_json(w,data) for w in legacy.certificates]))
    pool_records.append(dict(method='v7_group_edge',path=str(v7path),sha256=sha256_file(v7path) if not a.profile_only else None,diag=diag))
    lookup={w.digest:w for w in legacy.certificates}
    for budget in cfg['budgets']:
        t=time.perf_counter();result=edge_select(legacy,mandatory,budget,'edge_score')
        save('v7_group_edge',budget,result.selected_events,[lookup[w] for w in result.selected_witnesses],time.perf_counter()-t,
             v7path if not a.profile_only else None,{'candidate_scope':'bounded','objective_value':result.objective_value})
    del legacy,lookup
    for variant in ('group','representative','no_frequency'):
        values=scores['nofrequency_channel'] if variant=='no_frequency' else primary
        pool,diag=build_pool(data,values,groups,routes,mandatory,cfg['materialized_cap'],cfg['max_examined'],variant=='representative')
        key='v8_'+variant;path=record_pool(key,pool,diag);lookup={w.digest:w for w in pool.certificates}
        methods=[('v8_group_edge','edge'),('v8_group_concave','concave')] if variant=='group' else [('v8_'+variant+'_concave','concave')]
        for method,objective in methods:
            for budget in cfg['budgets']:
                t=time.perf_counter();result=select(pool,mandatory,budget,objective,cfg['eta'])
                seconds=time.perf_counter()-t;ct=time.perf_counter()
                certids={wid for j in result.selected_bundles for wid in pool.actions[j].witness_ids}
                cert=[lookup[w] for w in sorted(certids)]
                save(method,budget,result.selected_events,cert,seconds,path,
                    dict(candidate_scope='bounded',certificate_seconds=time.perf_counter()-ct,objective_value=result.objective_value,policy=result.policy,
                         selected_bundles=len(result.selected_bundles),trace=list(result.trace)))
        del pool,lookup
    manifest=dict(protocol=cfg['protocol'],case_index=a.case,name=info['name'],ledger_path=str(ledger),ledger_sha256=info['ledger_sha256'],
        config_sha256=sha256_file(cfg_path),source_sha256=source_hashes,raw_id_order_sha256=raw_id_hash,
        event_order='lexicographic_event_id',execution_git_commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
        candidate_events=len(data['ids']),groups=len(groups),poi_events=len(mandatory),score_seconds=score_times,
        history_supported_events=hmeta['supported_events'],pool_records=pool_records,decisions=decisions,
        elapsed_seconds=time.perf_counter()-tick,peak_rss_mib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024,
        labels_used=False,profile_only=a.profile_only)
    atomic_gzip_json(manifest_path,manifest)
    print('SAVED',a.case,round(manifest['elapsed_seconds'],2),round(manifest['peak_rss_mib'],1),flush=True)


if __name__=='__main__':main()
