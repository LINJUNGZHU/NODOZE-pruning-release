"""One frozen RRF retrieval revision, no label access."""
import argparse,hashlib,json,resource,subprocess,time
from pathlib import Path
import numpy as np
from tc_pruning.frequency_diffusion import load_ledger
from tc_pruning.history_channel import interaction_groups
from tc_pruning.canonical_event_order_v7 import canonical_event_order
from tc_pruning.deferred_event_groups import GroupIndex
from tc_pruning.rasp import temporal_routes,temporal_fork_routes
from tc_pruning.temporal_diffusion import temporal_affinity
from tc_pruning.alternative_witnesses import validate_witness
from tc_pruning.group_completion import select
from tc_pruning.group_completion_rrf import build_rrf_pool
from tc_pruning.budget_evidence_v7 import atomic_gzip_json
from tc_pruning.sparse_edge_evaluation import sha256_file
from scripts.run_group_completion_v8 import load_history,witness_json,SOURCE_FILES
from scripts.history_channel_common import prepare_scores


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--case',type=int,required=True);p.add_argument('--data-root',type=Path,required=True);p.add_argument('--output-dir',type=Path,required=True);p.add_argument('--profile-only',action='store_true');a=p.parse_args()
    cfgpath=Path('configs/group_completion_v8_rrf.json');cfg=json.loads(cfgpath.read_text());info=cfg['cases'][a.case];out=a.output_dir/f'case{a.case}';mpath=out/'manifest.json.gz'
    if mpath.exists():raise FileExistsError(mpath)
    tick=time.perf_counter();ledger=a.data_root/info['ledger']
    if sha256_file(ledger)!=info['ledger_sha256']:raise ValueError('ledger mismatch')
    raw=load_ledger(ledger);history,hmeta=load_history(a.data_root/info['history_prefix'],raw,Path(cfg['score_config']));data,history=canonical_event_order(raw,history)
    scorecfg=json.loads(Path(cfg['score_config']).read_text());groups=GroupIndex.from_events(data['src'],data['dst'],data['relation'],data['timestamp'],data['tie'],cfg['group_window_ns'],cfg['group_relation_policy'])
    values,times,diags=prepare_scores(data,scorecfg,history,interaction_groups(data['src'],data['dst'],data['timestamp'],cfg['group_window_ns']),['history']);primary=values['history_channel']
    back=temporal_routes(data['src'],data['dst'],data['timestamp'],data['poi'])[0][0];parent,pivot,_,depth=temporal_fork_routes(data['src'],data['dst'],data['timestamp'],data['poi'],back);routes=(back,parent,pivot);mandatory=set(map(int,np.flatnonzero(data['poi'])))
    affinity=temporal_affinity(data['timestamp'],data['timestamp'][data['poi']],scorecfg['temporal_scale_ns']);path_view=affinity/(1+np.minimum(depth,len(data['ids'])));path_view[pivot<0]=0
    source_hashes={s:sha256_file(Path(s)) for s in SOURCE_FILES+['tc_pruning/group_completion_rrf.py','scripts/run_group_completion_rrf_v8.py',str(cfgpath)]}
    pool,diag=build_rrf_pool(data,primary,history,path_view,groups,routes,mandatory,cfg['materialized_cap'],cfg['max_examined'],cfg['rrf_c']);poolpath=out/'pools'/'v8_rrf_group.json.gz';lookup={w.digest:w for w in pool.certificates}
    if not a.profile_only:
        atomic_gzip_json(poolpath,dict(method='v8_rrf_group',diag=diag,materialized_ids=[data['ids'][e] for e in pool.materialized_events],
            group_of={data['ids'][e]:int(pool.group_of[e]) for e in pool.materialized_events},group_weights={str(int(pool.group_of[e])):float(pool.group_weights[int(pool.group_of[e])]) for e in pool.materialized_events},event_scores={data['ids'][e]:float(pool.event_scores[e]) for e in pool.materialized_events},
            actions=[dict(anchors=[data['ids'][e] for e in x.anchors],events=[data['ids'][e] for e in x.events],witness_ids=list(x.witness_ids),group=x.group,level=x.level) for x in pool.actions],certificates=[witness_json(w,data) for w in pool.certificates]))
    decisions=[]
    for method,objective in [('v8_rrf_group_edge','edge'),('v8_rrf_group_concave','concave')]:
        for budget in cfg['budgets']:
            t=time.perf_counter();result=select(pool,mandatory,budget,objective,cfg['eta']);seconds=time.perf_counter()-t;ct=time.perf_counter();certids={wid for j in result.selected_bundles for wid in pool.actions[j].witness_ids};cert=[lookup[w] for w in sorted(certids)];cseconds=time.perf_counter()-ct;closed=set(mandatory)
            for w in cert:
                if not validate_witness(w,data['src'],data['dst'],data['timestamp'],data['poi']):raise ValueError('illegal certificate')
                closed.update(w.events)
            if closed!=set(result.selected_events) or len(closed)>budget:raise ValueError('closure/budget mismatch')
            path=out/'decisions'/f'{method}-b{budget}.json.gz';content=dict(case_index=a.case,method=method,budget=budget,selected_ids=sorted(data['ids'][i] for i in closed),mandatory_ids=sorted(data['ids'][i] for i in mandatory),certificates=[witness_json(w,data) for w in cert],ledger_sha256=info['ledger_sha256'],labels_used=False,selection_seconds=seconds,certificate_seconds=cseconds,pool_sha256=sha256_file(poolpath) if not a.profile_only else None,candidate_scope='bounded',objective_value=result.objective_value,policy=result.policy,selected_bundles=len(result.selected_bundles),trace=list(result.trace))
            if not a.profile_only:atomic_gzip_json(path,content)
            decisions.append(dict(method=method,budget=budget,selected_events=len(closed),selection_seconds=seconds,path=str(path),sha256=sha256_file(path) if not a.profile_only else None,trace=list(result.trace),objective_value=result.objective_value))
            print('DECISION',a.case,method,budget,len(closed),round(seconds,3),flush=True)
    manifest=dict(protocol=cfg['protocol'],case_index=a.case,name=info['name'],ledger_path=str(ledger),ledger_sha256=info['ledger_sha256'],config_sha256=sha256_file(cfgpath),source_sha256=source_hashes,execution_git_commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),candidate_events=len(data['ids']),pool_records=[dict(method='v8_rrf_group',path=str(poolpath),sha256=sha256_file(poolpath) if not a.profile_only else None,diag=diag)],decisions=decisions,score_seconds=times,elapsed_seconds=time.perf_counter()-tick,peak_rss_mib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024,labels_used=False,profile_only=a.profile_only)
    atomic_gzip_json(mpath,manifest);print('SAVED',a.case,round(manifest['elapsed_seconds'],2),flush=True)

if __name__=='__main__':main()
