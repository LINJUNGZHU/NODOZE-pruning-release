"""Post-selection label diagnosis and finite-pool label oracle; never imported by runner."""
import argparse,csv,gzip,json,math,time
from collections import defaultdict
from pathlib import Path
import numpy as np
from scipy.optimize import Bounds,LinearConstraint,milp
from scipy.sparse import coo_matrix
from tc_pruning.frequency_diffusion import load_ledger
from tc_pruning.rasp import temporal_routes,temporal_fork_routes
from tc_pruning.sparse_edge_evaluation import sha256_file


def read(path):
    with gzip.open(path,'rt') as f:return json.load(f)


def first_loss_stage(event,universe,reachable,pool,mandatory,budget,selected):
    if event not in universe:return 'raw_ledger_missing'
    if event in selected:return 'selected'
    if not reachable:return 'time_rule_unreachable'
    materialized=pool.get('_materialized_set')
    if materialized is None:materialized=set(pool['materialized_ids'])
    if event not in materialized:return 'candidate_not_materialized'
    actions=pool.get('_event_to_actions',{}).get(event)
    if actions is None:actions=[a for a in pool['actions'] if event in a['event_ids']]
    if not actions:return 'candidate_not_materialized'
    if all(len(set(a['event_ids'])|mandatory)>budget for a in actions):return 'certificate_alone_over_budget'
    return 'not_attributed'


def label_oracle(pool,mandatory,positive,budget,time_limit=20.):
    """Maximize known-positive IDs in an identical finite action/certificate pool."""
    mandatory=set(mandatory);positive=set(positive)
    if len(mandatory)>budget:return dict(status='infeasible_mandatory_budget',incumbent_tp=None,upper_bound_tp=None)
    actions=pool['actions'];events=sorted(mandatory|{e for a in actions for e in a['event_ids']});idx={e:i for i,e in enumerate(events)}
    n=len(events);m=len(actions);groups=defaultdict(list)
    incidence=[];reverse=defaultdict(list)
    for j,a in enumerate(actions):
        groups[a['anchor_id']].append(j)
        for eid in a['event_ids']:
            e=idx[eid];incidence.append((e,j));reverse[e].append(j)
    rows=[];cols=[];vals=[];upper=[]
    def constraint(terms,ub):
        r=len(upper);upper.append(float(ub))
        for col,val in terms:
            rows.append(r);cols.append(col);vals.append(val)
    for e,j in incidence:constraint([(n+j,1.),(e,-1.)],0.)
    for e,eid in enumerate(events):
        if eid not in mandatory:constraint([(e,1.)]+[(n+j,-1.) for j in reverse[e]],0.)
    constraint([(e,1.) for e in range(n)],float(budget))
    for js in groups.values():
        if len(js)>1:constraint([(n+j,1.) for j in js],1.)
    matrix=coo_matrix((vals,(rows,cols)),shape=(len(upper),n+m)).tocsc()
    lower=np.zeros(n+m)
    for e in mandatory:lower[idx[e]]=1
    objective=np.zeros(n+m)
    for e in positive&set(events):objective[idx[e]]=-1
    tick=time.perf_counter()
    r=milp(c=objective,integrality=np.ones(n+m),bounds=Bounds(lower,np.ones(n+m)),
           constraints=LinearConstraint(matrix,np.full(len(upper),-np.inf),np.array(upper)),
           options=dict(time_limit=time_limit,mip_rel_gap=0.,presolve=True))
    elapsed=time.perf_counter()-tick
    bound=getattr(r,'mip_dual_bound',None)
    upper_bound=-float(bound) if bound is not None and math.isfinite(bound) else None
    incumbent=None;cost=None
    if r.x is not None:
        x=np.asarray(r.x)
        if not np.isfinite(x).all() or np.max(np.abs(x-np.rint(x)))>1e-5:raise ValueError('nonbinary oracle incumbent')
        selected={events[e] for e in range(n) if x[e]>.5}
        chosen=[j for j in range(m) if x[n+j]>.5]
        closure=mandatory|{eid for j in chosen for eid in actions[j]['event_ids']}
        if closure!=selected or len(selected)>budget:raise ValueError('oracle closure/budget failure')
        if len({actions[j]['anchor_id'] for j in chosen})!=len(chosen):raise ValueError('oracle selected alternatives of one anchor')
        incumbent=len(selected&positive);cost=len(selected)
    gap=getattr(r,'mip_gap',None);gap=float(gap) if gap is not None and math.isfinite(gap) else None
    if incumbent is None:status='no_incumbent'
    elif upper_bound is not None and abs(upper_bound-incumbent)<1e-6:status='optimal'
    else:status='feasible_gap'
    if upper_bound is not None and incumbent is not None and upper_bound+1e-5<incumbent:raise ValueError('invalid oracle upper bound')
    return dict(status=status,incumbent_tp=incumbent,upper_bound_tp=upper_bound,selected_events=cost,
                solver_status=int(r.status),solver_message=str(r.message),gap=gap,seconds=elapsed,
                n_variables=n+m,n_constraints=len(upper),n_actions=m,n_pool_events=n,scope='finite_pool_known_positive_label_oracle')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input-dir',type=Path,required=True);p.add_argument('--output-dir',type=Path,required=True)
    p.add_argument('--oracle-time',type=float,default=20.);a=p.parse_args()
    stage_path=a.output_dir/'candidate_stage_audit.csv';oracle_path=a.output_dir/'oracle_bounds.csv'
    if stage_path.exists() or oracle_path.exists():raise FileExistsError('diagnosis already exists')
    ref=json.loads(Path('docs/sparse-five-local-critical-reference.json').read_text())
    audit=json.loads(Path('docs/budget-evidence-v7/input_audit.json').read_text())
    stages=[];bounds=[]
    for case in range(5):
        m=read(a.input_dir/f'case{case}'/'manifest.json.gz');d=load_ledger(Path(audit['cases'][case]['inputs']['ledger']['path']))
        universe=set(d['ids']);lookup={eid:i for i,eid in enumerate(d['ids'])}
        back=temporal_routes(d['src'],d['dst'],d['timestamp'],d['poi'])[0][0]
        pivot=temporal_fork_routes(d['src'],d['dst'],d['timestamp'],d['poi'],back)[1]
        positive=ref['cases'][case]['critical_event_ids'];pools={}
        for item in m['runs']:
            row=read(item['path']);budget=row['budget'];selected=set(row['selected_ids'] or ());mandatory=set(row['mandatory_ids'])
            if item['pool_path']:
                path=item['pool_path']
                if path not in pools:
                    pool=read(path);pool['_materialized_set']=set(pool['materialized_ids'])
                    reverse=defaultdict(list)
                    for action in pool['actions']:
                        for eid in action['event_ids']:reverse[eid].append(action)
                    pool['_event_to_actions']=reverse;pools[path]=pool
                pool=pools[path]
            else:
                # Full-candidate legacy selector has no saved per-anchor certificates.
                pool={'materialized_ids':list(universe),'actions':[], '_materialized_set':universe}
            counts=defaultdict(int)
            for eid in positive:
                st=first_loss_stage(eid,universe,bool(pivot[lookup[eid]]>=0) if eid in lookup else False,pool,mandatory,budget,selected)
                if not item['pool_path'] and st=='candidate_not_materialized':st='not_attributed'
                counts[st]+=1
            # E0 has selected IDs but no persisted per-anchor executable pool.
            # Its candidate closure cannot be inferred from the full ledger.
            closure=len(set(positive)&pool['_materialized_set'])/len(positive) if item['pool_path'] else None
            stages.append(dict(run_id=row['run_id'],case_index=case,method=row['method'],budget=budget,
                               selected_known=counts['selected'],known_total=len(positive),materialized_closure_recall=closure,
                               potential_descriptor_members=pool['diagnostics'].get('n_potential_members') if item['pool_path'] and pool['diagnostics'].get('representation')=='group' else None,
                               **{name:counts[name] for name in ['raw_ledger_missing','time_rule_unreachable','candidate_not_materialized','certificate_alone_over_budget','not_attributed']}))
        # Predeclared tractable diagnostic: E3 k1/k3, both budgets, identical pool per k.
        for k in (1,3):
            path=str(a.input_dir/f'case{case}'/'pools'/f'e3-c{case}-k{k}.json.gz')
            pool=pools[path]
            for budget in (256,1024):
                result=label_oracle(pool,set(d['ids'][i] for i in np.flatnonzero(d['poi'])),set(positive),budget,a.oracle_time)
                bounds.append(dict(case_index=case,k=k,budget=budget,pool_sha256=sha256_file(Path(path)),**result))
                print('ORACLE',case,k,budget,result['status'],result['incumbent_tp'],result['upper_bound_tp'],flush=True)
        print('STAGES',case,flush=True)
    a.output_dir.mkdir(parents=True,exist_ok=True)
    for path,records in [(stage_path,stages),(oracle_path,bounds)]:
        tmp=path.with_suffix('.pending')
        with tmp.open('w') as f:
            w=csv.DictWriter(f,fieldnames=list(records[0]),lineterminator='\n');w.writeheader();w.writerows(records)
        tmp.replace(path)
    print('SAVED',len(stages),'stage rows',len(bounds),'oracle rows',flush=True)


if __name__=='__main__':main()
