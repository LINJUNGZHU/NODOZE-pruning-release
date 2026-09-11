import copy
import itertools
import math
import numpy as np
import pytest
from tc_pruning.evidence_selection import select_evidence, witness_bundle, audit_selection, validate_routes, objective
from tc_pruning.rasp import personalized_pagerank, propagate


def case():
    return dict(src=np.array([2,1,0,2,3,9]),dst=np.array([3,2,1,3,4,10]),
                timestamp=np.array([5,3,1,4,6,7]),poi=np.array([1,0,0,0,0,0],bool),
                backward=np.array([-1,0,1,-1,-1,-1]),parent=np.array([-1,-1,-1,1,3,-1]),
                pivot=np.array([0,1,2,1,1,-1]),evidence=np.array([1.,0.,2.,.5,4.,9.]),
                family=np.arange(6),tie_keys=[(i,) for i in range(6)])


def solve(x,budget,**kwargs):
    return select_evidence(x['evidence'],x['poi'],x['backward'],x['parent'],x['pivot'],x['family'],budget,x['tie_keys'],**kwargs)


def independent_value(chosen,x):
    groups={}
    for i in chosen:
        if x['pivot'][i]>=0 and x['evidence'][i]>0:
            g=int(x['family'][i]);groups[g]=groups.get(g,0)+x['evidence'][i]
    weights={g:max(x['evidence'][j] for j in range(6) if x['family'][j]==g and x['pivot'][j]>=0) for g in groups}
    return .05*sum(groups.values())+.95*sum(weights[g]*math.log1p(v/weights[g]) for g,v in groups.items())


def test_whole_bundle_greedy_matches_small_independent_oracle():
    x=case();kept,a=solve(x,4)
    chosen={0}
    # Exhaustively compare every currently feasible bundle on each step.
    for row in a['trace']:
        candidates=[]
        for i in range(1,6):
            if i in chosen or x['pivot'][i]<0 or x['evidence'][i]<=0:continue
            added=set(witness_bundle(i,x['backward'],x['parent'],x['pivot']))-chosen
            if len(added)>4-len(chosen):continue
            gain=independent_value(chosen|added,x)-independent_value(chosen,x)
            candidates.append(((-gain/len(added),-gain,x['tie_keys'][i]),i,added))
        expected=min(candidates)
        assert row['anchor']==expected[1]
        assert set(row['new_edges'])==expected[2]
        chosen|=expected[2]
    assert set(np.flatnonzero(kept))==chosen=={0,1,3,4}
    assert a['reasons'][1]=='causal_connector'
    assert a['reasons'][2]=='bundle_exceeds_remaining_budget'
    assert a['reasons'][5]=='no_temporal_witness'
    assert audit_selection(kept,x['poi'],x['backward'],x['parent'],x['pivot'],a,x['evidence'],x['family'],4)['ledger_replayed']


def test_relaxation_bound_against_exhaustive_feasible_subsets():
    x=case()
    for budget in range(1,7):
        kept,a=solve(x,budget)
        optimum=0
        for mask in itertools.product([False,True],repeat=3):
            union={0}
            for use,i in zip(mask,[2,3,4]):
                if use:union.update(witness_bundle(i,x['backward'],x['parent'],x['pivot']))
            if len(union)<=budget:optimum=max(optimum,independent_value(union,x))
        assert a['objective']<=optimum+1e-10<=a['objective_upper_bound']+1e-10
    kept,a=solve(x,6)
    assert kept.sum()==5  # No evidence fabrication to fill remaining capacity.
    assert a['objective_fraction_of_upper_bound']==pytest.approx(1)


def test_corrupted_ledger_and_noncausal_witness_rejected():
    x=case();kept,a=solve(x,4)
    bad=copy.deepcopy(a);bad['trace'][0]['marginal_gain']+=1
    with pytest.raises(ValueError,match='objective mismatch'):
        audit_selection(kept,x['poi'],x['backward'],x['parent'],x['pivot'],bad,x['evidence'],x['family'],4)
    assert validate_routes(x['src'],x['dst'],x['timestamp'],x['poi'],x['backward'],x['parent'],x['pivot'])
    x['timestamp'][1]=x['timestamp'][0]
    with pytest.raises(ValueError,match='temporal witness'):
        validate_routes(x['src'],x['dst'],x['timestamp'],x['poi'],x['backward'],x['parent'],x['pivot'])


def test_numerically_uncertain_score_does_not_become_anchor():
    x=case();cert=np.array([True,False,False,True,False,True])
    kept,a=solve(x,6,certified=cert)
    assert not kept[2] and not kept[4]
    assert a['reasons'][2]=='background_lift_within_numeric_error'
    assert kept[1]  # An uncertified event can still be a required connector.


def test_ppr_error_certificate_bounds_exact_stationary_solution():
    a=np.array([0,1]);b=np.array([1,2]);w=np.array([1.,2.]);seed=np.array([1.,0.,0.]);restart=.15
    p,diag,_=personalized_pagerank(a,b,w,seed,restart=restart,iterations=8)
    adjacency=np.array([[0.,1.,0.],[1.,0.,2.],[0.,2.,0.]])
    transition=(adjacency/adjacency.sum(axis=1)[:,None]).T
    exact=np.linalg.solve(np.eye(3)-(1-restart)*transition,restart*seed)
    assert np.abs(p-exact).sum()<=diag['residual_l1']/restart


def test_structurally_identical_events_keep_equal_scores_without_jitter():
    src=np.array([0,0,1]);dst=np.array([1,1,2]);rel=np.zeros(3,int);rarity=np.ones(3);poi=np.array([False,False,True])
    config=dict(rarity_floor=.2,restart=.15,iterations=200,tolerance=1e-10,escape_floor=1e-6)
    score,diag=propagate(src,dst,rel,rarity,poi,np.ones(3,bool),config)
    assert score[0]==score[1]
    assert diag['positive_lift_certified'][0]==diag['positive_lift_certified'][1]
