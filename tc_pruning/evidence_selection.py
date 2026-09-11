"""Evidence-gated, auditable causal-bundle selection.

Relative background lift is an investigative eligibility condition, not a
calibrated maliciousness test. The greedy method has no claimed approximation
ratio. An explicit relaxation supplies a valid objective upper bound instead.
"""
from __future__ import annotations
import math
import numpy as np


def witness_bundle(i, backward, parent, pivot):
    if pivot[i] < 0:
        return ()
    path, seen = set(), set()
    j = int(i)
    while j >= 0:
        if j in seen: raise ValueError('cycle in forward witness')
        seen.add(j); path.add(j); j = int(parent[j])
    if int(pivot[i]) not in path: raise ValueError('pivot missing from forward witness')
    seen.clear(); j = int(pivot[i])
    while j >= 0:
        if j in seen: raise ValueError('cycle in backward witness')
        seen.add(j); path.add(j); j = int(backward[j])
    return tuple(sorted(path))


def validate_routes(src, dst, timestamp, poi, backward, parent, pivot):
    """Validate raw directed links and strict time order independently of scoring."""
    for i in range(len(src)):
        j = int(backward[i])
        if j >= 0:
            targets = (src[j], dst[j]) if poi[j] else (src[j],)
            if not timestamp[i] < timestamp[j] or dst[i] not in targets:
                raise ValueError('invalid backward temporal witness')
        j = int(parent[i])
        if j >= 0:
            origins = (src[j], dst[j]) if pivot[j] == j else (dst[j],)
            if not timestamp[j] < timestamp[i] or src[i] not in origins:
                raise ValueError('invalid forward temporal witness')
        if pivot[i] >= 0:
            route = witness_bundle(i, backward, parent, pivot)
            if not any(poi[k] for k in route): raise ValueError('witness has no POI')
    return True


def objective(indices, evidence, family, weights, quality=.05):
    indices = list(indices)
    if not indices: return 0.
    mass = np.bincount(family[indices], weights=evidence[indices], minlength=len(weights))
    active = weights > 0
    return float(quality*mass.sum() + (1-quality)*np.sum(weights[active]*np.log1p(mass[active]/weights[active])))


def select_evidence(evidence, poi, backward, parent, pivot, family, budget, tie_keys, quality=.05, certified=None):
    evidence = np.asarray(evidence, dtype=float)
    poi, family = np.asarray(poi, dtype=bool), np.asarray(family, dtype=int)
    n = len(evidence)
    if not all(len(x)==n for x in (poi,backward,parent,pivot,family,tie_keys)):
        raise ValueError('selection array lengths differ')
    if not np.all(np.isfinite(evidence)) or np.any(evidence<0) or np.any(family<0):
        raise ValueError('invalid evidence or family')
    if not 0<=quality<=1 or not int(poi.sum())<=budget<=n or not poi.any():
        raise ValueError('invalid quality, budget or POI')
    certified = evidence > 0 if certified is None else np.asarray(certified,dtype=bool)
    if len(certified)!=n: raise ValueError('certified mask length differs')
    eligible = (evidence > 0) & certified & (np.asarray(pivot) >= 0)
    eligible |= poi
    # Zero objective contribution from ineligible events; they may be connectors.
    utility = np.where(eligible,evidence,0.)
    groups = int(family.max())+1 if n else 0
    weights = np.zeros(groups)
    np.maximum.at(weights,family,utility)
    bundles = {int(i):witness_bundle(int(i),backward,parent,pivot) for i in np.flatnonzero(eligible & ~poi)}
    anchor_ids=np.array(list(bundles),dtype=int)
    membership_anchor=[];membership_event=[]
    for a,i in enumerate(anchor_ids):
        for j in bundles[int(i)]:membership_anchor.append(a);membership_event.append(j)
    membership_anchor=np.array(membership_anchor,dtype=int)
    membership_event=np.array(membership_event,dtype=int)
    # Each bundle/group pair aggregates all newly added evidence in that group.
    pair_codes=membership_anchor*max(1,groups)+family[membership_event]
    pairs,inverse=np.unique(pair_codes,return_inverse=True)
    pair_anchor=pairs//max(1,groups);pair_family=pairs%max(1,groups)
    tie_rank=np.empty(len(anchor_ids),dtype=int)
    for rank,a in enumerate(sorted(range(len(anchor_ids)),key=lambda a:tie_keys[anchor_ids[a]])):
        tie_rank[a]=rank
    selected=poi.copy();used=int(poi.sum())
    owner = np.full(n,-1,dtype=int); owner[poi]=np.flatnonzero(poi)
    step_of = np.full(n,-1,dtype=int); step_of[poi]=0
    trace=[]
    while used<budget and len(anchor_ids):
        fresh=~selected[membership_event]
        costs=np.bincount(membership_anchor,weights=fresh,minlength=len(anchor_ids)).astype(int)
        valid=(~selected[anchor_ids]) & (costs>0) & (costs<=budget-used)
        if not valid.any():break
        mass=np.bincount(family[selected],weights=utility[selected],minlength=groups)
        delta=np.bincount(inverse,weights=utility[membership_event]*fresh,minlength=len(pairs))
        pair_gain=np.zeros(len(pairs));active=delta>0
        g=pair_family[active]
        pair_gain[active]=quality*delta[active]+(1-quality)*weights[g]*np.log1p(delta[active]/(weights[g]+mass[g]))
        gains=np.bincount(pair_anchor,weights=pair_gain,minlength=len(anchor_ids))
        ratios=np.divide(gains,costs,out=np.full(len(anchor_ids),-np.inf),where=valid)
        best_ratio=float(np.max(ratios))
        if not best_ratio>0:break
        tied=np.flatnonzero(ratios==best_ratio)
        tied=tied[gains[tied]==np.max(gains[tied])]
        a=int(tied[np.argmin(tie_rank[tied])]);i=int(anchor_ids[a]);gain=float(gains[a])
        added=[j for j in bundles[i] if not selected[j]]
        trace.append(dict(step=len(trace)+1,anchor=i,new_edges=added,new_cost=len(added),
                          used_before=used,used_after=used+len(added),
                          marginal_gain=gain,gain_per_edge=float(gain/len(added))))
        owner[added]=i;step_of[added]=len(trace);selected[added]=True;used+=len(added)
    kept=set(np.flatnonzero(selected).tolist())
    selected=np.array([i in kept for i in range(n)])
    reasons=[];remaining=budget-len(kept)
    for i in range(n):
        if poi[i]:reason='manual_poi'
        elif selected[i]:reason='evidence' if eligible[i] else 'causal_connector'
        elif pivot[i]<0:reason='no_temporal_witness'
        elif evidence[i]<=0:reason='no_positive_background_lift'
        elif not certified[i]:reason='background_lift_within_numeric_error'
        else:
            needed=sum(j not in kept for j in bundles[i])
            if needed<=remaining: raise AssertionError('greedy stopped while a positive feasible bundle remained')
            reason='bundle_exceeds_remaining_budget'
        reasons.append(reason)
    attained=objective(kept,utility,family,weights,quality)
    upper=objective(np.flatnonzero(eligible),utility,family,weights,quality)
    return selected,dict(eligible=eligible,owner=owner,step_of=step_of,reasons=reasons,trace=trace,
                         objective=attained,objective_upper_bound=upper,
                         objective_fraction_of_upper_bound=attained/upper if upper>0 else 1.,
                         eligible_count=int(eligible.sum()),unused_budget=remaining,
                         stop_reason='budget_exhausted' if not remaining else 'all_eligible_evidence_retained' if np.all(selected[eligible]) else 'no_complete_bundle_fits')


def audit_selection(selected, poi, backward, parent, pivot, audit, evidence, family, budget, quality=.05):
    """Replay ledger additions, costs, objective gains and witness closure."""
    kept=set(np.flatnonzero(poi).tolist())
    eligible=np.asarray(audit['eligible']);utility=np.where(eligible,evidence,0.)
    weights=np.zeros(int(np.max(family))+1)
    np.maximum.at(weights,family,utility)
    for row in audit['trace']:
        expected=set(witness_bundle(row['anchor'],backward,parent,pivot))-kept
        if expected!=set(row['new_edges']) or len(expected)!=row['new_cost']:
            raise ValueError('ledger bundle mismatch')
        if row['used_before']!=len(kept) or row['used_after']!=len(kept|expected) or row['used_after']>budget:
            raise ValueError('ledger budget mismatch')
        gain=objective(kept|expected,utility,family,weights,quality)-objective(kept,utility,family,weights,quality)
        if not math.isclose(gain,row['marginal_gain'],rel_tol=1e-8,abs_tol=1e-10):
            raise ValueError('ledger objective mismatch')
        kept|=expected
    if kept!=set(np.flatnonzero(selected)) or not np.all(selected[poi]):
        raise ValueError('ledger final selection mismatch')
    for i in np.flatnonzero(selected):
        owner=int(audit['owner'][i])
        if owner<0 or i not in witness_bundle(owner,backward,parent,pivot) or not set(witness_bundle(owner,backward,parent,pivot))<=kept:
            raise ValueError('retained event missing complete owner witness')
    return dict(budget_valid=True,poi_preserved=True,complete_witnesses=True,ledger_replayed=True)
