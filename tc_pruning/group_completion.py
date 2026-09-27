"""Label-free multiresolution group actions with exact shared-event marginal costs.

The event-set utility is concave coverage. Overlapping witness costs do not
satisfy additive-knapsack assumptions; no approximation ratio is asserted.
"""
from __future__ import annotations
from dataclasses import dataclass
from collections import defaultdict
import math
import time
import numpy as np
from .alternative_witnesses import build_witnesses


@dataclass(frozen=True)
class Bundle:
    anchors: tuple[int,...]
    events: tuple[int,...]
    witness_ids: tuple[str,...]
    group: int
    level: str


@dataclass(frozen=True)
class Snapshot:
    actions: tuple[Bundle,...]
    event_scores: np.ndarray
    group_of: np.ndarray
    group_weights: np.ndarray
    certificates: tuple
    materialized_events: tuple[int,...]

    def __post_init__(self):
        n=len(self.event_scores)
        if len(self.group_of)!=n or not np.isfinite(self.event_scores).all() or np.any(self.event_scores<0):raise ValueError('invalid event scores')
        if not np.isfinite(self.group_weights).all() or np.any(self.group_weights<0):raise ValueError('invalid group weights')
        if np.any(self.group_of<0) or np.any(self.group_of>=len(self.group_weights)):raise ValueError('invalid group membership')
        materialized=set(self.materialized_events)
        if any(e<0 or e>=n for e in materialized):raise ValueError('invalid materialized identity')
        for a in self.actions:
            if not a.anchors or not a.events or len(set(a.events))!=len(a.events) or not set(a.anchors)<=set(a.events):raise ValueError('invalid bundle')
            if not set(a.events)<=materialized or not 0<=a.group<len(self.group_weights):raise ValueError('unmaterialized bundle')


@dataclass(frozen=True)
class Result:
    selected_events: tuple[int,...]
    selected_bundles: tuple[int,...]
    budget_used: int
    objective_value: float|None
    status: str
    policy: str
    trace: tuple


def utility(pool,selected,objective='concave',eta=1.):
    selected=list(selected)
    edge=float(pool.event_scores[selected].sum()) if selected else 0.
    if objective=='edge':return edge
    if objective!='concave':raise ValueError('unknown objective')
    counts=np.bincount(pool.group_of[selected],minlength=len(pool.group_weights)) if selected else np.zeros(len(pool.group_weights))
    return float(np.dot(pool.group_weights,np.sqrt(counts))+eta*edge)


def marginal_gain(pool,selected,action,objective='concave',eta=1.):
    selected=set(selected)
    return utility(pool,selected|set(action.events),objective,eta)-utility(pool,selected,objective,eta)


def select(pool,mandatory,budget,objective='concave',eta=1.):
    n=len(pool.event_scores);mandatory=set(map(int,mandatory))
    if isinstance(budget,bool) or not isinstance(budget,(int,np.integer)) or budget<0 or eta<0 or not math.isfinite(eta):raise ValueError('invalid budget or eta')
    if objective not in ('edge','concave') or any(e<0 or e>=n for e in mandatory):raise ValueError('invalid objective or mandatory identity')
    if len(mandatory)>budget:return Result((),(),0,None,'infeasible_mandatory_budget','none',())
    kept=np.zeros(n,bool);kept[list(mandatory)]=True
    actions=pool.actions;na=len(actions);ng=len(pool.group_weights)
    # Pair arrays store remaining event counts for every action/group pair.
    rows=[];cols=[];remaining=[];inverted=defaultdict(list)
    costs=np.zeros(na,np.int32);edge_gain=np.zeros(na,float)
    for j,a in enumerate(actions):
        counts=defaultdict(int)
        for e in a.events:
            if not kept[e]:counts[int(pool.group_of[e])]+=1;costs[j]+=1;edge_gain[j]+=pool.event_scores[e]
        pair={}
        for g,count in sorted(counts.items()):
            pair[g]=len(rows);rows.append(j);cols.append(g);remaining.append(count)
        for e in a.events:
            if not kept[e]:inverted[e].append((j,pair[int(pool.group_of[e])]))
    rows=np.asarray(rows,int);cols=np.asarray(cols,int);remaining=np.asarray(remaining,np.int32)
    counts=np.bincount(pool.group_of[list(mandatory)],minlength=ng)
    used=len(mandatory);chosen=[];trace=[]
    def gains():
        if objective=='edge':return np.maximum(edge_gain,0.)
        increments=pool.group_weights[cols]*(np.sqrt(counts[cols]+remaining)-np.sqrt(counts[cols]))
        return np.bincount(rows,weights=increments,minlength=na)+eta*np.maximum(edge_gain,0.)
    # Best feasible single action is a deployment control, not a label oracle.
    initial=gains();feasible=(costs<=budget-used)&(costs>0)&(initial>0)
    best_single=int(np.argmax(np.where(feasible,initial,-np.inf))) if np.any(feasible) else None
    while used<budget:
        gain=gains();feasible=(costs<=budget-used)&(costs>0)&(gain>1e-14)
        if not np.any(feasible):break
        density=np.full(na,-np.inf);density[feasible]=gain[feasible]/costs[feasible]
        j=int(np.argmax(density));a=actions[j];extra=[e for e in a.events if not kept[e]]
        before=used
        for e in extra:
            kept[e]=True;used+=1;counts[int(pool.group_of[e])]+=1
            for k,pair in inverted[e]:
                costs[k]-=1;remaining[pair]-=1;edge_gain[k]-=pool.event_scores[e]
        chosen.append(j);trace.append(dict(bundle=j,added_events=extra,used_before=before,used_after=used,marginal_gain=float(gain[j])))
    selected=tuple(map(int,np.flatnonzero(kept)));value=utility(pool,selected,objective,eta)
    if best_single is not None:
        singleton=tuple(sorted(mandatory|set(actions[best_single].events)))
        single_value=utility(pool,singleton,objective,eta)
        if single_value>value+1e-12:
            return Result(singleton,(best_single,),len(singleton),single_value,'ok','best_single_bundle',
                (dict(bundle=best_single,added_events=sorted(set(singleton)-mandatory),used_before=len(mandatory),used_after=len(singleton),marginal_gain=single_value-utility(pool,mandatory,objective,eta)),))
    return Result(selected,tuple(chosen),used,value,'ok','density_greedy',tuple(trace))


def build_pool(data,primary,groups,routes,mandatory,cap=32768,max_examined=327680,representatives_only=False):
    tick=time.perf_counter();n=len(data['ids']);primary=np.asarray(primary,float);mandatory=set(map(int,mandatory))
    if len(set(data['ids']))!=n or len(primary)!=n or len(groups.group_of)!=n:raise ValueError('misaligned or duplicate event identity')
    if not np.isfinite(primary).all() or np.any(primary<0) or cap<1 or max_examined<1 or len(mandatory)>cap:raise ValueError('invalid candidate limits or scores')
    if any(e<0 or e>=n for e in mandatory):raise ValueError('mandatory outside ledger')
    back,parent,pivot=routes
    weights=groups.scores(primary)
    order=groups.ranked_descriptors(primary,data['tie']);order=[int(g) for g in order if weights[g]>0]
    states={};examined=0;unreachable=0;materialized=set(mandatory);actions=[];registry={};admitted_prefixes=set()
    seen=np.zeros(n,dtype=bool)
    def admit(g,target,limit):
        nonlocal examined,unreachable
        if g not in states:
            members=groups.members(g)
            ordered=members[np.lexsort((data['tie'][members],-primary[members]))]
            states[g]=dict(members=ordered,cursor=0,witnesses=[])
        s=states[g];pending=list(s['witnesses'][:target])
        union={e for w in pending for e in w.events}
        pending_cost=sum(e not in materialized for e in union)
        while len(pending)<target and s['cursor']<len(s['members']):
            i=int(s['members'][s['cursor']])
            if not seen[i]:
                if examined>=max_examined:break
                seen[i]=True;examined+=1
            if pivot[i]<0:
                s['cursor']+=1;unreachable+=1;continue
            ws=build_witnesses(i,data['src'],data['dst'],data['timestamp'],data['poi'],back,parent,pivot,None,1)
            if not ws:s['cursor']+=1;continue
            extra={e for e in ws[0].events if e not in union and e not in materialized}
            # Retain only prefixes admitted to the real event union. A blocked member
            # stays at the cursor and may become affordable through later sharing.
            if len(materialized)+pending_cost+len(extra)>limit:break
            pending_cost+=len(extra);pending.append(ws[0]);union.update(ws[0].events);s['cursor']+=1
        if not pending:return
        anchors=tuple(w.anchor for w in pending)
        if (g,anchors) in admitted_prefixes:return
        if len(materialized)+sum(e not in materialized for e in union)>limit:return
        s['witnesses']=pending
        full=s['cursor']==len(s['members'])
        level='full' if full else 'representative' if len(pending)==1 else 'continuation'
        actions.append(Bundle(anchors,tuple(sorted(union)),tuple(w.digest for w in pending),g,level))
        materialized.update(union);admitted_prefixes.add((g,anchors))
        registry.update((w.digest,w) for w in pending)
    # Exploration does not spend the entire materialization budget on representatives.
    reserved=max(len(mandatory),cap//4)
    for g in order:admit(g,1,reserved)
    if not representatives_only:
        largest=max((len(groups.members(g)) for g in order),default=1)
        targets=[];size=2
        while size<largest:targets.append(size);size*=2
        targets.append(largest)
        for target in targets:
            for g in order:admit(g,min(target,len(groups.members(g))),cap)
    # Include one-member groups refused by the exploration reserve if final capacity allows.
    for g in order:admit(g,1,cap)
    certificates=tuple(registry.values())
    pool=Snapshot(tuple(actions),primary,groups.group_of.copy(),weights,certificates,tuple(sorted(materialized)))
    admitted={i for a in actions for i in a.anchors}
    diag=dict(cap=cap,max_examined=max_examined,examined_events=examined,unreachable_examined=unreachable,
              materialized_events=len(materialized),actions=len(actions),certificates=len(certificates),
              executable_anchors=len(admitted),zero_score_details_admitted=int(sum(primary[i]==0 for i in admitted)),
              cached_certificates=len({w.digest for s in states.values() for w in s["witnesses"]}),
              representative_actions=sum(a.level=='representative' for a in actions),
              continuation_actions=sum(a.level=='continuation' for a in actions),full_actions=sum(a.level=='full' for a in actions),
              full_scope='all examined reachable members only; not attack truth',
              scan_truncated=examined>=max_examined and any(s['cursor']<len(s['members']) for s in states.values()),
              representatives_only=representatives_only,seconds=time.perf_counter()-tick,labels_used=False)
    return pool,diag
