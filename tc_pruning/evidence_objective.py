"""Fixed-pool raw-event witness selection; no label or reference inputs."""
from dataclasses import dataclass
from collections import defaultdict
import math
import numpy as np


@dataclass(frozen=True)
class Action:
    anchor:int
    group:int
    events:tuple[int,...]
    score:float
    witness_id:str


@dataclass(frozen=True)
class CandidateSnapshot:
    actions:tuple[Action,...]
    event_scores:np.ndarray
    group_weights:np.ndarray
    event_count:int
    materialized_events:tuple[int,...]=()
    certificates:tuple=()

    def __post_init__(self):
        if len(self.event_scores)!=self.event_count or not np.isfinite(self.event_scores).all() or np.any(self.event_scores<0):raise ValueError('invalid event scores')
        if not np.isfinite(self.group_weights).all() or np.any(self.group_weights<0):raise ValueError('invalid group weights')
        ids=set()
        for a in self.actions:
            if a.witness_id in ids:raise ValueError('duplicate witness ID')
            ids.add(a.witness_id)
            if a.anchor<0 or a.anchor>=self.event_count or a.anchor not in a.events or a.group<0 or a.group>=len(self.group_weights):raise ValueError('invalid action identity')
            if not a.events or len(set(a.events))!=len(a.events) or any(e<0 or e>=self.event_count for e in a.events):raise ValueError('invalid action events')
            if not math.isfinite(a.score) or a.score<0:raise ValueError('invalid anchor score')


@dataclass(frozen=True)
class Selection:
    selected_events:tuple[int,...]
    selected_anchors:tuple[int,...]
    selected_witnesses:tuple[str,...]
    budget_used:int
    objective_value:float|None
    status:str
    steps:int


def complete_group(pool,group,selected):
    selected=set(selected)
    return any(a.group==group and set(a.events)<=selected for a in pool.actions)


def objective_value(pool,selected,anchors,objective,eta=1.):
    selected=set(selected);anchors=set(anchors)
    if objective=='edge_score':return float(pool.event_scores[list(selected)].sum()) if selected else 0.
    anchor_max={}
    for a in pool.actions:anchor_max[a.anchor]=max(anchor_max.get(a.anchor,0.),a.score)
    if objective=='anchor_score':return sum(anchor_max[i] for i in anchors)
    if objective!='witness_plus_detail':raise ValueError('unknown objective')
    wg=float(pool.group_weights.sum())
    complete={a.group for a in pool.actions if set(a.events)<=selected}
    coverage=sum(float(pool.group_weights[g]) for g in complete)/wg if wg>0 else 0.
    denom=sum(anchor_max.values())
    detail=sum(anchor_max[i] for i in anchors)/denom if denom>0 else 0.
    return coverage+eta*detail


def select(pool,mandatory,budget,objective,eta=1.):
    mandatory=set(map(int,mandatory))
    if objective not in ('edge_score','anchor_score','witness_plus_detail') or eta<0:raise ValueError('invalid objective or eta')
    if any(e<0 or e>=pool.event_count for e in mandatory):raise ValueError('mandatory outside ledger')
    if len(mandatory)>budget:return Selection((),(),(),0,None,'infeasible_mandatory_budget',0)
    kept=np.zeros(pool.event_count,bool);kept[list(mandatory)]=True
    actions=pool.actions;n=len(actions)
    inv=defaultdict(list);by_anchor=defaultdict(list)
    costs=np.zeros(n,np.int32);edge_gain=np.zeros(n,float)
    for j,a in enumerate(actions):
        by_anchor[a.anchor].append(j)
        for e in a.events:
            inv[e].append(j)
            if not kept[e]:costs[j]+=1;edge_gain[j]+=pool.event_scores[e]
    active=np.ones(n,bool);chosen_anchors=[];chosen_witnesses=[];covered=np.zeros(len(pool.group_weights),bool)
    for j,a in enumerate(actions):
        if costs[j]==0:covered[a.group]=True
    group_denom=float(pool.group_weights.sum())
    anchor_score={}
    for a in actions:anchor_score[a.anchor]=max(anchor_score.get(a.anchor,0.),a.score)
    detail_denom=sum(anchor_score.values())
    anchor_gain=np.array([anchor_score[a.anchor] for a in actions])
    group_id=np.array([a.group for a in actions],np.int32)
    used=int(kept.sum());steps=0
    while used<=budget:
        remaining=budget-used
        if objective=='edge_score':gain=edge_gain
        elif objective=='anchor_score':gain=anchor_gain
        else:
            c=pool.group_weights[group_id]*(~covered[group_id])/group_denom if group_denom>0 else np.zeros(n)
            d=eta*anchor_gain/detail_denom if detail_denom>0 else np.zeros(n)
            gain=c+d
        feasible=active&(costs<=remaining)&(gain>0)
        if not np.any(feasible):break
        density=np.full(n,-np.inf)
        density[feasible]=gain[feasible]/np.maximum(costs[feasible],1)
        density[feasible&(costs==0)]=np.inf
        best=int(np.argmax(density))
        a=actions[best];extra=[e for e in a.events if not kept[e]]
        for j in by_anchor[a.anchor]:active[j]=False
        chosen_anchors.append(a.anchor);chosen_witnesses.append(a.witness_id)
        for e in extra:
            kept[e]=True;used+=1
            for j in inv[e]:
                costs[j]-=1;edge_gain[j]-=pool.event_scores[e]
                if costs[j]==0:covered[actions[j].group]=True
        steps+=1
    ids=tuple(map(int,np.flatnonzero(kept)))
    value=objective_value(pool,ids,chosen_anchors,objective,eta)
    return Selection(ids,tuple(chosen_anchors),tuple(chosen_witnesses),used,float(value),'ok',steps)
