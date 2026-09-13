"""Label-free, relation-balanced temporal propagation with explicit fork witnesses.

Retrospective investigation: channel weights use the full fixed candidate graph.
Repeated channel observations do not accumulate mass. Scores are relevance, not
attack probabilities. Source inference here is candidate routing, not a classifier.
"""
from __future__ import annotations
import numpy as np


def channel_weights(src, dst, relation, rarity, balanced=True, rarity_floor=.2):
    src,dst,relation,rarity=map(np.asarray,(src,dst,relation,rarity))
    if not len(src) or any(len(x)!=len(src) for x in (dst,relation,rarity)):
        raise ValueError('nonempty equally sized arrays required')
    if np.any(src<0) or np.any(dst<0) or not 0<rarity_floor<=1:
        raise ValueError('invalid endpoints or rarity floor')
    if not np.all(np.isfinite(rarity)) or np.any((rarity<0)|(rarity>1)):
        raise ValueError('rarity must be finite in [0,1]')
    if not balanced:
        return np.ones(len(src)),np.ones(len(src))
    channels,inverse=np.unique(np.column_stack((src,dst,relation)),axis=0,return_inverse=True)
    mass=np.zeros(len(channels))
    np.maximum.at(mass,inverse,rarity_floor+(1-rarity_floor)*rarity)
    def normalize(endpoint):
        groups,index=np.unique(channels[:,[endpoint,2]],axis=0,return_inverse=True)
        total=np.bincount(index,weights=mass)
        relation_count=np.bincount(groups[:,0])
        return (mass/total[index]/relation_count[channels[:,endpoint]])[inverse]
    return normalize(0),normalize(1)


def temporal_propagation(src,dst,timestamp,poi,forward_weight,reverse_weight,tie,survival=.85):
    src,dst,timestamp,poi,forward_weight,reverse_weight,tie=map(np.asarray,
        (src,dst,timestamp,poi,forward_weight,reverse_weight,tie))
    poi=poi.astype(bool);n=len(src)
    if not n or not poi.any() or any(len(x)!=n for x in (dst,timestamp,poi,forward_weight,reverse_weight,tie)):
        raise ValueError('nonempty matching arrays and at least one POI required')
    if not 0<survival<1 or np.any(src<0) or np.any(dst<0):
        raise ValueError('invalid survival or node indices')
    for weights in (forward_weight,reverse_weight):
        if not np.all(np.isfinite(weights)) or np.any((weights<=0)|(weights>1)):
            raise ValueError('weights must be finite in (0,1]')
    node_count=int(max(src.max(),dst.max()))+1
    order=np.lexsort((tie,timestamp))
    starts=np.r_[0,np.flatnonzero(np.diff(timestamp[order]))+1,n]
    back=np.full(n,-1,dtype=np.int64);back_cost=np.full(n,np.inf)
    state_cost=np.full(node_count,np.inf);state_event=np.full(node_count,-1,dtype=np.int64)
    cost_backward=-np.log(survival*reverse_weight)
    cost_forward=-np.log(survival*forward_weight)
    def update(node,event,value):
        previous=state_event[node]
        if value<state_cost[node] or (value==state_cost[node] and (previous<0 or tie[event]<tie[previous])):
            state_cost[node]=value;state_event[node]=event
    # Read an entire time group before publishing updates: equal-time edges
    # can never be used as predecessor/successor witnesses.
    for group in range(len(starts)-2,-1,-1):
        batch=order[starts[group]:starts[group+1]]
        for i in batch:
            if poi[i]:back_cost[i]=0.
            elif state_event[dst[i]]>=0:
                back_cost[i]=state_cost[dst[i]]+cost_backward[i]
                back[i]=state_event[dst[i]]
        for i in batch:
            if np.isfinite(back_cost[i]):
                update(src[i],i,back_cost[i])
                if poi[i]:update(dst[i],i,0.)
    parent=np.full(n,-1,dtype=np.int64);pivot=np.full(n,-1,dtype=np.int64)
    cost=back_cost.copy();state_cost.fill(np.inf);state_event.fill(-1)
    for lo,hi in zip(starts[:-1],starts[1:]):
        batch=order[lo:hi]
        for i in batch:
            if np.isfinite(back_cost[i]):pivot[i]=i
            previous=state_event[src[i]]
            candidate=state_cost[src[i]]+cost_forward[i]
            if previous>=0 and candidate<cost[i]:
                cost[i]=candidate;parent[i]=previous;pivot[i]=pivot[previous]
        for i in batch:
            if pivot[i]>=0:
                update(dst[i],i,cost[i])
                if pivot[i]==i:update(src[i],i,cost[i])
    score=np.divide(1.,1.+cost,out=np.zeros(n),where=np.isfinite(cost))
    score[poi]=1.
    return score,back,parent,pivot


def select_reserved(base_score,temporal_score,poi,base_routes,temporal_routes,family,budget,tie,fraction):
    """Independent complete witness sets with disjoint budget allocations.

    Their union may leave capacity unused due to shared edges; no unverified
    filler or label-guided repair is added. This is an exploratory trade-off.
    """
    from tc_pruning.rasp_diverse import select_diverse
    seeds=int(np.asarray(poi,dtype=bool).sum())
    if not 0<fraction<1 or budget<2*seeds:raise ValueError('invalid reserve fraction or cap')
    reserve=max(seeds,int(budget*fraction));rest=budget-reserve
    if rest<seeds:raise ValueError('remaining allocation cannot hold POIs')
    temporal=select_diverse(temporal_score,poi,*temporal_routes,family,reserve,tie,0.)
    base=select_diverse(base_score,poi,*base_routes,family,rest,tie,0.)
    kept=base[0]|temporal[0]
    assert int(kept.sum())<=budget
    return kept,((base[0],base[1]),(temporal[0],temporal[1]))
