"""Budgeted saturated evidence coverage after frequency-conditioned diffusion.

Inspired by budgeted document summarization. These heuristics have no claimed
approximation ratio under overlapping causal-witness costs.
"""
from __future__ import annotations
import heapq
import numpy as np
from .rasp_diverse import event_families


def top_budget(values,mandatory,budget,ties):
    kept=np.asarray(mandatory,bool).copy()
    if not int(kept.sum())<=budget<=len(kept):raise ValueError('infeasible raw cap')
    order=np.lexsort((ties,-np.asarray(values)))
    kept[order[~kept[order]][:budget-int(kept.sum())]]=True
    return kept


def group_members(group):
    order=np.argsort(group,kind='stable')
    bounds=np.r_[0,np.flatnonzero(np.diff(group[order]))+1,len(group)]
    return [order[lo:hi] for lo,hi in zip(bounds[:-1],bounds[1:]) if hi>lo]


def select_coverage(data,values,group,routes,budget,mandatory=None,semantic=True):
    """Greedy saturated coverage with bounded episodes and raw fork witnesses."""
    src,dst,rel=data['src'],data['dst'],data['relation']
    backward,parent,pivot=routes
    kept=data['poi'].copy()
    if mandatory is not None:kept |= mandatory
    if not int(kept.sum())<=budget<=len(kept):raise ValueError('infeasible raw cap')
    members=group_members(group)
    features=[event_families(src,dst,rel)]
    if semantic:features.append(event_families(data['semantic'][src],data['semantic'][dst],rel))
    covered=[np.zeros(int(f.max())+1) for f in features]
    def update(indices):
        for f,c in zip(features,covered):np.maximum.at(c,f[indices],values[indices])
    # POI parallel evidence is completed before saturation, only when affordable.
    used=int(kept.sum())
    for g in sorted(set(map(int,group[data['poi']]))):
        extra=members[g][~kept[members[g]]]
        if used+len(extra)<=budget:kept[extra]=True;used+=len(extra)
    update(np.flatnonzero(kept))
    def gain(i):return sum(max(float(values[i])-c[f[i]],0.) for f,c in zip(features,covered))/len(features)
    eligible=np.flatnonzero((pivot>=0)&(values>0))
    order=eligible[np.lexsort((data['tie'][eligible],-values[eligible],group[eligible]))]
    if not len(order):return kept
    reps=order[np.r_[True,np.diff(group[order])!=0]]
    heap=[(-gain(i),int(data['tie'][i]),int(i)) for i in reps if not kept[members[int(group[i])]].all()]
    heapq.heapify(heap)
    while heap and used<budget:
        previous,tie,i=heapq.heappop(heap)
        marginal=gain(i)
        if marginal<=0:continue
        if heap and (-marginal,tie,i)>heap[0]:
            heapq.heappush(heap,(-marginal,tie,i));continue
        ids=members[int(group[i])]
        path=set(map(int,ids[~kept[ids]]));j=i
        while j>=0:
            if not kept[j]:path.add(j)
            j=int(parent[j])
        j=int(pivot[i])
        while j>=0:
            if not kept[j]:path.add(j)
            j=int(backward[j])
        # Shared connectors can reduce cost later; skipping is a heuristic.
        if used+len(path)>budget:continue
        chosen=np.fromiter(path,np.int64)
        kept[chosen]=True;used+=len(chosen);update(chosen)
    return kept
