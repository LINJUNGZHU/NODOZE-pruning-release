"""Budgeted global/type allocation admitting each anchor with its raw witnesses."""
import heapq
import math
import numpy as np


def witness_portfolio(values,relations,mandatory,budget,ties,routes,fraction=.5):
    kept=np.asarray(mandatory,bool).copy();used=int(kept.sum())
    if not used<=budget<=len(kept) or not 0<=fraction<=1:raise ValueError('infeasible cap or fraction')
    backward,parent,pivot=routes
    def bundle(i):
        out=set();j=int(i)
        while j>=0:
            if not kept[j]:out.add(j)
            j=int(parent[j])
        j=int(pivot[i])
        while j>=0:
            if not kept[j]:out.add(j)
            j=int(backward[j])
        return np.fromiter(out,np.int64)
    eligible=np.flatnonzero((pivot>=0)&(values>0))
    ranking=eligible[np.lexsort((ties[eligible],-values[eligible]))]
    prefix=max(used,math.floor(budget*fraction))
    for i in ranking:
        if used==prefix:break
        if kept[i]:continue
        extra=bundle(i)
        if used+len(extra)<=prefix:kept[extra]=True;used+=len(extra)
    counts=np.bincount(relations[kept],minlength=int(relations.max())+1)
    queues={};pos={};heap=[]
    for rel in np.unique(relations):
        indices=ranking[relations[ranking]==rel]
        if not len(indices):continue
        r=int(rel);queues[r]=indices;pos[r]=0;i=indices[0]
        heapq.heappush(heap,(int(counts[r]),-float(values[i]),int(ties[i]),r))
    def push(r):
        q=queues[r]
        while pos[r]<len(q) and kept[q[pos[r]]]:pos[r]+=1
        if pos[r]<len(q):
            i=q[pos[r]];heapq.heappush(heap,(int(counts[r]),-float(values[i]),int(ties[i]),r))
    while heap and used<budget:
        old_count,old_score,old_tie,r=heapq.heappop(heap);i=queues[r][pos[r]]
        if kept[i]:push(r);continue
        current=(int(counts[r]),-float(values[i]),int(ties[i]),r)
        if heap and current>heap[0]:heapq.heappush(heap,current);continue
        extra=bundle(i);pos[r]+=1
        if used+len(extra)<=budget:
            kept[extra]=True;used+=len(extra);np.add.at(counts,relations[extra],1)
        push(r)
    return kept
