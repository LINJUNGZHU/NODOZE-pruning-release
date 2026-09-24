"""Label-free deterministic candidate ranking views."""
import numpy as np


def rank_views(primary,rarity,temporal,ties,policy='primary',rrf_c=60):
    scores=[np.asarray(x,float) for x in (primary,rarity,temporal)]
    ties=np.asarray(ties)
    n=len(ties)
    if any(len(x)!=n or not np.isfinite(x).all() or np.any(x<0) for x in scores):
        raise ValueError('view scores must be finite, nonnegative and aligned')
    if len(np.unique(ties))!=n:raise ValueError('ties must be unique')
    if policy not in ('primary','round_robin','rrf') or rrf_c<=0:raise ValueError('invalid policy or RRF constant')
    orders=[np.lexsort((ties,-x)) for x in scores]
    if policy=='primary':return orders[0]
    if policy=='rrf':
        combined=np.zeros(n,float)
        for order in orders:
            rank=np.empty(n,np.int64);rank[order]=np.arange(1,n+1)
            combined+=1/(rrf_c+rank)
        return np.lexsort((ties,-combined))
    seen=np.zeros(n,bool);out=np.empty(n,np.int64);write=0
    for j in range(n):
        for order in orders:
            i=int(order[j])
            if not seen[i]:
                seen[i]=True;out[write]=i;write+=1
    return out
