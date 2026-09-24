"""POI-time-conditioned frequency diffusion and explicit graph-kernel adapters.

All scores are investigative priorities, not calibrated attack probabilities.
No case identities, entity names, label IDs or ground-truth input is accepted.
"""
from __future__ import annotations
import heapq
import math
import numpy as np
from .frequency_diffusion import transition,walk,semantic_uniqueness


def temporal_affinity(timestamp,poi_times,scale_ns):
    if scale_ns<=0 or not len(poi_times):raise ValueError('positive scale and POI times required')
    ts=np.asarray(timestamp,np.int64);distance=np.full(len(ts),np.inf)
    for t in poi_times:distance=np.minimum(distance,np.abs(ts-int(t)).astype(float))
    return 1/(1+distance/scale_ns)


def heat_walk(a,b,prob,seed,time=3.,tolerance=1e-12):
    """Poisson series exp(t(P-I))s, with seed redistribution for dangling mass.

    Full sparse matvec implementation, not Kloster/Gleich's local relaxation.
    """
    if time<=0 or time>100 or tolerance<=0:raise ValueError('invalid heat parameters')
    seed=np.asarray(seed,float);seed=seed/seed.sum();term=seed.copy();n=len(seed)
    active=np.bincount(a,minlength=n)>0
    coefficient=math.exp(-time);mass=coefficient;result=coefficient*term
    for k in range(1,1001):
        term=np.bincount(b,weights=prob*term[a],minlength=n)+term[~active].sum()*seed
        coefficient*=time/k;result+=coefficient*term;mass+=coefficient
        if 1-mass<=tolerance:break
    return result,dict(iterations=k,residual_l1=max(0.,1-mass),converged=1-mass<=tolerance)


def plain_score(data,config,kernel='ppr'):
    if kernel not in ('ppr','heat'):raise ValueError('unknown kernel')
    src,dst=data['src'],data['dst'];n=len(data['process_nodes']);poi=data['poi']
    if not poi.any():raise ValueError('at least one POI required')
    a,b,p=transition(src,dst,data['relation'],np.ones(len(src)),n,False)
    result=np.zeros(len(src));diagnostics=[]
    for i in np.flatnonzero(poi):
        seed=np.zeros(n);seed[src[i]]+=.5;seed[dst[i]]+=.5
        if kernel=='heat':v,diag=heat_walk(a,b,p,seed,config.get('heat_time',3.),config['tolerance'])
        else:v,diag=walk(a,b,p,seed,**{k:config[k] for k in ('restart','iterations','tolerance')})
        value=np.sqrt(v[src]*v[dst]);value/=max(value.max(),1e-300)
        result=np.maximum(result,value);diagnostics.append(diag)
    result[poi]=1
    return result,dict(walks=diagnostics)


def temporal_score(data,config,scale_ns,frequency=True,contrast=True):
    src,dst,rel=data['src'],data['dst'],data['relation'];poi=data['poi'];n=len(data['process_nodes'])
    if not poi.any():raise ValueError('at least one POI required')
    rarity=np.asarray(data['rarity']) if frequency else np.ones(len(src))
    if not np.all(np.isfinite(rarity)) or np.any((rarity<0)|(rarity>1)):raise ValueError('invalid rarity')
    if frequency:rarity=np.sqrt(rarity*semantic_uniqueness(src,dst,rel,data['process_nodes'],data['semantic']))
    base=config['rarity_floor']+(1-config['rarity_floor'])*rarity
    background=data['process_nodes'].astype(float)
    if not background.any():background[:]=1
    kwargs={k:config[k] for k in ('restart','iterations','tolerance')}
    result=np.zeros(len(src));diagnostics=[]
    for i in np.flatnonzero(poi):
        affinity=temporal_affinity(data['timestamp'],[data['timestamp'][i]],scale_ns)
        weight=base*affinity;a,b,p=transition(src,dst,rel,weight,n,True)
        seed=np.zeros(n);seed[src[i]]+=.5;seed[dst[i]]+=.5
        v,diag=walk(a,b,p,seed,**kwargs);diagnostics.append(diag)
        if contrast:
            q,diag=walk(a,b,p,background,**kwargs);diagnostics.append(diag)
            lift=np.log1p(np.maximum(v/np.maximum(q,1e-300)-1,0))
        else:lift=v
        value=(.5*np.sqrt(lift[src]*lift[dst])+.25*(lift[src]+lift[dst]))*weight
        if value.max()>0:value/=value.max()
        escape=np.sqrt(v[src]*v[dst])*weight
        if escape.max()>0:escape/=escape.max()
        floor=config.get('escape_floor',1e-6)
        result=np.maximum(result,(value+floor*escape)/(1+floor))
    result[poi]=1
    return result,dict(walks=diagnostics)


def stratified_budget(values,relations,mandatory,budget,ties):
    """Round-robin relation strata; mandatory events count against their strata."""
    kept=np.asarray(mandatory,bool).copy()
    if not int(kept.sum())<=budget<=len(kept):raise ValueError('infeasible raw cap')
    queues={};positions={};heap=[]
    for rel in np.unique(relations):
        indices=np.flatnonzero((relations==rel)&~kept)
        indices=indices[np.lexsort((ties[indices],-values[indices]))]
        if not len(indices):continue
        r=int(rel);queues[r]=indices;positions[r]=0;i=indices[0]
        heapq.heappush(heap,(int(kept[relations==rel].sum()),-float(values[i]),int(ties[i]),r))
    used=int(kept.sum())
    while heap and used<budget:
        count,_,_,r=heapq.heappop(heap);i=queues[r][positions[r]];kept[i]=True;used+=1;positions[r]+=1
        if positions[r]<len(queues[r]):
            i=queues[r][positions[r]];heapq.heappush(heap,(count+1,-float(values[i]),int(ties[i]),r))
    return kept
