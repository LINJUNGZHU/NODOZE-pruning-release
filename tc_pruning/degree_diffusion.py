"""Degree-normalized PPR/heat priorities; full-matvec task adapters.

Inspired by degree normalization before community-detection sweeps. We rank
raw events by geometric endpoint relevance, not by a conductance sweep.
"""
import numpy as np
from .frequency_diffusion import transition,walk
from .temporal_diffusion import heat_walk


def degree_normalized_score(data,config,kernel='ppr'):
    if kernel not in ('ppr','heat'):raise ValueError('unknown kernel')
    src,dst=data['src'],data['dst'];n=len(data['process_nodes']);poi=data['poi']
    if not poi.any():raise ValueError('at least one POI required')
    a,b,p=transition(src,dst,data['relation'],np.ones(len(src)),n,False)
    degree=np.bincount(a,minlength=n);out=np.zeros(len(src));diagnostics=[]
    for i in np.flatnonzero(poi):
        seed=np.zeros(n);seed[src[i]]+=.5;seed[dst[i]]+=.5
        if kernel=='heat':v,diag=heat_walk(a,b,p,seed,config.get('heat_time',3.),config['tolerance'])
        else:v,diag=walk(a,b,p,seed,**{k:config[k] for k in ('restart','iterations','tolerance')})
        v=np.divide(v,degree,out=np.zeros(n),where=degree>0)
        value=np.sqrt(v[src]*v[dst]);value/=max(value.max(),1e-300)
        out=np.maximum(out,value);diagnostics.append(diag)
    out[poi]=1
    return out,dict(walks=diagnostics)
