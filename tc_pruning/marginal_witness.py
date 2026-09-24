"""Marginal utility over unions of raw temporal witnesses; no label inputs.

This is a task adaptation, not the approximation algorithm of a coverage paper.
The MILP solves the restricted pool's *linear* utility, subject to solver limits.
"""
from dataclasses import dataclass
import math
import numpy as np
from scipy.optimize import Bounds, LinearConstraint, milp
from scipy.sparse import coo_matrix, csr_matrix


@dataclass
class WitnessPool:
    anchors: np.ndarray
    bundles: list
    values: np.ndarray
    relations: np.ndarray
    mandatory: np.ndarray
    ties: np.ndarray
    events: np.ndarray
    incidence: csr_matrix  # local raw event x anchor
    diagnostics: dict


def make_pool(values, relations, mandatory, budget, ties, routes, minimum=4096):
    values=np.asarray(values,float);relations=np.asarray(relations,int)
    mandatory=np.asarray(mandatory,bool);ties=np.asarray(ties)
    if not np.isfinite(values).all() or np.any(values<0):raise ValueError('invalid values')
    if mandatory.sum()>budget or budget>len(values):raise ValueError('infeasible budget')
    back,parent,pivot=routes
    eligible=np.flatnonzero((pivot>=0)&(values>0))
    ranked=eligible[np.lexsort((ties[eligible],-values[eligible]))]
    size=max(minimum,2*budget);types=np.unique(relations[eligible])
    quota=math.ceil(size/max(1,len(types)))
    chosen=set(map(int,ranked[:size]))
    for rel in types:chosen.update(map(int,ranked[relations[ranked]==rel][:quota]))
    # Anchor order is fixed by ID, independent of heap/update ordering.
    anchors=np.array(sorted(chosen,key=lambda i:int(ties[i])),dtype=np.int64)
    bundles=[]
    for i in anchors:
        members=set();j=int(i);seen=set()
        while j>=0:
            if j in seen:raise ValueError('cyclic parent route')
            seen.add(j);members.add(j);j=int(parent[j])
        j=int(pivot[i]);seen=set()
        while j>=0:
            if j in seen:raise ValueError('cyclic backward route')
            seen.add(j);members.add(j);j=int(back[j])
        bundles.append(np.array(sorted(members),dtype=np.int64))
    all_members=[np.flatnonzero(mandatory)]+bundles
    events=np.unique(np.concatenate(all_members))
    rows=np.concatenate([np.searchsorted(events,b) for b in bundles]) if bundles else np.array([],int)
    cols=np.repeat(np.arange(len(bundles)),[len(b) for b in bundles])
    incidence=coo_matrix((np.ones(len(rows),dtype=np.int8),(rows,cols)),shape=(len(events),len(bundles))).tocsr()
    scale=float(values[eligible].max()) if len(eligible) else 1.
    return WitnessPool(anchors,bundles,values/scale,relations,mandatory.copy(),ties[anchors],events,incidence,
        dict(eligible_anchors=len(eligible),pool_anchors=len(anchors),pool_raw_events=len(events),
             global_pool_limit=size,per_relation_pool_limit=quota,normalization_scale=scale))


def utility(pool, kept, diversity):
    mass=np.bincount(pool.relations[kept],weights=pool.values[kept],minlength=int(pool.relations.max())+1)
    return float(mass.sum()+diversity*np.sqrt(mass).sum())


def greedy_select(pool,budget,diversity=1.):
    kept=pool.mandatory.copy();used=int(kept.sum())
    if not used<=budget<=len(kept) or diversity<0:raise ValueError('infeasible budget or diversity')
    ntypes=int(pool.relations.max())+1
    event_values=pool.values[pool.events];event_types=pool.relations[pool.events]
    unkept=~kept[pool.events]
    costs=np.asarray(pool.incidence.T@unkept.astype(np.int64)).ravel()
    weights=np.zeros((len(pool.events),ntypes))
    weights[np.arange(len(pool.events)),event_types]=event_values*unkept
    remaining=np.asarray(pool.incidence.T@weights)
    current=np.bincount(pool.relations[kept],weights=pool.values[kept],minlength=ntypes)
    steps=0
    while used<budget:
        feasible=(costs>0)&(costs<=budget-used)
        indices=np.flatnonzero(feasible)
        if not len(indices):break
        mass=remaining[indices]
        gains=mass.sum(axis=1)
        if diversity:gains+=diversity*(np.sqrt(current+mass)-np.sqrt(current)).sum(axis=1)
        densities=gains/costs[indices]
        pick=int(indices[np.argmax(densities)]) # indices in deterministic ID order
        if densities.max()<=0:break
        bundle=pool.bundles[pick];extra=bundle[~kept[bundle]]
        kept[extra]=True;used+=len(extra);steps+=1
        for e in extra:
            local=int(np.searchsorted(pool.events,e))
            related=pool.incidence.indices[pool.incidence.indptr[local]:pool.incidence.indptr[local+1]]
            costs[related]-=1
            remaining[related,pool.relations[e]]-=pool.values[e]
            current[pool.relations[e]]+=pool.values[e]
        # Floating cancellation may leave tiny negatives in exhausted bundles.
        np.maximum(remaining,0,out=remaining)
    return kept,dict(status='ok',raw_events=used,steps=steps,objective=utility(pool,kept,diversity),diversity=diversity)


def milp_select(pool,budget,time_limit=20.,relative_gap=.01):
    if not int(pool.mandatory.sum())<=budget<=len(pool.mandatory):raise ValueError('infeasible budget')
    n=len(pool.events);m=len(pool.anchors);inc=pool.incidence.tocoo()
    local_mandatory=pool.mandatory[pool.events];non=np.flatnonzero(~local_mandatory)
    # y_j - x_e <= 0 for every incidence; x_e - sum_j y_j <= 0
    # for each nonmandatory event; and sum_e x_e <= budget.
    count=len(inc.data);base=count+len(non)
    reverse=np.full(n,-1,int);reverse[non]=np.arange(len(non))+count
    mask=~local_mandatory[inc.row]
    rows=np.concatenate([np.arange(count),np.arange(count),reverse[inc.row[mask]],count+np.arange(len(non)),np.full(n,base)])
    cols=np.concatenate([inc.row,n+inc.col,n+inc.col[mask],non,np.arange(n)])
    vals=np.concatenate([-np.ones(count),np.ones(count),-np.ones(mask.sum()),np.ones(len(non)),np.ones(n)])
    matrix=coo_matrix((vals,(rows,cols)),shape=(base+1,n+m)).tocsc()
    lower=np.zeros(n+m);lower[:n]=local_mandatory
    objective=np.concatenate([-pool.values[pool.events],np.zeros(m)])
    upper=np.zeros(base+1);upper[-1]=budget
    result=milp(c=objective,integrality=np.ones(n+m),bounds=Bounds(lower,np.ones(n+m)),
                constraints=LinearConstraint(matrix,np.full(base+1,-np.inf),upper),
                options=dict(time_limit=time_limit,mip_rel_gap=relative_gap,presolve=True))
    def finite(name):
        value=getattr(result,name,None)
        return float(value) if value is not None and np.isfinite(value) else None
    bound=finite('mip_dual_bound')
    meta=dict(status='no_incumbent',solver_status=int(result.status),solver_message=result.message,
              mip_gap=finite('mip_gap'),objective_upper_bound=-bound if bound is not None else None,
              mip_node_count=finite('mip_node_count'),variables=n+m,constraints=base+1,
              time_limit=time_limit,relative_gap_tolerance=relative_gap)
    if result.x is None:return None,meta
    x=np.asarray(result.x)
    if not np.isfinite(x).all() or np.max(np.abs(x-np.rint(x)))>1e-5:raise ValueError('noninteger incumbent')
    binary=x>.5
    if np.any(x<lower-1e-5) or np.any(x>1+1e-5):raise ValueError('incumbent bounds')
    kept=np.zeros(len(pool.mandatory),bool);kept[pool.events]=binary[:n]
    union=pool.mandatory.copy()
    for j in np.flatnonzero(binary[n:]):union[pool.bundles[j]]=True
    if not np.array_equal(union,kept) or kept.sum()>budget:raise ValueError('incumbent closure/budget')
    meta.update(status='ok',raw_events=int(kept.sum()),objective=utility(pool,kept,0))
    return kept,meta
