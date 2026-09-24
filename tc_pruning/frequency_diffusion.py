"""Experimental frequency-conditioned diffusion and reversible episode pruning.

No attack labels or prior pruning decisions are accepted by selection. Diffusion
is an investigative, undirected walk; raw temporal witnesses are separate.
"""
from __future__ import annotations
import gzip
import hashlib
import json
from pathlib import Path
import numpy as np


def load_ledger(path):
    fields={k:[] for k in ('src','dst','relation','timestamp','rarity','poi','old_score','tie')}
    nodes={}; semantics={}; relations={}; process=[]; semantic=[]; ids=[]
    with gzip.open(path,'rt') as stream:
        for line in stream:
            row=json.loads(line)
            ends=[]
            for side in ('src','dst'):
                key=(row['host'],row[side])
                if key not in nodes:
                    nodes[key]=len(nodes)
                    process.append(row[side+'_type']=='process')
                    sem=(row['host'],row[side+'_type'],row[side+'_semantic'])
                    semantic.append(semantics.setdefault(sem,len(semantics)))
                ends.append(nodes[key])
            a,b=ends
            if row['relation']=='EVENT_EXECUTE' and row['src_type']=='process' and row['dst_type']=='file':
                a,b=b,a
            eid=row['event_id']; ids.append(eid)
            values=(a,b,relations.setdefault(row['relation'],len(relations)),row['timestamp_ns'],
                    row['components']['rarity'],bool(row.get('is_declared_poi')),row['score'],
                    int.from_bytes(hashlib.sha256(eid.encode()).digest()[:8],'big'))
            for key,value in zip(fields,values):fields[key].append(value)
    data={k:np.asarray(v,dtype=np.uint64 if k=='tie' else None) for k,v in fields.items()}
    data.update(ids=ids,process_nodes=np.asarray(process,bool),semantic=np.asarray(semantic))
    return data


def episodes(src,dst,relation,timestamp,window_ns):
    """Partition into exact directed channel episodes with bounded total span."""
    if window_ns < 0:raise ValueError('negative episode window')
    n=len(src); groups=np.empty(n,np.int64)
    order=np.lexsort((timestamp,relation,dst,src))
    last=None; start=0; group=-1
    for i in order:
        channel=(int(src[i]),int(dst[i]),int(relation[i]))
        t=int(timestamp[i])
        if channel!=last or t-start>window_ns:
            group+=1; last=channel; start=t
        groups[i]=group
    return groups


def semantic_uniqueness(src,dst,relation,process_nodes,semantic):
    """Inverse log distinct process count per semantic object/relation.

    Counts come from the frozen candidate graph (transductive), not benign
    training data. Both endpoints can be processes; use the least unique side.
    """
    result=np.ones(len(src)); incidence=[]; views=[]
    for proc,obj in ((src,dst),(dst,src)):
        rows=np.flatnonzero(process_nodes[proc])
        if len(rows):
            incidence.append(np.column_stack((semantic[obj[rows]],relation[rows],proc[rows])))
            views.append((rows,obj))
    if not incidence:return result
    unique=np.unique(np.concatenate(incidence),axis=0)
    categories,counts=np.unique(unique[:,:2],axis=0,return_counts=True)
    lookup={(int(a),int(b)):1/np.log2(1+int(c)) for (a,b),c in zip(categories,counts)}
    for rows,obj in views:
        weights=np.fromiter((lookup[(int(semantic[obj[i]]),int(relation[i]))] for i in rows),float,count=len(rows))
        result[rows]=np.minimum(result[rows],weights)
    return result


def transition(src,dst,relation,weight,node_count,balanced):
    """Duplicate-invariant undirected channels, directed transition weights."""
    a,b=np.minimum(src,dst),np.maximum(src,dst)
    order=np.lexsort((relation,b,a))
    if not len(order):return a,b,np.asarray(weight,float)
    starts=np.r_[0,np.flatnonzero((np.diff(a[order])!=0)|(np.diff(b[order])!=0)|(np.diff(relation[order])!=0))+1]
    ix=order[starts]; w=np.maximum.reduceat(np.asarray(weight)[order],starts)
    u=np.r_[a[ix],b[ix]]; v=np.r_[b[ix],a[ix]]; rel=np.r_[relation[ix],relation[ix]]; w=np.r_[w,w]
    if balanced:
        _,g=np.unique(np.column_stack((u,rel)),axis=0,return_inverse=True)
        sums=np.bincount(g,weights=w)
        w=w/sums[g]
    degree=np.bincount(u,weights=w,minlength=node_count)
    return u,v,w/degree[u]


def walk(a,b,prob,seed,restart,iterations,tolerance):
    p=np.asarray(seed,float).copy(); p/=p.sum(); seed=p.copy(); n=len(p)
    active=np.bincount(a,minlength=n)>0
    for k in range(iterations):
        nxt=restart*seed+(1-restart)*(np.bincount(b,weights=prob*p[a],minlength=n)+p[~active].sum()*seed)
        residual=float(np.abs(nxt-p).sum()); p=nxt
        if residual<=tolerance:break
    return p,dict(iterations=k+1,residual_l1=residual,converged=residual<=tolerance)


def score(data,config,*,balanced=True,semantic_frequency=True,frequency=True,endpoint_mix=.5):
    src,dst,rel=data['src'],data['dst'],data['relation']
    poi=data['poi']; n=len(data['process_nodes'])
    if not poi.any():raise ValueError('at least one POI required')
    rarity=data['rarity'].copy() if frequency else np.ones(len(src))
    if not np.all(np.isfinite(rarity)) or np.any((rarity<0)|(rarity>1)):raise ValueError('invalid rarity')
    if semantic_frequency and frequency:
        rarity=np.sqrt(rarity*semantic_uniqueness(src,dst,rel,data['process_nodes'],data['semantic']))
    conductance=config['rarity_floor']+(1-config['rarity_floor'])*rarity
    a,b,p=transition(src,dst,rel,conductance,n,balanced)
    kwargs={k:config[k] for k in ('restart','iterations','tolerance')}
    bg=data['process_nodes'].astype(float)
    if not bg.any():bg[:]=1
    q,diag=walk(a,b,p,bg,**kwargs)
    result=np.zeros(len(src)); diagnostics=[diag]
    for i in np.flatnonzero(poi):
        seed=np.zeros(n); seed[src[i]]+=.5;seed[dst[i]]+=.5
        v,diag=walk(a,b,p,seed,**kwargs);diagnostics.append(diag)
        lift=np.log1p(np.maximum(v/np.maximum(q,1e-300)-1,0))
        evidence=(1-endpoint_mix)*np.sqrt(lift[src]*lift[dst])+endpoint_mix*(lift[src]+lift[dst])/2
        value=evidence*conductance
        if value.max()>0:value/=value.max()
        # Match the established weak escape channel for background-common edges.
        escape=np.sqrt(v[src]*v[dst])*conductance
        if escape.max()>0:escape/=escape.max()
        result=np.maximum(result,(value+config.get('escape_floor',1e-6)*escape)/(1+config.get('escape_floor',1e-6)))
    result[poi]=1
    return result,dict(walks=diagnostics,channels=len(a)//2)


def select_episodes(score,poi,backward,parent,pivot,group,budget,ties,mandatory=None):
    """Admit complete episodes and one temporal witness per episode.

    A POI is mandatory individually. Other members of its episode still cost
    budget. Full expansion is all-or-nothing; all raw connector costs count.
    """
    n=len(score)
    if not int(poi.sum())<=budget<=n:raise ValueError('invalid raw-event cap')
    kept=np.asarray(poi,bool).copy()
    if mandatory is not None:kept |= np.asarray(mandatory,bool)
    used=int(kept.sum())
    if used>budget:raise ValueError('mandatory events exceed raw cap')
    order=np.argsort(group,kind='stable')
    boundaries=np.r_[0,np.flatnonzero(np.diff(group[order]))+1,n]
    members={int(group[order[lo]]):order[lo:hi] for lo,hi in zip(boundaries[:-1],boundaries[1:]) if hi>lo}
    eligible=np.flatnonzero((pivot>=0)&(score>0))
    max_score=np.zeros(int(group.max())+1)
    np.maximum.at(max_score,group,score)
    ranking=eligible[np.lexsort((ties[eligible],-score[eligible],-max_score[group[eligible]]))]
    visited=set()
    for i in ranking:
        g=int(group[i])
        if g in visited:continue
        visited.add(g)
        path=set(map(int,members[g][~kept[members[g]]]))
        j=int(i)
        while j>=0:
            if not kept[j]:path.add(j)
            j=int(parent[j])
        j=int(pivot[i])
        while j>=0:
            if not kept[j]:path.add(j)
            j=int(backward[j])
        if used+len(path)<=budget:
            kept[list(path)]=True;used+=len(path)
        if used==budget:break
    return kept


def semantic_continuations(path):
    """Reuse all existing bounded POI semantic rules uniformly across cases.

    This preserves investigator context; these events are mandatory evidence,
    not new diffusion seeds and not certified temporal paths.
    """
    from . import poi_semantic_continuation as pc
    keys=('event_id','host','src','dst','src_type','dst_type','src_semantic','dst_semantic',
          'relation','timestamp_ns','data_size','is_declared_poi')
    rows=[]
    with gzip.open(path,'rt') as stream:
        for line in stream:
            row=json.loads(line)
            if row['relation'] in {'EVENT_WRITE','EVENT_EXECUTE','EVENT_CONNECT','EVENT_SENDTO',
                'EVENT_RECVFROM','EVENT_READ','EVENT_OPEN','EVENT_FORK'} or row.get('is_declared_poi'):
                rows.append({k:row[k] for k in keys if k in row})
    by_host={}
    for row in rows:by_host.setdefault(row['host'],[]).append(row)
    chosen=set()
    for host_rows in by_host.values():
        local=set()
        for fn in (pc.executable_continuations,pc.adjacent_file_writes,pc.network_poi_episode,
                   pc.poi_bridge_continuations,pc.file_poi_io_origin,pc.forward_file_execution,
                   pc.post_write_parent_connect,pc.file_poi_named_context):
            local.update(fn(host_rows))
        connects=local|{r['event_id'] for r in host_rows if r.get('is_declared_poi') and r['relation']=='EVENT_CONNECT'}
        local.update(pc.shell_forks_after_connections(host_rows,connects))
        chosen.update(local)
    return chosen


def episode_evidence(values,group,timestamp):
    """Concave short-window occupancy evidence; not an anomaly probability.

    Distinct event timestamps provide sublinear corroboration. Repeated copies
    of the same timestamp in one episode cannot increase this priority.
    """
    distinct=np.unique(np.column_stack((group,timestamp)),axis=0)
    counts=np.bincount(distinct[:,0],minlength=int(group.max())+1)
    return values*np.sqrt(counts[group])
