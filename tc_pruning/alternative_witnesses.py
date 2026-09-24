"""Up to k strict temporal fork certificates; first is the frozen legacy route."""
from dataclasses import dataclass
import hashlib,json
import numpy as np


@dataclass(frozen=True)
class Witness:
    anchor:int
    events:tuple[int,...]
    forward_chain:tuple[int,...]
    backward_chain:tuple[int,...]
    rule:str
    digest:str


@dataclass(frozen=True)
class AlternativeIndex:
    parent_event:np.ndarray
    parent_slot:np.ndarray
    pivot:np.ndarray
    depth:np.ndarray


def alternative_fork_index(src,dst,timestamp,poi,back,kmax=3,ties=None):
    """Keep a bounded number of forward fork states per node and timestamp layer."""
    src=np.asarray(src);dst=np.asarray(dst);timestamp=np.asarray(timestamp);poi=np.asarray(poi,bool);back=np.asarray(back)
    n=len(src)
    if any(len(a)!=n for a in (dst,timestamp,poi,back)) or kmax<1:raise ValueError('invalid route inputs')
    ties=np.arange(n,dtype=np.uint64) if ties is None else np.asarray(ties)
    if len(ties)!=n:raise ValueError('invalid tie order')
    large=n+1;back_depth=np.full(n,large,np.int32);back_depth[poi]=0
    for i in np.argsort(-timestamp,kind='stable'):
        if back[i]>=0:
            j=int(back[i])
            if timestamp[j]<=timestamp[i]:raise ValueError('non-strict backward route')
            back_depth[i]=back_depth[j]+1
    par=np.full((n,kmax),-1,np.int32);slot=np.full((n,kmax),-1,np.int8)
    piv=np.full((n,kmax),-1,np.int32);depth=np.full((n,kmax),large,np.int32)
    best={};order=np.argsort(timestamp,kind='stable');start=0
    while start<n:
        end=start+1
        while end<n and timestamp[order[end]]==timestamp[order[start]]:end+=1
        for i in order[start:end]:
            i=int(i);options=[]
            if back_depth[i]<large:options.append((int(back_depth[i]),-1,-1,i))
            for d,j,s,p in best.get(int(src[i]),[]):
                options.append((d+1,j,s,p))
            options.sort(key=lambda x:(x[0],int(ties[x[1]]) if x[1]>=0 else -1,x[2],x[3]))
            for z,(d,j,s,p) in enumerate(options[:kmax]):
                depth[i,z]=d;par[i,z]=j;slot[i,z]=s;piv[i,z]=p
        for i in order[start:end]:
            i=int(i)
            for z in range(kmax):
                if piv[i,z]<0:continue
                state=(int(depth[i,z]),i,z,int(piv[i,z]))
                nodes=(int(src[i]),int(dst[i])) if piv[i,z]==i else (int(dst[i]),)
                for node in nodes:
                    arr=best.setdefault(node,[]);arr.append(state)
                    arr.sort(key=lambda x:(x[0],int(ties[x[1]]),x[2]))
                    if len(arr)>kmax:del arr[kmax:]
        start=end
    return AlternativeIndex(par,slot,piv,depth)


def _make(anchor,forward,backward,rule):
    events=tuple(sorted(set(forward)|set(backward)))
    raw=json.dumps([anchor,events,forward,backward,rule],separators=(',',':'))
    return Witness(anchor,events,tuple(forward),tuple(backward),rule,hashlib.sha256(raw.encode()).hexdigest())


def validate_witness(w,src,dst,timestamp,poi):
    """Validate the two directed strict-time chains, not an attack-ground-truth claim."""
    f,b=w.forward_chain,w.backward_chain
    if not f or not b or f[0]!=w.anchor or f[-1]!=b[0] or not poi[b[-1]]:return False
    if tuple(sorted(set(f)|set(b)))!=w.events:return False
    for child,parent in zip(f,f[1:]):
        # A pivot exposes both endpoints: the sibling branch may leave its
        # source, while later links must follow the previous destination.
        linked=(dst[parent]==src[child] or (parent==f[-1] and src[parent]==src[child]))
        if not linked or timestamp[parent]>=timestamp[child]:return False
    if any(dst[child]!=src[parent] or timestamp[child]>=timestamp[parent] for child,parent in zip(b,b[1:])):return False
    return True


def build_witnesses(anchor,src,dst,timestamp,poi,back,parent,pivot,alternatives,k=3):
    if k<1:raise ValueError('k must be positive')
    if int(pivot[anchor])<0:return ()
    forward=[];j=int(anchor);seen=set()
    while j>=0:
        if j in seen:raise ValueError('cyclic legacy forward path')
        seen.add(j);forward.append(j);j=int(parent[j])
    if forward[-1]!=int(pivot[anchor]):raise ValueError('legacy pivot mismatch')
    backward=[];j=forward[-1];seen=set()
    while j>=0:
        if j in seen:raise ValueError('cyclic legacy backward path')
        seen.add(j);backward.append(j);j=int(back[j])
    first=_make(anchor,forward,backward,'legacy_fork')
    if not validate_witness(first,src,dst,timestamp,poi):raise ValueError('invalid legacy witness')
    out=[first];unique={first.events}
    for z in range(alternatives.pivot.shape[1]):
        if len(out)>=k:break
        if alternatives.pivot[anchor,z]<0:continue
        forward=[];i=int(anchor);slot=z;seen=set()
        while i>=0:
            if (i,slot) in seen:raise ValueError('cyclic alternative route')
            seen.add((i,slot));forward.append(i)
            nxt=int(alternatives.parent_event[i,slot]);slot=int(alternatives.parent_slot[i,slot]);i=nxt
        if forward[-1]!=int(alternatives.pivot[anchor,z]):raise ValueError('alternative pivot mismatch')
        backward=[];i=forward[-1];seen=set()
        while i>=0:
            if i in seen:raise ValueError('cyclic backward route')
            seen.add(i);backward.append(i);i=int(back[i])
        w=_make(anchor,forward,backward,'bounded_alternative')
        if not validate_witness(w,src,dst,timestamp,poi):raise ValueError('invalid alternative witness')
        if w.events not in unique:out.append(w);unique.add(w.events)
    return tuple(out)
