"""Historical conditional frequency and bounded channel retrieval.

No reference labels or attack-specific identities. Empirical percentiles are
investigative priorities, not calibrated attack probabilities.
"""
from collections import Counter,defaultdict
import math
import numpy as np
from scipy.sparse import coo_matrix
from .frequency_diffusion import episodes
from .marginal_witness import make_pool,WitnessPool


class ConditionalHistory:
    def __init__(self,fit,calibration,alpha=10.,minimum=32):
        if alpha<=0 or minimum<1:raise ValueError('invalid smoothing/support')
        self.fit=dict(fit);self.alpha=alpha;self.minimum=minimum
        self.total=Counter();self.source=Counter();self.destination=Counter();vocab=defaultdict(set)
        for key,count in fit.items():
            if len(key)!=6 or count<=0:raise ValueError('invalid frequency record')
            self.total[key[:2]]+=count;self.source[key[:4]]+=count
            self.destination[key[:2]+key[4:]]+=count;vocab[key[:2]].add(key[4:])
        self.vocab={k:len(v) for k,v in vocab.items()};self.distributions={}
        bygroup=defaultdict(list)
        for key,count in calibration.items():
            if len(key)!=6 or count<=0:raise ValueError('invalid calibration record')
            bygroup[key[:2]].append((self.novelty(key),count))
        for group,rows in bygroup.items():
            rows.sort();v=np.array([x[0] for x in rows]);weights=np.array([x[1] for x in rows],float)
            self.distributions[group]=(v,np.r_[0,np.cumsum(weights)])

    def probability(self,key):
        group=key[:2];v=self.vocab.get(group,0)
        prior=(self.destination[key[:2]+key[4:]]+1)/(self.total[group]+v+1)
        return (self.fit.get(key,0)+self.alpha*prior)/(self.source[key[:4]]+self.alpha)

    def novelty(self,key):return -math.log(max(self.probability(key),1e-300))

    def supported(self,key):
        distribution=self.distributions.get(key[:2])
        return self.total[key[:2]]>=self.minimum and distribution is not None and distribution[1][-1]>=self.minimum

    def percentile(self,key):
        if not self.supported(key):raise ValueError('insufficient history')
        v,cum=self.distributions[key[:2]];value=self.novelty(key)
        left=np.searchsorted(v,value,side='left');right=np.searchsorted(v,value,side='right')
        return float((.5*(cum[left]+cum[right])+1)/(cum[-1]+2))

    def calibrate(self,key,original,mix=.5):
        if not 0<=original<=1 or not 0<=mix<=1:raise ValueError('invalid rarity/mix')
        return (1-mix)*original+mix*self.percentile(key) if self.supported(key) else original


def aggregate_history(connection,start_ns,end_ns,bucket_ns=60_000_000_000):
    if start_ns>=end_ns or bucket_ns<=0:raise ValueError('invalid history window')
    rows=connection.execute('''SELECT e.host,e.relation,ns.node_type,ns.semantic_key,
        nd.node_type,nd.semantic_key,COUNT(DISTINCT CAST(e.timestamp_ns / ? AS INTEGER))
        FROM edges e JOIN nodes ns ON ns.uuid=e.src JOIN nodes nd ON nd.uuid=e.dst
        WHERE e.timestamp_ns>=? AND e.timestamp_ns<?
        GROUP BY e.host,e.relation,ns.node_type,ns.semantic_key,nd.node_type,nd.semantic_key''',
        (bucket_ns,int(start_ns),int(end_ns)))
    return {tuple(row[:6]):int(row[6]) for row in rows}


def interaction_groups(src,dst,timestamp,window_ns):
    return episodes(np.minimum(src,dst),np.maximum(src,dst),np.zeros(len(src),int),timestamp,window_ns)


def share_channel_scores(values,groups):
    maximum=np.zeros(int(groups.max())+1)
    np.maximum.at(maximum,groups,values)
    return maximum[groups]


def expanded_pool(values,relations,mandatory,budget,ties,routes,groups,minimum=4096,expanded_minimum=32768,multiplier=8):
    base=make_pool(values,relations,mandatory,budget,ties,routes,minimum)
    back,parent,pivot=routes
    sibling=np.isin(groups,groups[base.anchors])&(pivot>=0)&(values>0)
    sibling[base.anchors]=False;extra=np.flatnonzero(sibling)
    limit=max(expanded_minimum,multiplier*budget,len(base.anchors))
    extra=extra[np.lexsort((ties[extra],-values[extra]))][:max(0,limit-len(base.anchors))]
    anchors=np.r_[base.anchors,extra];order=np.argsort(ties[anchors],kind='stable');anchors=anchors[order]
    bundles=list(base.bundles)
    for i in extra:
        members=set();j=int(i);seen=set()
        while j>=0:
            if j in seen:raise ValueError('cyclic parent route')
            seen.add(j);members.add(j);j=int(parent[j])
        j=int(pivot[i]);seen=set()
        while j>=0:
            if j in seen:raise ValueError('cyclic backward route')
            seen.add(j);members.add(j);j=int(back[j])
        bundles.append(np.array(sorted(members),dtype=np.int64))
    bundles=[bundles[i] for i in order]
    events=np.unique(np.concatenate([np.flatnonzero(mandatory)]+bundles))
    rows=np.concatenate([np.searchsorted(events,b) for b in bundles]) if bundles else np.array([],int)
    cols=np.repeat(np.arange(len(bundles)),[len(b) for b in bundles])
    incidence=coo_matrix((np.ones(len(rows),np.int8),(rows,cols)),shape=(len(events),len(anchors))).tocsr()
    diagnostics=base.diagnostics|dict(base_pool_anchors=len(base.anchors),base_pool_raw_events=len(base.events),
        pool_anchors=len(anchors),pool_raw_events=len(events),eligible_siblings=int(sibling.sum()),added_siblings=len(extra),expanded_pool_limit=limit)
    return WitnessPool(anchors,bundles,base.values,base.relations,base.mandatory,ties[anchors],events,incidence,diagnostics)
