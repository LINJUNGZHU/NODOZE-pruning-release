"""Build bounded, executable candidate snapshots without reference labels."""
import gzip,json,time
from pathlib import Path
import numpy as np
from .candidate_views import rank_views
from .alternative_witnesses import build_witnesses,alternative_fork_index
from .evidence_objective import Action,CandidateSnapshot


def verify_unique_ids(ids):
    if len(ids)!=len(set(ids)):raise ValueError('duplicate event ID')


def atomic_gzip_json(path,content):
    path=Path(path)
    if path.exists():raise FileExistsError(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_suffix(path.suffix+'.pending')
    with tmp.open('xb') as raw:
        with gzip.GzipFile(fileobj=raw,mode='wb') as stream:
            stream.write(json.dumps(content,separators=(',',':')).encode())
    if path.exists():raise FileExistsError(path)
    tmp.replace(path)


def _group_order(groups,primary,rarity,temporal,ties,policy,c):
    gs=[groups.scores(v) for v in (primary,rarity,temporal)]
    group_ties=np.minimum.reduceat(np.asarray(ties)[groups.ordered_members],groups.offsets[:-1])
    return rank_views(*gs,group_ties,policy,c)


def build_snapshot(data,primary,rarity,temporal,groups,routes,mandatory,representation,rank_policy,materialized_event_cap,max_examined,rrf_c=60,alternative_index=None,k=1):
    """Materialize actual action certificates under a distinct ledger-ID cap.

    The group descriptor does not count as an event, but every admitted
    certificate event does. `max_examined` is a declared search boundary.
    """
    tick=time.perf_counter();n=len(data['ids']);verify_unique_ids(data['ids'])
    if representation not in ('event','group') or materialized_event_cap<1 or max_examined<1:raise ValueError('invalid candidate protocol')
    if any(len(x)!=n for x in (primary,rarity,temporal,data['src'],data['dst'],data['timestamp'],groups.group_of)):raise ValueError('misaligned candidate arrays')
    mandatory=set(map(int,mandatory))
    if any(i<0 or i>=n for i in mandatory):raise ValueError('mandatory outside ledger')
    if len(mandatory)>materialized_event_cap:raise ValueError('materialized cap below mandatory')
    back,parent,pivot=routes
    if representation=='event':
        order=rank_views(primary,rarity,temporal,data['tie'],rank_policy,rrf_c)
        iterator=((int(i),None) for i in order)
    else:
        order=_group_order(groups,primary,rarity,temporal,data['tie'],rank_policy,rrf_c)
        def enumerate_group():
            for g in order:
                members=groups.members(int(g))
                members=members[np.lexsort((data['tie'][members],-primary[members]))]
                for i in members:yield int(i),int(g)
        iterator=enumerate_group()
    materialized=set(mandatory);actions=[];certificates=[];scanned=generated=visited=potential=0;last_group=None
    for i,g in iterator:
        if scanned>=max_examined:break
        scanned+=1
        if g is not None and g!=last_group:
            visited+=1;potential+=len(groups.members(g));last_group=g
        if primary[i]<=0 or pivot[i]<0:continue
        ws=build_witnesses(i,data['src'],data['dst'],data['timestamp'],data['poi'],back,parent,pivot,alternative_index,k)
        generated+=len(ws)
        for w in ws:
            extra=set(w.events)-materialized
            if len(materialized)+len(extra)>materialized_event_cap:continue
            actions.append(Action(i,int(groups.group_of[i]),w.events,float(primary[i]),w.digest))
            certificates.append(w);materialized.update(extra)
    weights=np.zeros(len(groups),float)
    for a in actions:weights[a.group]=max(weights[a.group],a.score)
    snap=CandidateSnapshot(tuple(actions),np.asarray(primary,float),weights,n,tuple(sorted(materialized)),tuple(certificates))
    diag=dict(representation=representation,rank_policy=rank_policy,rrf_c=rrf_c,k=k,materialized_event_cap=materialized_event_cap,
              max_examined=max_examined,n_scanned_events=scanned,n_group_refs=visited,n_potential_members=potential if representation=='group' else scanned,
              n_executable_anchors=len(set(a.anchor for a in actions)),n_witnesses=len(actions),n_generated_certificates=generated,
              n_materialized_events=len(materialized),n_materialized_synthetic=sum(data['ids'][i].startswith('LINEAGE:') for i in materialized),
              build_seconds=time.perf_counter()-tick,scan_truncated=scanned>=max_examined and scanned<n)
    return snap,diag


def expand_alternatives(base,data,routes,groups,k,cap=None):
    """Keep the same anchors and add legal alternative certificates."""
    tick=time.perf_counter();back,parent,pivot=routes
    alt=alternative_fork_index(data['src'],data['dst'],data['timestamp'],data['poi'],back,k,data['tie'])
    anchors=list(dict.fromkeys(a.anchor for a in base.actions));actions=[];certs=[];materialized=set(base.materialized_events)
    for i in anchors:
        for w in build_witnesses(i,data['src'],data['dst'],data['timestamp'],data['poi'],back,parent,pivot,alt,k):
            if cap is not None and len(materialized|set(w.events))>cap:continue
            actions.append(Action(i,int(groups.group_of[i]),w.events,float(base.event_scores[i]),w.digest))
            certs.append(w);materialized.update(w.events)
    weights=np.zeros(len(groups),float)
    for a in actions:weights[a.group]=max(weights[a.group],a.score)
    snap=CandidateSnapshot(tuple(actions),base.event_scores,weights,base.event_count,tuple(sorted(materialized)),tuple(certs))
    return snap,dict(k=k,anchors=len(anchors),witnesses=len(actions),materialized_events=len(materialized),seconds=time.perf_counter()-tick)
