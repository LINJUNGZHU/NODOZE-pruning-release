"""Separate development fix: expansion applies only to explored descriptors.

The r3/r4 modules remain frozen. This builder preserves budget for extending
existing groups instead of starting new representatives during expansion.
"""
import time
import numpy as np
from .group_completion import Bundle,Snapshot
from .alternative_witnesses import build_witnesses
from .group_completion_rrf import RankedGroups
from .budget_evidence_v7 import _group_order


def build_pool(data,primary,groups,routes,mandatory,cap=32768,max_examined=327680,representatives_only=False):
    tick=time.perf_counter();n=len(data['ids']);primary=np.asarray(primary,float);mandatory=set(map(int,mandatory))
    if len(set(data['ids']))!=n or len(primary)!=n or len(groups.group_of)!=n:raise ValueError('misaligned or duplicate event identity')
    if not np.isfinite(primary).all() or np.any(primary<0) or cap<1 or max_examined<1 or len(mandatory)>cap:raise ValueError('invalid candidate limits or scores')
    if any(e<0 or e>=n for e in mandatory):raise ValueError('mandatory outside ledger')
    back,parent,pivot=routes
    weights=groups.scores(primary)
    order=groups.ranked_descriptors(primary,data['tie']);order=[int(g) for g in order if weights[g]>0]
    states={};examined=0;unreachable=0;materialized=set(mandatory);actions=[];registry={};admitted_prefixes=set()
    seen=np.zeros(n,dtype=bool)
    def admit(g,target,limit):
        nonlocal examined,unreachable
        if g not in states:
            members=groups.members(g)
            ordered=members[np.lexsort((data['tie'][members],-primary[members]))]
            states[g]=dict(members=ordered,cursor=0,witnesses=[])
        s=states[g];pending=list(s['witnesses'][:target])
        union={e for w in pending for e in w.events}
        pending_cost=sum(e not in materialized for e in union)
        while len(pending)<target and s['cursor']<len(s['members']):
            i=int(s['members'][s['cursor']])
            if not seen[i]:
                if examined>=max_examined:break
                seen[i]=True;examined+=1
            if pivot[i]<0:
                s['cursor']+=1;unreachable+=1;continue
            ws=build_witnesses(i,data['src'],data['dst'],data['timestamp'],data['poi'],back,parent,pivot,None,1)
            if not ws:s['cursor']+=1;continue
            extra={e for e in ws[0].events if e not in union and e not in materialized}
            # Retain only prefixes admitted to the real event union. A blocked member
            # stays at the cursor and may become affordable through later sharing.
            if len(materialized)+pending_cost+len(extra)>limit:break
            pending_cost+=len(extra);pending.append(ws[0]);union.update(ws[0].events);s['cursor']+=1
        if not pending:return
        anchors=tuple(w.anchor for w in pending)
        if (g,anchors) in admitted_prefixes:return
        if len(materialized)+sum(e not in materialized for e in union)>limit:return
        if len(pending)>len(s['witnesses']):s['witnesses']=pending
        full=s['cursor']==len(s['members']) and len(pending)==len(s['witnesses'])
        level='full' if full else 'representative' if len(pending)==1 else 'continuation'
        actions.append(Bundle(anchors,tuple(sorted(union)),tuple(w.digest for w in pending),g,level))
        materialized.update(union);admitted_prefixes.add((g,anchors))
        registry.update((w.digest,w) for w in pending)
    # Exploration does not spend the entire materialization budget on representatives.
    reserved=min(cap,max(len(mandatory)+1,cap//4))
    for g in order:
        admit(g,1,reserved)
        if len(materialized)>=reserved:break
    admitted_groups={a.group for a in actions}
    expansion_order=[g for g in order if g in admitted_groups]
    if not representatives_only:
        largest=max((len(groups.members(g)) for g in expansion_order),default=1)
        targets=[];size=2
        while size<largest:targets.append(size);size*=2
        targets.append(largest)
        for target in targets:
            for g in expansion_order:admit(g,min(target,len(groups.members(g))),cap)
    # Include one-member groups refused by the exploration reserve if final capacity allows.
    for g in order:admit(g,1,cap)
    certificates=tuple(registry.values())
    pool=Snapshot(tuple(actions),primary,groups.group_of.copy(),weights,certificates,tuple(sorted(materialized)))
    admitted={i for a in actions for i in a.anchors}
    diag=dict(cap=cap,max_examined=max_examined,examined_events=examined,unreachable_examined=unreachable,
              materialized_events=len(materialized),actions=len(actions),certificates=len(certificates),
              executable_anchors=len(admitted),zero_score_details_admitted=int(sum(primary[i]==0 for i in admitted)),
              cached_certificates=len({w.digest for s in states.values() for w in s["witnesses"]}),
              representative_actions=sum(a.level=='representative' for a in actions),
              continuation_actions=sum(a.level=='continuation' for a in actions),full_actions=sum(a.level=='full' for a in actions),
              full_scope='all examined reachable members only; not attack truth',
              scan_truncated=examined>=max_examined and any(s['cursor']<len(s['members']) for s in states.values()),
              representatives_only=representatives_only,expansion_groups=len(expansion_order),exploration_limit=reserved,seconds=time.perf_counter()-tick,labels_used=False)
    return pool,diag


def build_rrf_pool(data,primary,rarity,path_view,groups,routes,mandatory,cap=32768,max_examined=327680,rrf_c=60):
    order=_group_order(groups,primary,rarity,path_view,data['tie'],'rrf',rrf_c)
    pool,diag=build_pool(data,primary,RankedGroups(groups,order),routes,mandatory,cap,max_examined)
    diag.update(rank_policy='rrf',rrf_c=rrf_c,revision='r5: stop exploration at reserve; expand only admitted descriptors')
    return pool,diag
