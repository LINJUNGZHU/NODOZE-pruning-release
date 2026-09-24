import sqlite3
import math
import numpy as np
import pytest
from tc_pruning.history_channel import ConditionalHistory, aggregate_history, interaction_groups, share_channel_scores, expanded_pool
from tc_pruning.marginal_witness import greedy_select


def key(dst,host='a',src='p',rel='READ'):
    return (host,rel,'process',src,'file',dst)


def test_conditional_probability_normalizes_seen_and_unseen_categories():
    h=ConditionalHistory({key('common'):90,key('rare'):10},{key('common'):90,key('rare'):10},minimum=1)
    assert sum(h.probability(key(k)) for k in ['common','rare','new'])==pytest.approx(1)
    assert h.calibrate(key('new'),.1)>h.calibrate(key('rare'),.1)>h.calibrate(key('common'),.1)
    # An unseen source backs off to the global destination distribution.
    assert h.probability(key('rare',src='new'))==pytest.approx(11/103)


def test_host_isolation_and_insufficient_history_preserves_original():
    h=ConditionalHistory({key('a'):100},{key('a'):100})
    assert h.calibrate(key('a',host='other'),.37)==.37
    h=ConditionalHistory({key('a'):10},{key('a'):100})
    assert h.calibrate(key('new'),.41)==.41


def test_weighted_ecdf_ties_are_identical_and_finite():
    h=ConditionalHistory({key('a'):10,key('b'):10},{key('a'):100,key('b'):100},minimum=1)
    assert h.percentile(key('a'))==h.percentile(key('b'))==.5
    assert 0<h.percentile(key('new'))<1
    assert math.isfinite(h.probability(key('new')))


def test_history_sql_respects_half_open_windows_and_deduplicates_minutes():
    c=sqlite3.connect(':memory:')
    c.executescript('CREATE TABLE nodes(uuid,node_type,semantic_key); CREATE TABLE edges(src,dst,host,relation,timestamp_ns);')
    c.executemany('INSERT INTO nodes VALUES(?,?,?)',[('p','process','p'),('a','file','a')])
    c.executemany('INSERT INTO edges VALUES(?,?,?,?,?)',[('p','a','a','READ',t) for t in [-1,0,1,59_000_000_000,60_000_000_000,120_000_000_000]])
    assert aggregate_history(c,0,60_000_000_000)=={key('a'):1}
    assert aggregate_history(c,60_000_000_000,120_000_000_000)=={key('a'):1}


def test_interaction_group_merges_directions_not_entities_or_unbounded_chain():
    src=np.array([0,1,0,0,2]);dst=np.array([1,0,1,1,3]);ts=np.array([0,5,10,11,0])
    g=interaction_groups(src,dst,ts,10)
    assert g[0]==g[1]==g[2] and g[3]!=g[0] and g[4]!=g[0]
    assert share_channel_scores(np.array([.9,.1,.2,.3,.4]),g).tolist()==[.9,.9,.9,.3,.4]


def test_expansion_recovers_low_score_sibling_without_free_edges():
    values=np.array([1.,.9,.8,.01,.7]);rels=np.zeros(5,int);m=np.arange(5)==0
    routes=(np.array([-1,0,0,0,0]),np.full(5,-1),np.array([0,1,2,3,-1]))
    group=np.array([0,1,2,1,1])
    pool=expanded_pool(values,rels,m,1,np.arange(5),routes,group,minimum=2,expanded_minimum=3,multiplier=1)
    assert 3 in pool.anchors and 4 not in pool.anchors
    assert len(pool.anchors)==3
    kept,_=greedy_select(pool,2,1)
    assert kept.sum()==2 and kept[0]
    assert pool.diagnostics['expanded_pool_limit']==3
