import numpy as np
import pytest
from tc_pruning import frequency_diffusion as fd


def test_episode_window_is_bounded_and_directions_separate():
    g = fd.episodes(np.array([0,0,0,1]), np.array([1,1,1,0]), np.zeros(4,int), np.array([0,9,18,0]), 10)
    assert g[0] == g[1] and g[1] != g[2] and g[0] != g[3]


def test_frequency_counts_instances_not_record_duplicates():
    s=np.array([0,0,1,2]); d=np.array([3,3,3,4]); r=np.zeros(4,int)
    u=fd.semantic_uniqueness(s,d,r,np.array([True,True,True,False,False]),np.array([0,1,2,3,4]))
    assert u[0] == pytest.approx(1/np.log2(3))
    assert u[0] == u[1] == u[2]
    assert u[3] == 1


def test_relation_balance_does_not_drown_single_network_channel():
    a,b,p=fd.transition(np.array([0,0,0]),np.array([1,2,3]),np.array([0,0,1]),np.ones(3),4,True)
    outgoing=p[a==0]
    assert np.allclose(sorted(outgoing),[.25,.25,.5])
    assert np.allclose(np.bincount(a,weights=p,minlength=4),1)


def test_diffusion_duplicate_invariance_and_isolated_mass():
    a,b,p=fd.transition(np.array([0,0]),np.array([1,1]),np.array([0,0]),np.ones(2),3,True)
    v,diag=fd.walk(a,b,p,np.array([0.,0.,1.]),.15,200,1e-10)
    assert np.allclose(v,[0,0,1]) and diag['converged']
    assert len(a)==2


def test_episode_admission_counts_all_members_and_connectors():
    score=np.array([1.,.9,.9,.1]); poi=np.array([True,False,False,False])
    backward=np.array([-1,-1,-1,0]); parent=np.array([-1,3,3,-1]); pivot=np.array([0,3,3,3])
    groups=np.array([0,1,1,2]); ties=np.arange(4)
    kept=fd.select_episodes(score,poi,backward,parent,pivot,groups,3,ties)
    assert kept.tolist()==[True,False,False,True]
    kept=fd.select_episodes(score,poi,backward,parent,pivot,groups,4,ties)
    assert kept.all()


def test_loader_host_isolation_and_type_aware_execute(tmp_path):
    import gzip,json
    rows=[]
    for host,kind in [('a','file'),('b','process')]:
        rows.append(dict(event_id=host,host=host,src='same',dst='other',src_type='process',dst_type=kind,
            src_semantic='p',dst_semantic='q',relation='EVENT_EXECUTE',timestamp_ns=0,components={'rarity':.2},
            is_declared_poi=True,score=.3,decisions=[]))
    path=tmp_path/'ledger.gz'
    with gzip.open(path,'wt') as f:
        for row in rows:f.write(json.dumps(row)+'\n')
    d=fd.load_ledger(path)
    assert len(d['process_nodes'])==4
    assert d['src'].tolist()==[1,2] and d['dst'].tolist()==[0,3]
    assert d['semantic'][0]!=d['semantic'][2]
