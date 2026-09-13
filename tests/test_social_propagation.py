import numpy as np
import pytest
from tc_pruning.social_propagation import channel_weights, temporal_propagation


def run(rows, poi, balanced=True):
    a=np.array(rows,dtype=np.int64)
    w,z=channel_weights(a[:,0],a[:,1],a[:,3],np.ones(len(a)),balanced=balanced)
    return temporal_propagation(a[:,0],a[:,1],a[:,2],np.array(poi),w,z,np.arange(len(a)))


def test_relation_mass_is_balanced_without_replication_inflation():
    src=np.array([0,0,0,0]);dst=np.array([1,2,3,3]);rel=np.array([0,0,1,1])
    f,b=channel_weights(src,dst,rel,np.ones(4))
    assert np.allclose(f,[.25,.25,.5,.5])
    assert np.allclose(b,1)


def test_time_and_direction_do_not_create_fake_reachability():
    # POI 1->2 at t=2; an earlier 0->1 is a source witness.
    # Same-time 8->0 cannot feed that source; 2->7 at t=1 is too early.
    score,back,parent,pivot=run([(0,1,1,0),(1,2,2,0),(8,0,1,0),(2,7,1,0),(0,3,3,0),(3,4,4,0)], [0,1,0,0,0,0])
    assert score[0]>0 and back[0]==1
    assert score[2]==0 and score[3]==0
    assert score[4]>0 and score[5]>0
    assert pivot[5]==0 and parent[5]==4


def test_equal_time_events_cannot_feed_each_other():
    score,*_=run([(0,1,1,0),(1,2,2,0),(2,3,2,0),(3,4,3,0)],[1,0,0,0])
    assert score[1]>0 and score[2]==0 and score[3]==0


def test_duplicate_events_and_permutation_preserve_scores():
    rows=[(0,1,1,0),(1,2,2,1),(1,3,3,0)]
    score,*_=run(rows,[1,0,0])
    copied,*_=run(rows+[rows[1]],[1,0,0,0])
    assert np.allclose(score,copied[:3])
    permuted,*_=run([rows[i] for i in [2,0,1]],[0,1,0])
    assert np.allclose(score,permuted[[1,2,0]])


def test_missing_poi_rejected():
    with pytest.raises(ValueError):run([(0,1,1,0)],[0])


def test_selected_forks_have_complete_strict_witnesses_under_budget():
    from tc_pruning.rasp_diverse import event_families,select_diverse
    from scripts.run_social_propagation import verify_witnesses
    for seed in range(10):
        rng=np.random.default_rng(seed)
        src=rng.integers(0,8,40);dst=rng.integers(0,8,40)
        t=rng.integers(0,15,40);rel=rng.integers(0,3,40)
        poi=np.zeros(40,dtype=bool);poi[20]=True
        f,b=channel_weights(src,dst,rel,rng.random(40))
        score,back,parent,pivot=temporal_propagation(src,dst,t,poi,f,b,np.arange(40))
        family=event_families(src,dst,rel)
        for budget in (1,5,20):
            kept,anchors,_=select_diverse(score,poi,back,parent,pivot,family,budget,np.arange(40),0.)
            assert kept.sum()<=budget and kept[20]
            verify_witnesses(dict(src=src,dst=dst,timestamp=t,poi=poi),back,parent,pivot,kept,anchors)


def test_absent_time_window_means_full_selected_database():
    from scripts.run_social_propagation import reference_window
    assert reference_window(None)==(None,None)
    assert reference_window([10,20])==(10,20)
    with pytest.raises(ValueError):reference_window([20,10])


def test_reserved_selection_respects_total_cap_and_both_path_sets():
    from tc_pruning.social_propagation import select_reserved
    from tc_pruning.rasp_diverse import event_families
    src=np.array([0,1,1,2,3]);dst=np.array([1,2,3,4,5]);t=np.arange(5)
    poi=np.array([True,False,False,False,False]);rel=np.zeros(5,dtype=int);tie=np.arange(5)
    f,b=channel_weights(src,dst,rel,np.ones(5))
    score,back,parent,pivot=temporal_propagation(src,dst,t,poi,f,b,tie)
    kept,parts=select_reserved(score,score,poi,(back,parent,pivot),(back,parent,pivot),event_families(src,dst,rel),4,tie,.5)
    assert kept.sum()<=4 and kept[0]
    assert np.array_equal(kept,parts[0][0]|parts[1][0])


def test_excluded_dataset_never_enters_experiment(tmp_path):
    from scripts.run_social_propagation import run
    with pytest.raises(ValueError,match='not admitted'):
        run('optc-0201',tmp_path/'missing-inputs.json',tmp_path/'output')
    assert not (tmp_path/'output').exists()


def test_replay_rejects_a_missing_connector():
    from scripts.run_social_propagation import verify_witnesses
    src=np.array([0,1,0,3]);dst=np.array([1,2,3,4]);t=np.arange(4)
    poi=np.array([False,True,False,False]);tie=np.arange(4)
    f,b=channel_weights(src,dst,np.zeros(4,dtype=int),np.ones(4))
    _,back,parent,pivot=temporal_propagation(src,dst,t,poi,f,b,tie)
    anchors=np.array([False,True,False,True]);kept=np.ones(4,dtype=bool)
    data=dict(src=src,dst=dst,timestamp=t,poi=poi)
    verify_witnesses(data,back,parent,pivot,kept,anchors)
    kept[0]=False
    with pytest.raises(AssertionError):verify_witnesses(data,back,parent,pivot,kept,anchors)
