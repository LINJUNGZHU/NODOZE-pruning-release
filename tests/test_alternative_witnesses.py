import numpy as np
import pytest
from tc_pruning.rasp import temporal_routes,temporal_fork_routes
from tc_pruning.alternative_witnesses import alternative_fork_index,build_witnesses,validate_witness


def graph():
    # POI 0->1 at 10. One branch reaches 3 before the POI via 2; another after via 1.
    src=np.array([0,2,2,1,3]);dst=np.array([1,0,3,3,4]);ts=np.array([10,5,6,11,12]);poi=np.array([1,0,0,0,0],bool)
    back=temporal_routes(src,dst,ts,poi)[0][0]
    parent,pivot,_,_=temporal_fork_routes(src,dst,ts,poi,back)
    return src,dst,ts,poi,back,parent,pivot


def test_k1_is_old_fork_and_k3_finds_distinct_legal_branch():
    args=graph();src,dst,ts,poi,back,parent,pivot=args
    alt=alternative_fork_index(src,dst,ts,poi,back,3)
    one=build_witnesses(4,*args,alt,1)
    many=build_witnesses(4,*args,alt,3)
    assert len(one)==1 and one[0].events==(0,3,4)
    assert one[0]==many[0]
    assert len(many)>=2
    assert (0,1,2,4) in [w.events for w in many]
    assert all(validate_witness(w,src,dst,ts,poi) for w in many)


def test_equal_time_link_is_rejected_and_missing_routes_do_not_invent_certificate():
    src,dst,ts,poi,back,parent,pivot=graph()
    alt=alternative_fork_index(src,dst,ts,poi,back,3)
    w=build_witnesses(4,src,dst,ts,poi,back,parent,pivot,alt,3)[0]
    altered=ts.copy();altered[3]=altered[4]
    assert not validate_witness(w,src,dst,altered,poi)
    isolated_src=np.array([0,2]);isolated_dst=np.array([1,3]);isolated_ts=np.array([10,12]);isolated_poi=np.array([1,0],bool)
    b=temporal_routes(isolated_src,isolated_dst,isolated_ts,isolated_poi)[0][0]
    p,v,_,_=temporal_fork_routes(isolated_src,isolated_dst,isolated_ts,isolated_poi,b)
    a=alternative_fork_index(isolated_src,isolated_dst,isolated_ts,isolated_poi,b,3)
    assert build_witnesses(1,isolated_src,isolated_dst,isolated_ts,isolated_poi,b,p,v,a,3)==()
