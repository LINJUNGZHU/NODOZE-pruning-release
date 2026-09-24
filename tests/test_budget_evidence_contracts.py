from pathlib import Path
import gzip,json
import numpy as np
import pytest
from tc_pruning.budget_evidence_v7 import verify_unique_ids,atomic_gzip_json,build_snapshot
from tc_pruning.deferred_event_groups import GroupIndex
from tc_pruning.rasp import temporal_routes,temporal_fork_routes


def test_duplicate_event_id_rejected_and_atomic_output_refuses_overwrite(tmp_path):
    with pytest.raises(ValueError,match='duplicate'):
        verify_unique_ids(['a','b','a'])
    p=tmp_path/'decision.json.gz';atomic_gzip_json(p,{'selected_ids':['a']})
    with gzip.open(p,'rt') as f:assert json.load(f)=={'selected_ids':['a']}
    with pytest.raises(FileExistsError):atomic_gzip_json(p,{'selected_ids':['b']})
    assert not list(tmp_path.glob('*.pending'))


def test_materialization_charges_each_member_and_its_own_certificate():
    src=np.array([0,1,1,1]);dst=np.array([1,2,2,2]);ts=np.array([10,11,12,13]);rel=np.array([0,1,1,1]);poi=np.array([1,0,0,0],bool);tie=np.array([1,2,3,4],np.uint64)
    data=dict(src=src,dst=dst,timestamp=ts,relation=rel,poi=poi,tie=tie,ids=['p','a','b','c'])
    b=temporal_routes(src,dst,ts,poi)[0][0];p,v,_,_=temporal_fork_routes(src,dst,ts,poi,b)
    groups=GroupIndex.from_events(src,dst,rel,ts,tie,10,'across_relations')
    primary=np.array([1.,.9,.8,.7]);rarity=primary.copy();temporal=primary.copy()
    snap,diag=build_snapshot(data,primary,rarity,temporal,groups,(b,p,v),{0},'group','primary',3,20)
    assert diag['n_materialized_events']<=3
    assert all(set(a.events)<=set(snap.materialized_events) for a in snap.actions)
    assert len({a.anchor for a in snap.actions if a.anchor>0})<=2
    assert len(snap.actions)==diag['n_witnesses']
