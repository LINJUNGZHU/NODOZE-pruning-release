import json
import numpy as np
import pytest


def core():
    from tc_pruning import chain_workbench
    return chain_workbench


def sample():
    from scripts.run_adaptive_chains import synthetic_case
    return synthetic_case(81,noise_count=60,chain_count=2)


def test_matrix_is_label_independent_budgeted_and_cold_reliability_matches_legacy():
    data=sample();rows=data['rows']
    prepared=core().prepare_evidence(rows,[],data['cutoff_ns'])
    for policy in ('single','declared','adaptive'):
        online=core().run_variant(rows,prepared,policy,[12,24],max_anchors=32)
        assert online['poi'].any()
        assert set(online['masks'])=={f'{m}@{b}' for m in core().METHODS for b in (12,24)}
        assert np.array_equal(online['scores']['rasp'],online['scores']['reliability'])
        for key,mask in online['masks'].items():
            assert mask.dtype==np.bool_ and mask.sum()<=int(key.split('@')[1])
            assert np.all(mask[online['poi']])
            assert np.all(~mask|online['eligible'][key.split('@')[0]])
        other=core().run_variant([dict(r,attack=True,ground_truth='changed') for r in rows],prepared,policy,[12,24],max_anchors=32)
        assert all(np.array_equal(mask,other['masks'][key]) for key,mask in online['masks'].items())


def test_frozen_variant_replays_and_detects_tampering(tmp_path):
    c=core();data=sample();rows=data['rows'];prepared=c.prepare_evidence(rows,data['history'],data['cutoff_ns'])
    online=c.run_variant(rows,prepared,'declared',[16],max_anchors=32)
    path=tmp_path/'frozen';c.freeze_variant(path,rows,prepared,online,case_id='synthetic81',track='base',provenance={'kind':'fixture'})
    verified=c.validate_variant(path)
    assert verified['candidate_events']==len(rows)
    assert verified['decision_points']==len(c.METHODS)
    with pytest.raises(FileExistsError):c.freeze_variant(path,rows,prepared,online,case_id='x',track='base',provenance={})
    p=path/'decisions.npz';p.write_bytes(p.read_bytes()+b'bad')
    with pytest.raises(ValueError,match='hash'):c.validate_variant(path)


def test_source_history_and_actual_seed_identity_are_frozen(tmp_path):
    import gzip
    c=core();data=sample();rows=data['rows'];prepared=c.prepare_evidence(rows,data['history'],data['cutoff_ns'])
    online=c.run_variant(rows,prepared,'single',[12],max_anchors=32)
    c.freeze_variant(tmp_path/'frozen',rows,prepared,online,case_id='x',track='base',provenance={})
    with gzip.open(tmp_path/'frozen/candidates.json.gz','rt') as stream:stored=json.load(stream)
    assert sum(r['is_declared_poi'] for r in stored)==1
    assert all(set(r)<=set(c.INPUT_FIELDS) for r in stored)
    assert c.validate_variant(tmp_path/'frozen')['valid']


@pytest.mark.parametrize('budgets', [[],[0],[True],[2,2],[10000]])
def test_invalid_raw_budgets_rejected(budgets):
    data=sample();prepared=core().prepare_evidence(data['rows'],[],data['cutoff_ns'])
    with pytest.raises(ValueError):core().run_variant(data['rows'],prepared,'declared',budgets,max_anchors=32)


def test_history_boundary_cannot_overlap_earliest_candidate():
    data=sample();first=min(r['timestamp_ns'] for r in data['rows'])
    with pytest.raises(ValueError,match='history cutoff'):
        core().prepare_evidence(data['rows'],[],first+1)
