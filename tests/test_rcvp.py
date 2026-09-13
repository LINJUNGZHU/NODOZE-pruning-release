import numpy as np
import pytest

from tc_pruning import rcvp
from tc_pruning.rcvp_config import preset, validate_config, relation_families, optc_relation_names


def run(src, dst, times, poi, **overrides):
    n = max(src + dst) + 1
    cfg = dict(preset('full'), **overrides)
    return rcvp.propagate(np.array(src), np.array(dst), np.array(times, dtype=np.int64),
                          np.array(['EVENT_FORK'] * len(src)), np.ones(len(src)),
                          np.array(poi, dtype=bool), np.ones(n, dtype=bool), cfg)


def test_relation_mapping_and_fallback_are_configurable():
    cfg = preset('full')
    assert relation_families(['EVENT_READ', 'FILE_WRITE', 'EVENT_EXECUTE', 'unknown'], cfg).tolist() == [
        'file_read', 'file_write', 'execution', 'other']
    cfg['relation_families']['custom'] = ['unknown']
    cfg['relation_weights']['custom'] = 1.
    assert relation_families(['unknown'], validate_config(cfg))[0] == 'custom'


def test_optc_network_relation_uses_existing_observed_direction():
    edges = [{'relation': 'FLOW_MESSAGE', 'raw': {'properties': {'direction': d}}}
             for d in ('inbound', 'outbound', 'unknown')]
    names = optc_relation_names(edges, preset('full'))
    assert relation_families(names, preset('full')).tolist() == ['network_receive', 'network_send', 'other']
    assert all(e['relation'] == 'FLOW_MESSAGE' for e in edges)


def test_relation_normalization_does_not_follow_raw_relation_count():
    src = np.zeros(101, dtype=int)
    dst = np.arange(1, 102)
    rel = np.array(['EVENT_READ'] * 100 + ['EVENT_FORK'])
    operator = rcvp.build_operator(src, dst, np.arange(101), rel, np.ones(101), preset('relation_aware'))
    w = operator['forward_weight']
    assert w[:100].sum() == pytest.approx(.5)
    assert w[100] == pytest.approx(.5)


@pytest.mark.parametrize('times', [[2, 1, 3], [1, 1, 3]])
def test_no_reverse_or_equal_timestamp_path(times):
    _, diag = run([0, 1, 2], [1, 2, 3], times, [False, False, True])
    assert diag['edge_fields']['poi_backward_score'][0] == 0
    assert all(r['node'] != 0 for r in diag['roots'])


def test_background_equal_seeds_has_zero_lift():
    op = rcvp.build_operator(np.array([0, 1]), np.array([1, 2]), np.array([1, 2]),
                             np.array(['EVENT_FORK'] * 2), np.ones(2), preset('relation_aware'))
    a = rcvp.temporal_pass(op, [(0, 0, 1.)], reverse=False)
    b = rcvp.temporal_pass(op, [(0, 0, 1.)], reverse=False)
    assert np.array_equal(rcvp.contrast(a['log_support'], b['log_support']), np.zeros(2))


def test_source_tracing_and_two_valid_roots():
    _, diag = run([0, 1, 4, 2], [1, 2, 2, 3], [1, 2, 1, 3], [False, False, False, True],
                  root_quantile=0., root_min_score=0.)
    roots = {r['node'] for r in diag['roots']}
    assert {0, 4} <= roots
    assert diag['edge_fields']['root_forward_score'][0] > 0
    assert diag['edge_fields']['roundtrip_verification_score'][0] > 0
    assert diag['edge_fields']['roundtrip_verification_score'][2] > 0


def test_temporally_false_root_has_no_verification():
    _, diag = run([0, 1, 2], [1, 2, 3], [4, 2, 3], [False, False, True], root_quantile=0.)
    assert diag['edge_fields']['roundtrip_verification_score'][0] == 0
    assert all(r['node'] != 0 for r in diag['roots'])


def test_downstream_consequence_has_own_nonzero_channel():
    _, diag = run([0, 1, 2], [1, 2, 3], [1, 2, 3], [False, True, False])
    fields = diag['edge_fields']
    assert fields['poi_backward_score'][2] == 0
    assert fields['poi_forward_score'][2] > 0
    assert fields['diffusion_verified'][2] > 0


def test_hub_fanout_attenuation_does_not_cancel_in_normalization():
    src = np.array([0] * 30 + [31, 32])
    dst = np.array(list(range(1, 31)) + [32, 33])
    times = np.array([1] * 30 + [1, 2])
    config = dict(preset('full'), high_frequency_degree=10, fanout_gamma=1.)
    op = rcvp.build_operator(src, dst, times, np.array(['EVENT_FORK'] * 32), np.ones(32), config)
    assert op['forward_fanout'][0] < op['forward_fanout'][-1]
    result = rcvp.temporal_pass(op, [(0, 0, .5), (31, 0, .5)], reverse=False)
    assert result['log_support'][0] < result['log_support'][30]


def test_duplicate_interaction_transition_is_invariant():
    def weights(repeats):
        op = rcvp.build_operator(np.array([0] * repeats + [0]), np.array([1] * repeats + [2]),
             np.arange(repeats + 1), np.array(['EVENT_READ'] * repeats + ['EVENT_FORK']),
             np.ones(repeats + 1), preset('relation_aware'))
        return op['forward_weight']
    assert weights(1)[0] == weights(100)[0]
    assert weights(1)[-1] == weights(100)[-1]


def test_past_only_relation_cannot_dilute_future_transition():
    cfg = preset('relation_aware')
    op = rcvp.build_operator(np.array([0, 0]), np.array([1, 2]), np.array([1, 3]),
                            np.array(['EVENT_READ', 'EVENT_FORK']), np.ones(2), cfg)
    result = rcvp.temporal_pass(op, [(0, 2, 1.)])
    assert np.exp(result['log_support'][1]) == pytest.approx(cfg['damping'])


def test_source_state_normalization_uses_its_own_legal_future_families():
    cfg = preset('relation_aware')
    # Two arrivals to node 1; its READ family expires between the arrivals.
    op = rcvp.build_operator(np.array([0, 1, 0, 1]), np.array([1, 2, 1, 3]), np.array([1, 2, 3, 4]),
                            np.array(['EVENT_FORK', 'EVENT_READ', 'EVENT_FORK', 'EVENT_FORK']), np.ones(4), cfg)
    result = rcvp.temporal_pass(op, [(0, 0, 1.)])
    assert np.exp(result['log_support'][3]) == pytest.approx(cfg['damping'] ** 2)
    assert result['parent'][3] == 2


def test_reproducible_and_root_cap():
    args = ([0, 1, 4, 2], [1, 2, 2, 3], [1, 2, 1, 3], [False, False, False, True])
    a, da = run(*args, max_root_candidates=1)
    b, db = run(*args, max_root_candidates=1)
    assert np.array_equal(a, b)
    assert da['roots'] == db['roots']
    assert len(da['roots']) <= 1


def test_time_decay_is_applied_once_and_relation_override_is_used():
    cfg = dict(preset('relation_aware'), temporal_tau_seconds=10.,
               temporal_tau_overrides={'process_control': 20.})
    op = rcvp.build_operator(np.array([0]), np.array([1]), np.array([10_000_000_000]),
                             np.array(['EVENT_FORK']), np.ones(1), cfg)
    result = rcvp.temporal_pass(op, [(0, 0, 1.)])
    assert result['temporal_weight'][0] == pytest.approx(np.exp(-.5))
    assert np.exp(result['log_support'][0]) == pytest.approx(cfg['damping'] * np.exp(-.5))


def test_input_permutation_does_not_change_edge_scores():
    src, dst, ts = np.array([0, 1, 4, 2]), np.array([1, 2, 2, 3]), np.array([1, 2, 1, 3])
    rel, rarity, poi = np.array(['EVENT_FORK'] * 4), np.ones(4), np.array([False, False, False, True])
    order = np.array([3, 1, 0, 2])
    score, _ = rcvp.propagate(src, dst, ts, rel, rarity, poi, np.ones(5, bool))
    reordered, _ = rcvp.propagate(src[order], dst[order], ts[order], rel[order], rarity[order], poi[order], np.ones(5, bool))
    assert np.allclose(score[order], reordered, rtol=0, atol=1e-14)


@pytest.mark.parametrize('change', [{'fanout_gamma': float('nan')}, {'max_root_candidates': True},
                                  {'root_quantile': 2}, {'typo': 1}, {'temporal_tau_seconds': 0}])
def test_bad_configuration_fails_closed(change):
    with pytest.raises(ValueError):
        validate_config(dict(preset('full'), **change))


def test_small_timestamp_batches_avoid_repeated_numpy_sorts(monkeypatch):
    count = 200
    src = np.tile([0, 1], count)
    dst = np.tile([1, 2], count)
    timestamps = np.repeat(np.arange(count, dtype=np.int64), 2)
    poi = np.zeros(len(src), dtype=bool); poi[count] = True
    calls = []
    original = np.lexsort
    def counted(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)
    monkeypatch.setattr(np, 'lexsort', counted)
    rcvp.propagate(src, dst, timestamps, np.array(['EVENT_FORK'] * len(src)),
        np.ones(len(src)), poi, np.ones(3, dtype=bool), dict(preset('full'), include_legacy=False))
    assert len(calls) <= 1


@pytest.mark.parametrize('size', [2, 3, 4])
def test_small_timestamp_fast_path_matches_vector_reference(monkeypatch, size):
    rng = np.random.default_rng(117)
    n = size * 40
    src = rng.integers(0, 7, n); dst = rng.integers(0, 7, n)
    timestamps = np.repeat(np.arange(40, dtype=np.int64) * 1000000000, size)
    relations = rng.choice(['EVENT_FORK', 'EVENT_READ', 'EVENT_WRITE'], n)
    poi = np.zeros(n, dtype=bool); poi[n // 2] = True
    args = (src, dst, timestamps, relations, rng.random(n), poi, np.ones(7, dtype=bool))
    config = dict(preset('full'), include_legacy=False, temporal_tau_overrides={'file_read': 20.})
    fast, fast_diag = rcvp.propagate(*args, config)
    monkeypatch.setattr(rcvp, 'SMALL_TIMESTAMP_BATCH', 0)
    reference, reference_diag = rcvp.propagate(*args, config)
    np.testing.assert_allclose(fast, reference, rtol=1e-14, atol=1e-15)
    for name, field in fast_diag['edge_fields'].items():
        if field.dtype.kind in 'OUS':
            np.testing.assert_array_equal(field, reference_diag['edge_fields'][name])
        else:
            np.testing.assert_allclose(field, reference_diag['edge_fields'][name], rtol=1e-14, atol=1e-15)
    np.testing.assert_array_equal(fast_diag['backward_parent'], reference_diag['backward_parent'])
    np.testing.assert_array_equal(fast_diag['forward_parent'], reference_diag['forward_parent'])
    assert fast_diag['roots'] == reference_diag['roots']
