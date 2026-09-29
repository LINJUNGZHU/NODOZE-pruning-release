"""History reliability and evidence-diverse investigation anchors stay label-free."""
from copy import deepcopy
import importlib

import numpy as np
import pytest


def module():
    assert importlib.util.find_spec('tc_pruning.adaptive_pois') is not None
    return importlib.import_module('tc_pruning.adaptive_pois')


def row(event, program='worker', process=None, relation='EVENT_WRITE', seconds=1, declared=False, **extra):
    return {'event_id': event, 'src': process or program+'-process', 'dst': 'resource-'+event,
            'src_type': 'process', 'dst_type': 'file', 'src_semantic': 'process:/usr/bin/'+program,
            'dst_semantic': 'file:/tmp/resource-'+event, 'host': 'host', 'relation': relation,
            'timestamp_ns': seconds*1_000_000_000, 'is_declared_poi': declared, **extra}


def test_zero_confidence_returns_exact_legacy_rarity_and_full_support_interpolates():
    raw = np.array([.0001, .3, 1., .9])
    context = [{'confidence': 0., 'contextual_surprise': 1.} for _ in raw]
    assert np.array_equal(module().reliability_rarity(raw, context), raw)
    context[-1] = {'confidence': 1., 'contextual_surprise': .1}
    actual = module().reliability_rarity(raw, context)
    assert np.array_equal(actual[:3], raw[:3])
    assert actual[-1] == pytest.approx(.3)


def test_supported_semantically_ordinary_novel_resource_is_below_unusual_behavior():
    context = [{'confidence': .9, 'contextual_surprise': .01, 'novelty': 1.},
               {'confidence': .9, 'contextual_surprise': .95, 'novelty': .5}]
    ordinary, unusual = module().reliability_rarity([1., .8], context)
    assert ordinary == pytest.approx(.33175)
    assert unusual > ordinary


@pytest.mark.parametrize('raw,context,weight', [
    ([1.], [], .75), ([float('nan')], [{'confidence': 0., 'contextual_surprise': 0.}], .75),
    ([1.1], [{'confidence': 0., 'contextual_surprise': 0.}], .75),
    ([.5], [{'confidence': -.1, 'contextual_surprise': 0.}], .75),
    ([.5], [{'confidence': .2, 'contextual_surprise': float('inf')}], .75),
    ([.5], [{'confidence': True, 'contextual_surprise': 0.}], .75),
    ([.5], [{'confidence': 0., 'contextual_surprise': 0.}], 1.1),
    ([.5], [{'confidence': 0., 'contextual_surprise': 0.}], True),
    (['.5'], [{'confidence': 0., 'contextual_surprise': 0.}], .75),
])
def test_invalid_reliability_inputs_are_rejected(raw, context, weight):
    with pytest.raises(ValueError): module().reliability_rarity(raw, context, weight=weight)


def test_all_declared_anchors_preserved_even_when_they_share_an_episode():
    rows = [row('a', declared=True), row('b', declared=True), row('c', program='other')]
    kept, diag = module().select_adaptive_pois(rows, [0., 0., .9], max_pois=3)
    assert kept.tolist() == [True, True, True]
    assert diag['declared_event_ids'] == ['a', 'b']
    assert diag['suggested_event_ids'] == ['c']
    assert diag['suggested_are_detector_confirmed'] is False


def test_suggestions_are_variable_count_and_stop_below_meaningful_gain():
    rows = [row('seed', declared=True), row('good', program='rare'), row('weak', program='weak')]
    kept, diag = module().select_adaptive_pois(rows, [1., .8, .01])
    assert kept.tolist() == [True, True, False]
    assert diag['stop_reason'] == 'gain_below_threshold'
    assert diag['selected_count'] == 2
    assert diag['suggestions'][0]['marginal_gain'] >= .05


def test_repeated_resources_in_same_episode_cannot_create_more_anchors():
    rows = [row('declared', program='seed', declared=True)]
    rows += [row(f'noise-{i:04}', program='noisy') for i in range(200)]
    rows += [row('important', program='different')]
    kept, diag = module().select_adaptive_pois(rows, [1.] + [.99]*200 + [.7])
    assert kept.sum() == 3
    assert diag['suggested_event_ids'] == ['important', 'noise-0000']
    assert diag['episode_representative_count'] == 3


def test_many_noisy_process_instances_do_not_monopolize_suggestions():
    rows = [row('seed', program='seed', declared=True)]
    rows += [row(f'noise-{i:04}', program='noisy', process=f'pid-{i}') for i in range(200)]
    rows += [row('important', program='different')]
    kept, diag = module().select_adaptive_pois(rows, [1.] + [.99]*200 + [.7])
    assert kept[-1]
    assert sum(kept[1:-1]) == 1
    assert kept.sum() == 3


def test_new_operation_can_add_anchor_while_later_identical_episode_stops():
    rows = [row('seed', declared=True), row('other-op', relation='EVENT_SENDTO'),
            row('late-same-op', seconds=121)]
    kept, _ = module().select_adaptive_pois(rows, [1., 1., 1.], gain_threshold=.08)
    assert kept.tolist() == [True, True, False]


def test_event_order_and_label_metadata_do_not_change_selected_identities():
    rows = [row('b', program='other'), row('seed', declared=True), row('a', program='other'), row('weak', program='weak')]
    values = np.array([.8, 1., .8, .01])
    original = deepcopy(rows)
    mask, audit = module().select_adaptive_pois(rows, values)
    order = [3, 2, 0, 1]
    altered = [dict(rows[i], ground_truth='malicious', attack=True, label='known-positive') for i in order]
    second, audit2 = module().select_adaptive_pois(altered, values[order])
    assert {rows[i]['event_id'] for i in np.flatnonzero(mask)} == {altered[i]['event_id'] for i in np.flatnonzero(second)}
    assert audit == audit2
    assert rows == original


def test_zero_score_cannot_fabricate_seed_and_over_cap_declared_is_infeasible():
    kept, diag = module().select_adaptive_pois([row('a'), row('b')], [0., 0.])
    assert not kept.any()
    assert diag['stop_reason'] == 'no_anchor'
    with pytest.raises(ValueError, match='declared'):
        module().select_adaptive_pois([row('a', declared=True), row('b', declared=True)], [0., 0.], max_pois=1)


@pytest.mark.parametrize('changes,values,kwargs', [
    ({'timestamp_ns': 1.5}, [1.], {}), ({'timestamp_ns': True}, [1.], {}),
    ({'timestamp_ns': -1}, [1.], {}), ({'is_declared_poi': 'false'}, [1.], {}),
    ({}, [float('nan')], {}), ({}, [1.1], {}), ({}, [.8], {'max_pois': True}),
    ({}, [.8], {'episode_seconds': 0}), ({}, [.8], {'gain_threshold': -.1}),
])
def test_invalid_anchor_inputs_are_rejected(changes, values, kwargs):
    with pytest.raises(ValueError): module().select_adaptive_pois([row('a', **changes)], values, **kwargs)


def test_duplicate_event_ids_are_rejected():
    with pytest.raises(ValueError, match='event'):
        module().select_adaptive_pois([row('a'), row('a')], [.2, .5])


def test_reversed_storage_process_endpoint_keeps_same_cohort_without_mutation():
    first = row('seed', declared=True)
    second = row('read', relation='EVENT_READ')
    second.update(src='resource', dst=first['src'], src_type='file', dst_type='process',
                  src_semantic='file:/etc/passwd', dst_semantic=first['src_semantic'])
    before = deepcopy(second)
    mask, diag = module().select_adaptive_pois([first, second], [1., .8])
    assert mask.tolist() == [True, True]
    assert diag['cohort_count'] == 1
    assert second == before


def test_candidate_pool_is_bounded_and_discloses_pruned_representatives():
    rows = [row(f'program-{i:05}', program=f'program-{i:05}') for i in range(4200)]
    kept, diag = module().select_adaptive_pois(rows, np.ones(len(rows)), max_pois=2)
    assert kept.sum() == 2
    assert diag['candidate_pool_count'] <= 4096
    assert diag['candidate_pool_truncated'] is True
