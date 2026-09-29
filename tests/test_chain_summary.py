"""Publication is a numeric allowlist, never recursive redaction of raw data."""
from copy import deepcopy
import importlib
import json

import pytest


SECRET = 'PRIVATE-EVENT-UUID-/home/alice/secret-203.0.113.9-SCORE-0.987654321'


def publisher():
    assert importlib.util.find_spec('scripts.publish_chain_summary') is not None
    return importlib.import_module('scripts.publish_chain_summary')


def ratio(n, d):
    return {'numerator': n, 'denominator': d, 'value': n / d if d else None}


def report():
    stages = ['source', 'candidate', 'retained']
    funnel = {
        'reference_event_count': 4, 'stage_order': stages,
        'stages': {stage: {'retained_event_count': count, 'total_retention': ratio(count, 4),
                          'conditional_retention': ratio(count, 4)}
                   for stage, count in zip(stages, [4, 4, 2])},
        'first_loss_counts': {'source': 0, 'candidate': 0, 'retained': 2, 'surviving': 2},
    }
    evaluation = {
        'schema_version': 'chain-evaluation-v1', 'reference_chain_count': 2,
        'admitted_complete_chain_count': 0, 'derived_reference_chain_count': 2,
        'stage_order': stages,
        'stages': {stage: {'reference_chain_count': count, 'reference_chain_retention': ratio(count, 2),
                          'complete_chain_count': 0, 'complete_chain_retention': ratio(0, 0)}
                   for stage, count in zip(stages, [2, 2, 1])},
        'first_loss_counts': {'source': 0, 'candidate': 0, 'retained': 1, 'surviving': 1},
        'event_funnel': deepcopy(funnel),
    }
    point = {
        'method': 'adaptive', 'method_label': SECRET, 'budget_ratio': .5, 'budget_edges': 5,
        'retained_edges': 2, 'actual_compression': .8,
        'complete_reference_retention': ratio(1, 2), 'verified_attack_chain_retention': ratio(0, 0),
        'candidate_chain_coverage': ratio(2, 2), 'conditional_reference_retention': ratio(1, 2),
        'positive_event_retention': ratio(2, 4),
        'chain_evaluation': evaluation, 'positive_event_funnel': deepcopy(funnel),
        'retained_event_ids': [SECRET], 'diagnostics': {'retained_score': SECRET},
    }
    return {'schema_version': 'adaptive-chain-study-v1', 'generated_at': SECRET,
            'methodology': {'source': SECRET}, 'cases': [{
                'id': 'cadets06', 'kind': 'real', 'label': SECRET, 'candidate_edges': 10,
                'reference_chains': [{'id': SECRET}, {'events': [{'src_semantic': SECRET, 'score': SECRET}]}],
                'source_provenance': {'database': SECRET}, 'history_source': SECRET,
                'results': [point],
            }]}


def test_public_summary_retains_metrics_without_any_private_strings():
    original = report()
    # Arbitrary nested extra fields, including inside ratio dictionaries, cannot
    # become publication fields merely because their enclosing object is safe.
    def inject(value):
        if isinstance(value, dict):
            for child in list(value.values()):
                inject(child)
            value['private_payload'] = SECRET
        elif isinstance(value, list):
            for child in value:
                inject(child)
    inject(original)
    before = deepcopy(original)
    result = publisher().make_public_summary(original)
    serialized = json.dumps(result, ensure_ascii=False, allow_nan=False)
    assert SECRET not in serialized
    assert 'private_payload' not in serialized
    assert result['schema_version'] == 'adaptive-chain-study-v1'
    assert result['data_visibility'] == 'aggregate_only'
    case = result['cases'][0]
    assert case['label'] == 'CADETS-06'
    assert case['reference_chains'] == []
    assert case['reference_chain_count'] == 2
    point = case['results'][0]
    assert point['complete_reference_retention'] == ratio(1, 2)
    assert point['chain_evaluation']['stages']['retained']['reference_chain_count'] == 1
    assert point['positive_event_funnel']['first_loss_counts']['retained'] == 2
    for key in ('diagnostics', 'source_provenance', 'retained_event_ids', 'missing_ids', 'lost_ids', 'chains'):
        assert f'"{key}"' not in serialized
    assert original == before


@pytest.mark.parametrize('field,value', [('candidate_edges', -1), ('candidate_edges', True),
                                        ('candidate_edges', 1.5), ('candidate_edges', float('nan'))])
def test_invalid_case_counts_are_rejected(field, value):
    data = report(); data['cases'][0][field] = value
    with pytest.raises(ValueError): publisher().make_public_summary(data)


@pytest.mark.parametrize('field,value', [('retained_edges', -1), ('budget_edges', -1),
                                        ('budget_ratio', float('nan')), ('budget_ratio', 1.1),
                                        ('actual_compression', float('inf')), ('actual_compression', -.1),
                                        ('actual_compression', .5), ('retained_edges', 6)])
def test_invalid_budget_or_compression_is_rejected(field, value):
    data = report(); data['cases'][0]['results'][0][field] = value
    with pytest.raises(ValueError): publisher().make_public_summary(data)


@pytest.mark.parametrize('bad_ratio', [
    {'numerator': -1, 'denominator': 2, 'value': -.5},
    {'numerator': 3, 'denominator': 2, 'value': 1.5},
    {'numerator': 1, 'denominator': 2, 'value': float('nan')},
    {'numerator': 1, 'denominator': 2, 'value': .7},
    {'numerator': 0, 'denominator': 0, 'value': 0},
    {'numerator': 1, 'denominator': 0, 'value': None},
    {'numerator': True, 'denominator': 2, 'value': .5},
])
def test_invalid_nested_ratios_are_rejected(bad_ratio):
    data = report()
    data['cases'][0]['results'][0]['chain_evaluation']['stages']['retained']['reference_chain_retention'] = bad_ratio
    with pytest.raises(ValueError): publisher().make_public_summary(data)


@pytest.mark.parametrize('field,value', [('id', SECRET), ('kind', SECRET), ('kind', 'synthetic')])
def test_case_identity_is_registered_and_kind_matches(field, value):
    data = report(); data['cases'][0][field] = value
    with pytest.raises(ValueError): publisher().make_public_summary(data)


def test_unregistered_method_and_stage_names_are_rejected():
    data = report(); data['cases'][0]['results'][0]['method'] = SECRET
    with pytest.raises(ValueError): publisher().make_public_summary(data)
    data = report(); data['cases'][0]['results'][0]['chain_evaluation']['stage_order'].append(SECRET)
    with pytest.raises(ValueError): publisher().make_public_summary(data)


def test_negative_nested_count_is_rejected():
    data = report(); data['cases'][0]['results'][0]['positive_event_funnel']['first_loss_counts']['retained'] = -1
    with pytest.raises(ValueError): publisher().make_public_summary(data)


def test_summary_is_idempotent_and_preserves_unavailable_ratios():
    first = publisher().make_public_summary(report())
    assert publisher().make_public_summary(first) == first
    assert first['cases'][0]['results'][0]['verified_attack_chain_retention'] == ratio(0, 0)


def test_cli_publishes_only_allowlisted_summary(tmp_path):
    module = publisher(); source = tmp_path / 'private.json'; output = tmp_path / 'web' / 'summary.json'
    source.write_text(json.dumps(report()))
    module.main(['--input', str(source), '--output', str(output)])
    assert json.loads(output.read_text()) == module.make_public_summary(report())
    assert SECRET not in output.read_text()
