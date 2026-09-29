"""Frozen validation checks graph contracts even after artifact hashes update."""
import json

import numpy as np
import pytest

from tc_pruning import chain_workbench as core
from scripts.run_adaptive_chains import synthetic_case


@pytest.fixture
def frozen(tmp_path):
    case = synthetic_case(81, noise_count=60, chain_count=2)
    rows = case['rows']
    evidence = core.prepare_evidence(rows, case['history'], case['cutoff_ns'])
    online = core.run_variant(rows, evidence, 'declared', [16], max_anchors=32)
    path = tmp_path / 'frozen'
    core.freeze_variant(path, rows, evidence, online, case_id='synthetic81', track='base', provenance={})
    return path


def update_manifest(path, change):
    manifest = json.loads((path / 'manifest.json').read_text())
    change(manifest)
    core.write_json(path / 'manifest.json', manifest)


def changed_gzip(path, filename, change):
    value = core.read_gzip(path / filename)
    replacement = change(value)
    core.write_gzip(path / filename, value if replacement is None else replacement)
    update_manifest(path, lambda m: m['artifacts'].update({filename: core.digest(path / filename)}))


def changed_npz(path, filename, change):
    with np.load(path / filename, allow_pickle=False) as source:
        data = {key: source[key].copy() for key in source.files}
    change(data)
    np.savez_compressed(path / filename, **data)
    update_manifest(path, lambda m: m['artifacts'].update({filename: core.digest(path / filename)}))


def test_valid_frozen_inputs_report_strict_implementation_check(frozen):
    result = core.validate_variant(frozen)
    assert result['valid'] and result['implementation_matches_current'] is True


@pytest.mark.parametrize('timestamp', ['not-an-integer', '1.5', '-1', str(2**63), True, 1.0])
def test_candidate_timestamp_contract_checked_after_rehash(frozen, timestamp):
    changed_gzip(frozen, 'candidates.json.gz', lambda rows: rows[0].update(timestamp_ns=timestamp))
    with pytest.raises(ValueError): core.validate_variant(frozen)


@pytest.mark.parametrize('identity', [None, '', '  '])
def test_missing_event_identity_rejected_after_rehash(frozen, identity):
    changed_gzip(frozen, 'candidates.json.gz', lambda rows: rows[0].update(event_id=identity))
    with pytest.raises(ValueError): core.validate_variant(frozen)


def test_whitespace_and_case_duplicate_identity_rejected(frozen):
    changed_gzip(frozen, 'candidates.json.gz', lambda rows: rows[1].update(event_id=' '+rows[0]['event_id'].upper()+' '))
    with pytest.raises(ValueError): core.validate_variant(frozen)


def test_history_cutoff_cannot_overlap_frozen_candidates(frozen):
    first = min(int(row['timestamp_ns']) for row in core.read_gzip(frozen / 'candidates.json.gz'))
    update_manifest(frozen, lambda m: m.update(cutoff_ns=str(first + 1)))
    with pytest.raises(ValueError): core.validate_variant(frozen)


def test_bundle_method_structure_is_validated(frozen):
    changed_gzip(frozen, 'bundles.json.gz', lambda data: {'arbitrary': 'not a witness'})
    with pytest.raises(ValueError): core.validate_variant(frozen)


@pytest.mark.parametrize('field,value', [
    ('complete_in_candidate', 'false'), ('complete_in_candidate', 1),
    ('anchor_index', True), ('event_indices', [-1]), ('event_indices', [True]),
    ('boundary_status', 'complete_attack'), ('scope', 'ground_truth'),
])
def test_bundle_contract_fields_cannot_fake_complete_witness(frozen, field, value):
    changed_gzip(frozen, 'bundles.json.gz', lambda data: data['adaptive_v1'][0].update({field: value}))
    with pytest.raises(ValueError): core.validate_variant(frozen)


def test_bundle_path_union_cannot_omit_required_events(frozen):
    def mutate(data):
        bundle = next(b for b in data['adaptive_v1'] if len(b['event_indices']) > 1)
        bundle['paths'] = [[bundle['event_indices'][0]]]
    changed_gzip(frozen, 'bundles.json.gz', mutate)
    with pytest.raises(ValueError): core.validate_variant(frozen)


def test_bundle_causal_paths_cannot_be_reversed(frozen):
    def mutate(data):
        path = next(p for b in data['adaptive_v1'] for p in b['paths'] if len(p) > 1)
        path.reverse()
    changed_gzip(frozen, 'bundles.json.gz', mutate)
    with pytest.raises(ValueError): core.validate_variant(frozen)


def test_equal_time_path_is_not_a_causal_chain(frozen):
    bundles = core.read_gzip(frozen / 'bundles.json.gz')
    a, b = next(p[:2] for bundle in bundles['adaptive_v1'] for p in bundle['paths'] if len(p) > 1)
    changed_gzip(frozen, 'candidates.json.gz', lambda rows: rows[b].update(timestamp_ns=rows[a]['timestamp_ns']))
    with pytest.raises(ValueError): core.validate_variant(frozen)


def test_changed_causal_endpoint_cannot_keep_old_witness(frozen):
    bundles = core.read_gzip(frozen / 'bundles.json.gz')
    a = next(p[0] for bundle in bundles['adaptive_v1'] for p in bundle['paths'] if len(p) > 1)
    changed_gzip(frozen, 'candidates.json.gz', lambda rows: rows[a].update(dst='disconnected-endpoint'))
    with pytest.raises(ValueError): core.validate_variant(frozen)


def test_temporal_and_method_eligibility_are_derived_from_actual_graph(frozen):
    changed_npz(frozen, 'eligibility.npz', lambda arrays: [array.fill(True) for array in arrays.values()])
    with pytest.raises(ValueError): core.validate_variant(frozen)


def test_old_context_fusion_must_match_frozen_confidence_and_surprise(frozen):
    changed_npz(frozen, 'evidence.npz', lambda arrays: arrays['context_v1'].fill(.123))
    with pytest.raises(ValueError): core.validate_variant(frozen)


def test_method_score_aliases_must_share_identical_values(frozen):
    changed_npz(frozen, 'scores.npz', lambda arrays: arrays['adaptive_v1'].fill(.123))
    with pytest.raises(ValueError): core.validate_variant(frozen)


@pytest.mark.parametrize('change', [
    lambda m: m.update(implementation={}),
    lambda m: m['implementation'].update({'tc_pruning/chain_workbench.py': 'not-a-sha256'}),
    lambda m: m['implementation'].update({'tc_pruning/chain_workbench.py': '0'*64}),
    lambda m: m['config'].update(reliability_weight=0),
    lambda m: m['config'].update(scoring={'wrong': True}),
    lambda m: m['config'].update(max_hops=True),
    lambda m: m['config'].update(max_anchors=0),
])
def test_implementation_and_configuration_are_bound_to_contract(frozen, change):
    update_manifest(frozen, change)
    with pytest.raises(ValueError): core.validate_variant(frozen)


def test_structural_only_mode_explicitly_reports_source_mismatch(frozen):
    update_manifest(frozen, lambda m: m['implementation'].update({'tc_pruning/chain_workbench.py': '0'*64}))
    result = core.validate_variant(frozen, strict_implementation=False)
    assert result['valid'] and result['implementation_matches_current'] is False


def test_diagnostic_retained_count_must_match_decision(frozen):
    update_manifest(frozen, lambda m: m['diagnostics']['rasp@16'].update(retained_edges=1234))
    with pytest.raises(ValueError): core.validate_variant(frozen)


def test_witness_resource_limits_are_present_in_frozen_diagnostics(frozen):
    manifest = json.loads((frozen / 'manifest.json').read_text())
    for method in ('adaptive_v1', 'reliability_chain'):
        diagnostic = manifest['diagnostics'][method+'@16']
        assert type(diagnostic['anchor_limit_reached']) is bool
        assert type(diagnostic['truncated_bundles']) is int
        assert diagnostic['max_anchors'] == 32
        assert diagnostic['max_hops'] == 64
        assert 'eligible_event_ids' not in diagnostic


def test_disconnected_path_cannot_be_smuggled_into_an_eligible_bundle(frozen):
    with np.load(frozen / 'eligibility.npz', allow_pickle=False) as arrays:
        unrelated = int(np.flatnonzero(~arrays['temporal'])[0])
    bundles = core.read_gzip(frozen / 'bundles.json.gz')
    target = next(b for b in bundles['adaptive_v1'] if b['complete_in_candidate'])
    target['event_indices'].append(unrelated)
    target['paths'].append([unrelated])
    core.write_gzip(frozen / 'bundles.json.gz', bundles)
    update_manifest(frozen, lambda m: m['artifacts'].update({'bundles.json.gz': core.digest(frozen / 'bundles.json.gz')}))
    changed_npz(frozen, 'eligibility.npz', lambda a: a['adaptive_v1'].__setitem__(unrelated, True))
    with np.load(frozen / 'decisions.npz', allow_pickle=False) as data:
        mask = data['adaptive_v1@16']
    completed = [b for b in bundles['adaptive_v1'] if b['complete_in_candidate'] and mask[b['event_indices']].all()]
    def repair_statistics(manifest):
        audit = manifest['diagnostics']['adaptive_v1@16']
        audit['retained_complete_bundles'] = len(completed)
        audit['selected_bundle_ids'] = [name for name in audit['selected_bundle_ids'] if name != target['id']]
    update_manifest(frozen, repair_statistics)
    with pytest.raises(ValueError, match='connected'):
        core.validate_variant(frozen)
