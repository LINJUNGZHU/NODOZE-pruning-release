"""Detailed offline references must stay bound to the exact frozen selection."""
import json

import pytest

from test_evaluate_chain_workbench import frozen, change_registration


def api():
    from scripts.export_chain_reference_audit import ReferenceAuditExporter
    return ReferenceAuditExporter


def test_audit_has_exact_paths_missing_edges_and_string_times(frozen, tmp_path):
    exporter = api()(frozen['run'])
    output = tmp_path / 'audit.json'
    audit = exporter.export('cadets06', 'base', 'single', 'rarity_only', 2, output)
    assert json.loads(output.read_text()) == audit
    assert audit['counts']['reference_chains'] == 1
    assert audit['counts']['retained_reference_chains'] == 0
    assert audit['counts']['covered_positive_events'] == 3
    assert audit['verified_attack_chain_count'] is None
    assert audit['chains'][0]['missing_event_ids']
    assert audit['chains'][0]['status'] == 'broken'
    assert all(isinstance(event['timestamp_ns'], str) for event in audit['events'])
    assert [e['event_id'] for e in audit['events'] if e['retained']] == ['SECRET_EVENT_A', 'SECRET_EVENT_B']
    complete = exporter.export('cadets06', 'base', 'single', 'rarity_only', 5, tmp_path/'full.json')
    assert complete['counts']['retained_reference_chains'] == 1
    assert complete['chains'][0]['status'] == 'complete'
    assert not complete['chains'][0]['missing_event_ids']
    with pytest.raises(FileExistsError):
        exporter.export('cadets06', 'base', 'single', 'rarity_only', 5, output)


def test_all_decisions_validated_before_reference_loading(frozen, monkeypatch):
    from scripts import evaluate_chain_workbench as evaluator
    (frozen['folder']/'base/adaptive/decisions.npz').write_bytes(b'broken')
    monkeypatch.setattr(evaluator, '_load_reference', lambda *_: pytest.fail('labels loaded too early'))
    with pytest.raises(ValueError, match='hash'):
        api()(frozen['run'])


def test_no_reference_is_unavailable_not_zero_or_perfect(frozen, tmp_path):
    change_registration(frozen, lambda registration: registration['case'].update(reference={'kind':'unavailable'}))
    audit = api()(frozen['run']).export('cadets06', 'base', 'single', 'rarity_only', 2, tmp_path/'audit.json')
    assert audit['annotation_status'] == 'unavailable'
    assert all(value is None for value in audit['counts'].values())
    assert audit['events'] == [] and audit['chains'] == []


def test_reject_unknown_budget_before_loading_labels(frozen, monkeypatch, tmp_path):
    from scripts import evaluate_chain_workbench as evaluator
    exporter = api()(frozen['run'])
    monkeypatch.setattr(evaluator, '_load_reference', lambda *_: pytest.fail('unregistered decision loaded labels'))
    with pytest.raises(ValueError, match='frozen'):
        exporter.export('cadets06', 'base', 'single', 'rarity_only', 3, tmp_path/'audit.json')


@pytest.mark.parametrize('name', ['manifest.json', 'decisions.npz'])
def test_mutation_after_global_validation_prevents_annotation(frozen, monkeypatch, tmp_path, name):
    from scripts import evaluate_chain_workbench as evaluator
    exporter = api()(frozen['run'])
    path = frozen['folder']/'base/single'/name
    path.write_bytes(path.read_bytes()+b' ')
    monkeypatch.setattr(evaluator, '_load_reference', lambda *_: pytest.fail('changed input loaded labels'))
    with pytest.raises(ValueError, match='changed'):
        exporter.export('cadets06', 'base', 'single', 'rarity_only', 2, tmp_path/'audit.json')


def test_manifest_expected_hash_is_not_rebased_after_validation(frozen, monkeypatch, tmp_path):
    from scripts import evaluate_chain_workbench as evaluator
    original = evaluator._validate_all
    def mutate_after_validation(root):
        result = original(root)
        path = frozen['folder']/'base/single/manifest.json'
        path.write_bytes(path.read_bytes()+b' ')
        return result
    monkeypatch.setattr(evaluator, '_validate_all', mutate_after_validation)
    exporter = api()(frozen['run'])
    monkeypatch.setattr(evaluator, '_load_reference', lambda *_: pytest.fail('changed manifest loaded labels'))
    with pytest.raises(ValueError, match='changed'):
        exporter.export('cadets06', 'base', 'single', 'rarity_only', 2, tmp_path/'audit.json')


def test_changed_decision_during_annotation_is_not_written(frozen, monkeypatch, tmp_path):
    from scripts import evaluate_chain_workbench as evaluator
    exporter = api()(frozen['run'])
    original = evaluator._load_reference
    def mutate_after_labels(registration):
        result = original(registration)
        path = frozen['folder']/'base/single/manifest.json'
        path.write_bytes(path.read_bytes()+b' ')
        return result
    monkeypatch.setattr(evaluator, '_load_reference', mutate_after_labels)
    output = tmp_path/'audit.json'
    with pytest.raises(ValueError, match='changed'):
        exporter.export('cadets06', 'base', 'single', 'rarity_only', 2, output)
    assert not output.exists()
