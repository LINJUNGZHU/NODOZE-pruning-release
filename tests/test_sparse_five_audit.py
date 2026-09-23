import json

import pytest

from scripts.run_sparse_five_audit import CASE_NAMES, audit_inventory


def test_all_five_cases_are_required(tmp_path):
    inventory = tmp_path / 'cases.json'
    inventory.write_text(json.dumps({'cases': [{'name': name} for name in CASE_NAMES[:-1]]}))
    with pytest.raises(ValueError, match='five'):
        audit_inventory(inventory)


def test_theia_case_five_cannot_silently_use_trace(tmp_path):
    inventory = tmp_path / 'cases.json'
    cases = [{'name': name} for name in CASE_NAMES]
    cases[-1]['raw_logs'] = ['/data/ta1-trace-e3-official-1.json']
    inventory.write_text(json.dumps({'cases': cases}))
    with pytest.raises(ValueError, match='TRACE'):
        audit_inventory(inventory)


def test_explicit_trace_case_five_mapping_is_allowed(tmp_path):
    inventory = tmp_path / 'cases.json'
    cases = [{'name': name} for name in CASE_NAMES]
    cases[-1].update({'raw_logs': ['/data/ta1-trace-e3-official-1.json'],
                      'paper_case_identity': 'inferred_trace_case5'})
    inventory.write_text(json.dumps({'cases': cases}))
    entry = audit_inventory(inventory)['cases'][-1]
    assert entry['paper_case_identity'] == 'inferred_trace_case5'
    assert entry['status'] == 'unavailable'


def test_unavailable_cases_are_preserved(tmp_path):
    inventory = tmp_path / 'cases.json'
    inventory.write_text(json.dumps({'cases': [{'name': name} for name in CASE_NAMES]}))
    result = audit_inventory(inventory)
    assert [case['name'] for case in result['cases']] == list(CASE_NAMES)
    assert all(case['status'] == 'unavailable' for case in result['cases'])


def test_literal_theia_case_five_remains_marked_noncomparable_after_measurement(tmp_path):
    ledger = tmp_path / 'ledger.jsonl'
    ledger.write_text(json.dumps({'event_id': 'a', 'decisions': [{'budget_key': '0.2', 'kept': True}]}) + '\n')
    reference = tmp_path / 'reference.json'
    reference.write_text(json.dumps({'attack_event_ids': ['a'], 'metadata': {'exhaustive_event_labels': False}}))
    cases = [{'name': name} for name in CASE_NAMES]
    cases[-1].update({'ledger': str(ledger), 'reference': str(reference),
                      'paper_case_identity': 'ambiguous_literal_theia',
                      'reason': 'paper row may be TRACE'})
    inventory = tmp_path / 'cases.json'
    inventory.write_text(json.dumps({'cases': cases}))
    entry = audit_inventory(inventory)['cases'][-1]
    assert entry['status'] == 'measured_literal_only'
    assert entry['paper_case_identity'] == 'ambiguous_literal_theia'
    assert entry['reason'] == 'paper row may be TRACE'
