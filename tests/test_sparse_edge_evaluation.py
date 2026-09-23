import gzip
import hashlib
import json

import pytest

from tc_pruning.sparse_edge_evaluation import evaluate_ledger


def write_inputs(tmp_path, rows, positives, *, complete=False, poi_ids=None):
    ledger = tmp_path / 'scores.jsonl.gz'
    with gzip.open(ledger, 'wt') as stream:
        for row in rows:
            stream.write(json.dumps(row) + '\n')
    reference = tmp_path / 'reference.json'
    reference.write_text(json.dumps({
        'attack_event_ids': positives,
        'poi_event_ids': poi_ids or [],
        'metadata': {
            'exhaustive_event_labels': complete,
            'candidate_ledger_sha256': hashlib.sha256(ledger.read_bytes()).hexdigest() if complete else None,
        },
    }))
    return ledger, reference


def row(event_id, kept):
    return {'event_id': event_id, 'decisions': [{'budget_key': '0.2', 'kept': kept}]}


def test_partial_truth_does_not_invent_false_positives(tmp_path):
    ledger, reference = write_inputs(tmp_path, [row('a', True), row('b', True), row('c', False)], ['a', 'c'])
    result = evaluate_ledger(ledger, reference, '0.2')
    assert result['candidate_edges'] == 3
    assert result['output_edges'] == 2
    assert result['known_positive_hits'] == 1
    assert result['known_positive_misses'] == 1
    assert result['observed_positive_recall'] == 0.5
    assert result['unreviewed_selected_edges'] == 1
    assert result['fp'] is None
    assert result['fn'] is None
    assert result['precision'] is None
    assert result['f1'] is None


def test_certified_complete_truth_calculates_paper_metrics(tmp_path):
    ledger, reference = write_inputs(tmp_path, [row('a', True), row('b', True), row('c', False)], ['a', 'c'], complete=True)
    result = evaluate_ledger(ledger, reference, '0.2')
    assert (result['tp'], result['fp'], result['fn'], result['tn']) == (1, 1, 1, 0)
    assert result['precision'] == 0.5
    assert result['recall'] == 0.5
    assert result['f1'] == 0.5
    assert result['paper_fpr'] == pytest.approx(1 / 3)


@pytest.mark.parametrize('rows, positives, error', [
    ([row('a', True), row('a', False)], ['a'], 'duplicate'),
    ([{'event_id': 'a', 'decisions': []}], ['a'], 'budget'),
    ([{'event_id': 'a', 'decisions': [row('a', True)['decisions'][0]] * 2}], ['a'], 'budget'),
])
def test_bad_identity_or_decision_fails_closed(tmp_path, rows, positives, error):
    ledger, reference = write_inputs(tmp_path, rows, positives)
    with pytest.raises(ValueError, match=error):
        evaluate_ledger(ledger, reference, '0.2')


def test_complete_claim_requires_bound_ledger_hash(tmp_path):
    ledger, reference = write_inputs(tmp_path, [row('a', True)], ['a'], complete=True)
    data = json.loads(reference.read_text())
    data['metadata']['candidate_ledger_sha256'] = 'wrong'
    reference.write_text(json.dumps(data))
    with pytest.raises(ValueError, match='hash'):
        evaluate_ledger(ledger, reference, '0.2')


def test_alternative_frozen_decisions_use_same_candidate_identity(tmp_path):
    ledger, reference = write_inputs(tmp_path, [row('a', True), row('b', True), row('c', False)], ['a', 'c'])
    decisions = tmp_path / 'other.jsonl.gz'
    with gzip.open(decisions, 'wt') as stream:
        for event_id, kept in [('a', False), ('b', False), ('c', True)]:
            stream.write(json.dumps({'event_id': event_id, 'decisions': {'new@0.2': kept}}) + '\n')
    result = evaluate_ledger(ledger, reference, '0.2', decision_path=decisions, decision_key='new@0.2')
    assert result['output_edges'] == 1
    assert result['known_positive_hits'] == 1
    assert result['decision_sha256'] == hashlib.sha256(decisions.read_bytes()).hexdigest()

    with gzip.open(decisions, 'wt') as stream:
        stream.write(json.dumps({'event_id': 'wrong', 'decisions': {'new@0.2': True}}) + '\n')
    with pytest.raises(ValueError, match='identity'):
        evaluate_ledger(ledger, reference, '0.2', decision_path=decisions, decision_key='new@0.2')


def test_report_informed_poi_is_excluded_from_new_recovery(tmp_path):
    ledger, reference = write_inputs(tmp_path, [row('a', True), row('b', True), row('c', False)], ['a', 'c'], poi_ids=['a'])
    result = evaluate_ledger(ledger, reference, '0.2')
    assert result['known_positive_hits'] == 1
    assert result['non_poi_positive_hits'] == 0
    assert result['non_poi_positive_edges'] == 1
    assert result['non_poi_observed_recall'] == 0


def test_partial_reference_reports_candidate_misses_without_calling_them_false_negatives(tmp_path):
    ledger, reference = write_inputs(tmp_path, [row('a', True), row('b', False)], ['a', 'outside'])
    result = evaluate_ledger(ledger, reference, '0.2')
    assert result['known_positive_hits'] == 1
    assert result['known_positive_misses'] == 1
    assert result['known_positive_outside_candidate'] == 1
    assert result['candidate_positive_coverage'] == 0.5
    assert result['fn'] is None


def test_complete_reference_rejects_positive_outside_bound_candidate(tmp_path):
    ledger, reference = write_inputs(tmp_path, [row('a', True)], ['a', 'outside'], complete=True)
    with pytest.raises(ValueError, match='outside'):
        evaluate_ledger(ledger, reference, '0.2')


def test_malformed_decision_schema_fails_closed(tmp_path):
    ledger, reference = write_inputs(tmp_path, [{'event_id': 'a', 'decisions': {'0.2': True}}], ['a'])
    with pytest.raises(ValueError, match='decisions'):
        evaluate_ledger(ledger, reference, '0.2')

    ledger, reference = write_inputs(tmp_path, [row('a', True)], ['a'])
    decisions = tmp_path / 'alternative.jsonl.gz'
    with gzip.open(decisions, 'wt') as stream:
        stream.write(json.dumps({'event_id': 'a', 'decisions': [True]}) + '\n')
    with pytest.raises(ValueError, match='decisions'):
        evaluate_ledger(ledger, reference, '0.2', decision_path=decisions, decision_key='other')
