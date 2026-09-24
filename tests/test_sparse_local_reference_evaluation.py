import gzip
import json

import pytest

from scripts.evaluate_sparse_local_reference import evaluate_case


def test_proxy_metrics_count_exact_event_ids_and_group_coverage(tmp_path):
    ledger = tmp_path / 'ledger.jsonl.gz'
    decisions = tmp_path / 'decisions.jsonl.gz'
    rows = [
        {'event_id': 'a', 'decisions': [{'budget_key': '0.2', 'kept': True}]},
        {'event_id': 'b', 'decisions': [{'budget_key': '0.2', 'kept': True}]},
        {'event_id': 'c', 'decisions': [{'budget_key': '0.2', 'kept': True}]},
        {'event_id': 'd', 'decisions': [{'budget_key': '0.2', 'kept': False}]},
        {'event_id': 'e', 'decisions': [{'budget_key': '0.2', 'kept': False}]},
    ]
    with gzip.open(ledger, 'wt') as stream:
        for row in rows:
            stream.write(json.dumps(row) + '\n')
    with gzip.open(decisions, 'wt') as stream:
        for event_id, kept in [('a', True), ('b', True), ('c', False),
                               ('d', False), ('e', False)]:
            stream.write(json.dumps({'event_id': event_id,
                                     'decisions': {'method': kept}}) + '\n')
    reference = {
        'critical_event_ids': ['a', 'c'],
        'exemplars': [
            {'event_id': 'a', 'stage': 'drop', 'parallel_event_ids': ['a']},
            {'event_id': 'c', 'stage': 'connect', 'parallel_event_ids': ['c']},
        ],
    }
    baseline = evaluate_case(ledger, reference, budget_key='0.2')
    optimized = evaluate_case(ledger, reference, budget_key='0.2',
                              decision_path=decisions, decision_key='method')
    assert (baseline['proxy_tp'], baseline['proxy_fp'], baseline['proxy_fn'],
            baseline['proxy_tn']) == (2, 1, 0, 2)
    assert (optimized['proxy_tp'], optimized['proxy_fp'], optimized['proxy_fn'],
            optimized['proxy_tn']) == (1, 1, 1, 2)
    assert optimized['proxy_precision'] == 0.5
    assert optimized['proxy_recall'] == 0.5
    assert optimized['proxy_f1'] == 0.5
    assert optimized['proxy_fpr'] == 1 / 3
    assert optimized['proxy_fnr'] == 1 / 2
    assert optimized['proxy_fp_per_candidate'] == 1 / 5
    assert optimized['critical_groups_hit'] == 1
    assert optimized['official_equivalent_metrics'] == {
        'fp': None, 'fn': None, 'precision': None, 'recall': None, 'f1': None,
    }


def test_proxy_evaluation_reports_reference_edges_outside_candidate(tmp_path):
    ledger = tmp_path / 'ledger.jsonl'
    ledger.write_text(json.dumps({'event_id': 'a',
                                  'decisions': [{'budget_key': '0.2', 'kept': True}]}) + '\n')
    reference = {'critical_event_ids': ['a', 'outside'],
                 'exemplars': [{'event_id': 'a', 'stage': 'one', 'parallel_event_ids': ['a']},
                               {'event_id': 'outside', 'stage': 'two',
                                'parallel_event_ids': ['outside']}]}
    result = evaluate_case(ledger, reference, budget_key='0.2')
    assert result['reference_outside_candidate'] == 1
    assert result['proxy_fn'] == 1
    assert result['proxy_recall'] == 0.5


def test_proxy_evaluation_rejects_misaligned_decisions(tmp_path):
    ledger = tmp_path / 'ledger.jsonl'
    decision = tmp_path / 'decision.jsonl'
    ledger.write_text(json.dumps({'event_id': 'a'}) + '\n')
    decision.write_text(json.dumps({'event_id': 'wrong',
                                    'decisions': {'method': True}}) + '\n')
    with pytest.raises(ValueError, match='identity mismatch'):
        evaluate_case(ledger, {'critical_event_ids': ['a'], 'exemplars': []},
                      budget_key='0.2', decision_path=decision,
                      decision_key='method')


def test_uncertain_events_are_excluded_from_proxy_negative_counts(tmp_path):
    ledger = tmp_path / 'ledger.jsonl'
    ledger.write_text(''.join(json.dumps({
        'event_id': event_id,
        'decisions': [{'budget_key': '0.2', 'kept': True}],
    }) + '\n' for event_id in ('critical', 'uncertain', 'negative')))
    result = evaluate_case(ledger, {
        'critical_event_ids': ['critical'],
        'uncertain_event_ids': ['uncertain'],
        'exemplars': [{'event_id': 'critical', 'stage': 'drop',
                       'parallel_event_ids': ['critical']}],
    }, budget_key='0.2')
    assert result['selected_uncertain_edges'] == 1
    assert result['proxy_fp'] == 1
    assert result['proxy_precision'] == 0.5
