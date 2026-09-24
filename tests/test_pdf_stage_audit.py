import hashlib
import json

from scripts.audit_pdf_stage_anchors import audit


def test_pdf_stage_audit_supports_differently_ordered_baseline_and_optimized_ledgers(tmp_path):
    pdf = tmp_path / 'report.pdf'
    pdf.write_bytes(b'fixed report')
    baseline = tmp_path / 'baseline.jsonl'
    optimized = tmp_path / 'optimized.jsonl'
    decisions = tmp_path / 'decisions.jsonl'
    def row(event_id, kept):
        return {'event_id': event_id, 'relation': 'EVENT_CONNECT',
                'host': 'test-host', 'timestamp_ns': 123,
                'src_semantic': 'process:implant', 'dst_semantic': f'socket:{event_id}:80',
                'decisions': [{'budget_key': '0.2', 'kept': kept}]}
    baseline.write_text('\n'.join(json.dumps(row(event_id, kept))
                                  for event_id, kept in [('a', True), ('b', False)]) + '\n')
    optimized.write_text('\n'.join(json.dumps(row(event_id, False))
                                   for event_id in ('b', 'a')) + '\n')
    decisions.write_text('\n'.join(json.dumps({'event_id': event_id,
                                               'decisions': {'method': True}})
                                   for event_id in ('b', 'a')) + '\n')
    config = tmp_path / 'config.json'
    config.write_text(json.dumps({
        'protocol': 'test', 'pdf': str(pdf),
        'pdf_sha256': hashlib.sha256(pdf.read_bytes()).hexdigest(),
        'label_scope': 'representative only',
        'cases': [{
            'name': 'case', 'baseline_ledger': str(baseline),
            'optimized_ledger': str(optimized),
            'baseline_budget_key': '0.2', 'optimized_decision_path': str(decisions),
            'optimized_decision_key': 'method',
            'anchors': [{'stage': event_id, 'event_id': event_id,
                         'expected_relation': 'EVENT_CONNECT',
                         'expected_semantic_contains': f'socket:{event_id}:80',
                         'pdf_page': 1} for event_id in ('a', 'b')],
        }],
    }))
    case = audit(config)['cases'][0]
    assert (case['baseline_anchor_hits'], case['optimized_anchor_hits']) == (1, 2)
    assert case['optimized_candidate_anchor_hits'] == 2
    assert [(a['host'], a['timestamp_ns']) for a in case['anchors']] == [
        ('test-host', 123), ('test-host', 123),
    ]
