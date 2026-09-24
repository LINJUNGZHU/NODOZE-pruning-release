import gzip
import hashlib
import json

import pytest

from scripts.validate_sparse_local_critical_edges import build_case_reference


def test_reference_expands_only_nearby_same_host_pair_and_relation(tmp_path):
    ledger = tmp_path / 'ledger.jsonl.gz'
    rows = [
        {'event_id': 'anchor', 'host': 'target', 'timestamp_ns': 100_000_000_000,
         'relation': 'EVENT_WRITE', 'src': 'process', 'dst': 'file',
         'src_semantic': 'process:implant', 'dst_semantic': 'file:/tmp/implant',
         'decisions': [{'kept': True}]},
        {'event_id': 'parallel', 'host': 'target', 'timestamp_ns': 109_000_000_000,
         'relation': 'EVENT_WRITE', 'src': 'process', 'dst': 'file'},
        {'event_id': 'late', 'host': 'target', 'timestamp_ns': 111_000_000_000,
         'relation': 'EVENT_WRITE', 'src': 'process', 'dst': 'file'},
        {'event_id': 'other-host', 'host': 'elsewhere', 'timestamp_ns': 109_000_000_000,
         'relation': 'EVENT_WRITE', 'src': 'process', 'dst': 'file'},
        {'event_id': 'other-relation', 'host': 'target', 'timestamp_ns': 109_000_000_000,
         'relation': 'EVENT_OPEN', 'src': 'process', 'dst': 'file'},
    ]
    with gzip.open(ledger, 'wt') as stream:
        for row in rows:
            stream.write(json.dumps(row) + '\n')
    ledger_hash = hashlib.sha256(ledger.read_bytes()).hexdigest()
    packet = {
        'name': 'case', 'ledger': str(ledger), 'ledger_sha256': ledger_hash,
        'candidate_edges': len(rows),
        'selection_uses_detector_decisions': False,
        'anchors': [{'stage': 'drop', 'pdf_page': 1, 'event': rows[0],
                     'neighbors': []}],
    }
    choices = {'name': 'case', 'exemplars': [
        {'event_id': 'anchor', 'stage': 'drop', 'rationale': 'Report confirms drop'},
    ]}
    result = build_case_reference(packet, choices, window_ns=10_000_000_000)
    assert result['critical_event_ids'] == ['anchor', 'parallel']
    assert result['candidate_edges'] == 5
    assert result['exemplars'][0]['host'] == 'target'
    assert result['exemplars'][0]['pdf_page'] == 1
    assert 'decisions' not in result['exemplars'][0]


def test_reference_rejects_unsupported_stage_and_stale_ledger(tmp_path):
    ledger = tmp_path / 'ledger.jsonl.gz'
    with gzip.open(ledger, 'wt') as stream:
        stream.write(json.dumps({'event_id': 'a', 'host': 'h', 'timestamp_ns': 1,
                                 'relation': 'EVENT_WRITE', 'src': 'p', 'dst': 'f'}) + '\n')
    row = {'event_id': 'a', 'host': 'h', 'timestamp_ns': 1,
           'relation': 'EVENT_WRITE', 'src': 'p', 'dst': 'f'}
    packet = {'name': 'case', 'ledger': str(ledger),
              'ledger_sha256': hashlib.sha256(ledger.read_bytes()).hexdigest(),
              'candidate_edges': 1, 'selection_uses_detector_decisions': False,
              'anchors': [{'stage': 'drop', 'pdf_page': 1, 'event': row,
                           'neighbors': []}]}
    choices = {'name': 'case', 'exemplars': [
        {'event_id': 'a', 'stage': 'unknown', 'rationale': 'bad'},
    ]}
    with pytest.raises(ValueError, match='unsupported stage'):
        build_case_reference(packet, choices)
    choices['exemplars'][0]['stage'] = 'drop'
    packet['ledger_sha256'] = '0' * 64
    with pytest.raises(ValueError, match='ledger hash'):
        build_case_reference(packet, choices)
    packet['ledger_sha256'] = hashlib.sha256(ledger.read_bytes()).hexdigest()
    packet['anchors'][0]['event']['host'] = 'wrong-host'
    with pytest.raises(ValueError, match='metadata differs'):
        build_case_reference(packet, choices)
