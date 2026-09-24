import gzip
import json

from scripts.build_sparse_critical_review_packets import build_case_packet


def test_review_packet_keeps_parallel_events_and_excludes_other_host_and_decisions(tmp_path):
    ledger = tmp_path / 'ledger.jsonl.gz'
    rows = [
        {'event_id': 'anchor', 'host': 'target', 'timestamp_ns': 100,
         'relation': 'EVENT_WRITE', 'src': 'proc', 'dst': 'file',
         'src_semantic': 'process:evil', 'dst_semantic': 'file:/tmp/evil',
         'decisions': [{'kept': True}]},
        {'event_id': 'read-1', 'host': 'target', 'timestamp_ns': 91,
         'relation': 'EVENT_READ', 'src': 'file2', 'dst': 'proc',
         'src_semantic': 'file:/tmp/input', 'dst_semantic': 'process:evil',
         'decisions': [{'kept': False}]},
        {'event_id': 'read-2', 'host': 'target', 'timestamp_ns': 92,
         'relation': 'EVENT_READ', 'src': 'file2', 'dst': 'proc',
         'src_semantic': 'file:/tmp/input', 'dst_semantic': 'process:evil',
         'decisions': [{'kept': True}]},
        {'event_id': 'other-host', 'host': 'elsewhere', 'timestamp_ns': 93,
         'relation': 'EVENT_READ', 'src': 'file2', 'dst': 'proc',
         'decisions': [{'kept': True}]},
        {'event_id': 'unrelated', 'host': 'target', 'timestamp_ns': 94,
         'relation': 'EVENT_READ', 'src': 'x', 'dst': 'y',
         'decisions': [{'kept': True}]},
    ]
    with gzip.open(ledger, 'wt') as stream:
        for row in rows:
            stream.write(json.dumps(row) + '\n')
    packet = build_case_packet(ledger, [{'event_id': 'anchor', 'stage': 'drop'}],
                               before_ns=20, after_ns=20)
    assert packet['candidate_edges'] == 5
    assert packet['anchors'][0]['event']['event_id'] == 'anchor'
    assert [row['event_id'] for row in packet['anchors'][0]['neighbors']] == [
        'read-2', 'read-1',
    ]
    assert '"decisions":' not in json.dumps(packet)
