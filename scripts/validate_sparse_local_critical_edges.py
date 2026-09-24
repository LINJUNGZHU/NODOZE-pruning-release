"""Resolve analyst-chosen attack-step edges to an explicit local proxy reference.

The resulting labels are an operational benchmark, not the unpublished SPARSE
ground truth. A selected exemplar expands only to parallel CDM events on the
same host, directed entity pair, relation, and a 10-second time window.
"""

from __future__ import annotations

import argparse
import gzip
import json
from pathlib import Path

from tc_pruning.sparse_edge_evaluation import sha256_file


FIELDS = ('event_id', 'host', 'timestamp_ns', 'relation', 'src', 'dst',
          'src_semantic', 'dst_semantic', 'data_size')


def _view(row: dict) -> dict:
    return {field: row.get(field) for field in FIELDS}


def _rows(path: Path):
    opener = gzip.open if path.suffix == '.gz' else open
    with opener(path, 'rt', encoding='utf-8') as stream:
        for line in stream:
            yield json.loads(line)


def build_case_reference(packet: dict, choices: dict, *,
                         window_ns: int = 10_000_000_000) -> dict:
    if window_ns < 0:
        raise ValueError('window_ns must be nonnegative')
    if packet['name'] != choices['name']:
        raise ValueError('case name mismatch')
    if packet.get('selection_uses_detector_decisions') is not False:
        raise ValueError('review packet must be decision-blind')
    ledger = Path(packet['ledger'])
    if sha256_file(ledger) != packet['ledger_sha256']:
        raise ValueError('ledger hash differs from review packet')

    stage_rows = {}
    stage_pages = {}
    for anchor in packet['anchors']:
        stage = anchor['stage']
        if stage in stage_rows:
            raise ValueError(f'duplicate report stage: {stage}')
        stage_rows[stage] = {row['event_id']: row for row in
                             [anchor['event'], *anchor['neighbors']]}
        stage_pages[stage] = anchor['pdf_page']
    selected = {}
    for choice in choices['exemplars']:
        event_id = choice['event_id']
        stage = choice['stage']
        if stage not in stage_rows:
            raise ValueError(f'unsupported stage: {stage}')
        if event_id not in stage_rows[stage]:
            raise ValueError(f'exemplar outside review packet stage: {event_id}')
        if event_id in selected:
            raise ValueError(f'duplicate exemplar: {event_id}')
        rationale = choice.get('rationale')
        if not isinstance(rationale, str) or not rationale.strip():
            raise ValueError(f'missing rationale: {event_id}')
        selected[event_id] = (choice, stage_rows[stage][event_id])
    if not selected:
        raise ValueError('critical reference needs at least one exemplar')

    groups = {event_id: [] for event_id in selected}
    by_pair = {}
    for event_id, (_, row) in selected.items():
        key = tuple(row.get(field) for field in ('host', 'src', 'dst', 'relation'))
        by_pair.setdefault(key, []).append((event_id, int(row['timestamp_ns'])))
    resolved = {}
    count = 0
    for row in _rows(ledger):
        count += 1
        event_id = row['event_id']
        if event_id in selected:
            reviewed = selected[event_id][1]
            if any(row.get(field) != reviewed.get(field) for field in FIELDS):
                raise ValueError(f'exemplar metadata differs from ledger: {event_id}')
            resolved[event_id] = _view(row)
        key = tuple(row.get(field) for field in ('host', 'src', 'dst', 'relation'))
        for exemplar_id, timestamp in by_pair.get(key, ()):
            if abs(int(row['timestamp_ns']) - timestamp) <= window_ns:
                groups[exemplar_id].append(event_id)
    if count != packet['candidate_edges']:
        raise ValueError('candidate edge count differs from review packet')
    if resolved.keys() != selected.keys():
        raise ValueError(f'exemplars missing from ledger: {sorted(selected.keys() - resolved.keys())}')

    exemplars = []
    for event_id, (choice, _) in selected.items():
        row = resolved[event_id]
        exemplars.append({
            **row, 'stage': choice['stage'], 'pdf_page': stage_pages[choice['stage']],
            'rationale': choice['rationale'],
            'parallel_event_ids': sorted(groups[event_id]),
        })
    positives = sorted({event_id for group in groups.values() for event_id in group})
    return {
        'name': packet['name'], 'ledger': str(ledger.resolve()),
        'ledger_sha256': packet['ledger_sha256'], 'candidate_edges': count,
        'label_scope': 'local_minimal_attack_narrative_proxy',
        'parallel_edge_rule': 'same host, directed src/dst, relation, within window of an exemplar',
        'parallel_window_ns': window_ns,
        'closed_world_proxy_assumption': 'all candidate events outside these groups count as noncritical only for proxy metrics',
        'exemplars': exemplars, 'critical_event_ids': positives,
        'critical_event_count': len(positives),
        'stage_count': len({row['stage'] for row in exemplars}),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--choices', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.choices.read_text(encoding='utf-8'))
    pdf = Path(config['pdf'])
    if sha256_file(pdf) != config['pdf_sha256']:
        raise ValueError('official report hash differs from choices')
    cases = []
    for case in config['cases']:
        packet_path = Path(case['packet'])
        packet = json.loads(packet_path.read_text(encoding='utf-8'))
        result = build_case_reference(packet, case,
                                      window_ns=config.get('parallel_window_ns', 10_000_000_000))
        result['packet_sha256'] = sha256_file(packet_path)
        cases.append(result)
        print(result['name'], len(result['exemplars']), result['critical_event_count'])
    output = {
        'protocol': 'sparse-local-critical-edge-reference-v1',
        'source_method': 'SPARSE V-A2 POI/IOC/attack-step manual review; local directed-pair 10s expansion',
        'pdf_sha256': config['pdf_sha256'],
        'choices_sha256': sha256_file(args.choices),
        'official_sparse_event_ids_available': False,
        'cases': cases,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
