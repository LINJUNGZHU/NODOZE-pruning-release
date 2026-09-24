"""Extract bounded, decision-blind CDM neighborhoods for manual edge review."""

from __future__ import annotations

import argparse
import gzip
import heapq
import json
import re
from pathlib import Path

from tc_pruning.sparse_edge_evaluation import sha256_file


FIELDS = ('event_id', 'edge_id', 'host', 'timestamp_ns', 'relation',
          'src', 'dst', 'src_semantic', 'dst_semantic', 'data_size')
REVIEW_RELATIONS = {'EVENT_WRITE', 'EVENT_READ', 'EVENT_OPEN', 'EVENT_EXECUTE',
                    'EVENT_FORK', 'EVENT_CONNECT', 'EVENT_SENDTO', 'EVENT_RECVFROM'}


def _view(row: dict) -> dict:
    return {field: row.get(field) for field in FIELDS}


def _rows(path: Path):
    opener = gzip.open if path.suffix == '.gz' else open
    with opener(path, 'rt', encoding='utf-8') as stream:
        for line in stream:
            yield json.loads(line)


def build_case_packet(
    ledger: Path, anchors: list[dict], *,
    before_ns: int = 30_000_000_000, after_ns: int = 30_000_000_000,
    max_per_anchor: int = 40,
) -> dict:
    """Return same-host neighbors of known report events without decisions."""
    if before_ns < 0 or after_ns < 0 or max_per_anchor < 1:
        raise ValueError('invalid packet bounds')
    specs = {anchor['event_id']: anchor for anchor in anchors}
    if len(specs) != len(anchors):
        raise ValueError('duplicate anchor event ID')
    found: dict[str, dict] = {}
    count = 0
    for row in _rows(ledger):
        count += 1
        event_id = row.get('event_id')
        if event_id in specs:
            if event_id in found:
                raise ValueError(f'duplicate anchor in ledger: {event_id}')
            found[event_id] = _view(row)
    missing = specs.keys() - found.keys()
    if missing:
        raise ValueError(f'anchors outside ledger: {sorted(missing)}')

    heaps: dict[str, list] = {event_id: [] for event_id in specs}
    for row in _rows(ledger):
        if row.get('relation') not in REVIEW_RELATIONS or row.get('event_id') in specs:
            continue
        for event_id, anchor in found.items():
            if row.get('host') != anchor['host']:
                continue
            delta = int(row['timestamp_ns']) - int(anchor['timestamp_ns'])
            if not -before_ns <= delta <= after_ns:
                continue
            nodes = {anchor['src'], anchor['dst']}
            if row.get('src') not in nodes and row.get('dst') not in nodes:
                continue
            item = (-abs(delta), row['event_id'], _view(row))
            heapq.heappush(heaps[event_id], item)
            if len(heaps[event_id]) > max_per_anchor:
                heapq.heappop(heaps[event_id])

    return {
        'protocol': 'sparse-local-critical-review-packet-v1',
        'ledger': str(ledger.resolve()), 'ledger_sha256': sha256_file(ledger),
        'candidate_edges': count,
        'selection_uses_detector_decisions': False,
        'bounds': {'before_ns': before_ns, 'after_ns': after_ns,
                   'max_per_anchor': max_per_anchor},
        'anchors': [{
            'stage': spec['stage'], 'pdf_page': spec.get('pdf_page'),
            'event': found[spec['event_id']],
            'neighbors': [item[2] for item in sorted(
                heaps[spec['event_id']], key=lambda item: (-item[0], item[1]))],
        } for spec in anchors],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--before-seconds', type=float, default=30)
    parser.add_argument('--after-seconds', type=float, default=30)
    parser.add_argument('--max-per-anchor', type=int, default=40)
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding='utf-8'))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for case in config['cases']:
        packet = build_case_packet(
            Path(case['optimized_ledger']), case['anchors'],
            before_ns=round(args.before_seconds * 1e9),
            after_ns=round(args.after_seconds * 1e9),
            max_per_anchor=args.max_per_anchor,
        )
        packet['name'] = case['name']
        slug = re.sub(r'[^a-z0-9]+', '-', case['name'].casefold()).strip('-')
        output = args.output_dir / f'{slug}.json'
        output.write_text(json.dumps(packet, indent=2) + '\n', encoding='utf-8')
        print(case['name'], packet['candidate_edges'],
              [len(anchor['neighbors']) for anchor in packet['anchors']], output)


if __name__ == '__main__':
    main()
