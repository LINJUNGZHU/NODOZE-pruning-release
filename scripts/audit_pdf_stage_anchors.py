"""Check report-confirmed representative events in frozen candidate and output graphs.

The PDF supplies attack steps, not exhaustive event labels. This audit reports
presence of one manually resolved CDM event per stated stage; it never turns
unlisted edges into false positives or claims SPARSE-equivalent recall.
"""

from __future__ import annotations

import argparse
import gzip
import json
from itertools import zip_longest
from pathlib import Path

from tc_pruning.sparse_edge_evaluation import sha256_file


def _open_text(path: Path):
    return gzip.open(path, 'rt', encoding='utf-8') if path.suffix == '.gz' else path.open(encoding='utf-8')


def _check_anchor(row: dict, anchor: dict) -> None:
    event_id = row['event_id']
    if row.get('relation') != anchor['expected_relation']:
        raise ValueError(f'PDF anchor relation mismatch: {event_id}')
    semantics = ' '.join(str(row.get(k) or '') for k in ('src_semantic', 'dst_semantic'))
    if anchor['expected_semantic_contains'].casefold() not in semantics.casefold():
        raise ValueError(f'PDF anchor semantic mismatch: {event_id}')


def _baseline_hits(ledger: Path, anchors: dict[str, dict], budget_key: str) -> dict[str, bool]:
    found = {}
    with _open_text(ledger) as stream:
        for line in stream:
            row = json.loads(line)
            event_id = row['event_id']
            if event_id not in anchors:
                continue
            if event_id in found:
                raise ValueError(f'duplicate PDF anchor in baseline ledger: {event_id}')
            _check_anchor(row, anchors[event_id])
            decisions = [d for d in row['decisions'] if d.get('budget_key') == budget_key]
            if len(decisions) != 1 or type(decisions[0].get('kept')) is not bool:
                raise ValueError(f'invalid baseline decision for {event_id}')
            found[event_id] = decisions[0]['kept']
    return found


def _optimized_hits(ledger: Path, decisions: Path, anchors: dict[str, dict],
                    decision_key: str) -> dict[str, dict]:
    found = {}
    with _open_text(ledger) as candidate_stream, _open_text(decisions) as optimized_stream:
        for line_number, (candidate_line, optimized_line) in enumerate(
            zip_longest(candidate_stream, optimized_stream), start=1
        ):
            if candidate_line is None or optimized_line is None:
                raise ValueError('candidate/decision length mismatch')
            candidate = json.loads(candidate_line)
            decision = json.loads(optimized_line)
            event_id = candidate['event_id']
            if decision.get('event_id') != event_id:
                raise ValueError(f'candidate/decision identity mismatch at line {line_number}')
            if event_id not in anchors:
                continue
            if event_id in found:
                raise ValueError(f'duplicate PDF anchor in optimized ledger: {event_id}')
            _check_anchor(candidate, anchors[event_id])
            kept = decision.get('decisions', {}).get(decision_key)
            if type(kept) is not bool:
                raise ValueError(f'invalid optimized decision for {event_id}')
            found[event_id] = {
                'kept': kept, 'relation': candidate['relation'],
                'host': candidate.get('host'),
                'timestamp_ns': candidate.get('timestamp_ns'),
                'src_semantic': candidate.get('src_semantic'),
                'dst_semantic': candidate.get('dst_semantic'),
            }
    return found


def audit(config_path: Path) -> dict:
    config = json.loads(config_path.read_text(encoding='utf-8'))
    pdf = Path(config['pdf'])
    actual_pdf_hash = sha256_file(pdf)
    if actual_pdf_hash != config['pdf_sha256']:
        raise ValueError('PDF content hash differs from the audited source')
    cases = []
    for case in config['cases']:
        baseline_ledger = Path(case['baseline_ledger'])
        optimized_ledger = Path(case['optimized_ledger'])
        decisions = Path(case['optimized_decision_path'])
        anchor_ids = [a['event_id'] for a in case['anchors']]
        if len(anchor_ids) != len(set(anchor_ids)):
            raise ValueError(f"duplicate stage anchor in {case['name']}")
        anchors = {a['event_id']: a for a in case['anchors']}
        baseline = _baseline_hits(baseline_ledger, anchors, case['baseline_budget_key'])
        optimized = _optimized_hits(optimized_ledger, decisions, anchors,
                                    case['optimized_decision_key'])
        ordered = []
        for anchor in case['anchors']:
            event_id = anchor['event_id']
            matched = optimized.get(event_id, {})
            ordered.append({
                'stage': anchor['stage'], 'event_id': event_id,
                'pdf_page': anchor['pdf_page'], 'relation': matched.get('relation'),
                'host': matched.get('host'),
                'timestamp_ns': matched.get('timestamp_ns'),
                'src_semantic': matched.get('src_semantic'),
                'dst_semantic': matched.get('dst_semantic'),
                'baseline_candidate': event_id in baseline,
                'baseline_kept': baseline.get(event_id, False),
                'optimized_candidate': event_id in optimized,
                'optimized_kept': matched.get('kept', False),
            })
        cases.append({
            'name': case['name'], 'anchor_count': len(ordered),
            'baseline_candidate_anchor_hits': sum(a['baseline_candidate'] for a in ordered),
            'optimized_candidate_anchor_hits': sum(a['optimized_candidate'] for a in ordered),
            'baseline_anchor_hits': sum(a['baseline_kept'] for a in ordered),
            'optimized_anchor_hits': sum(a['optimized_kept'] for a in ordered),
            'baseline_ledger_sha256': sha256_file(baseline_ledger),
            'optimized_ledger_sha256': sha256_file(optimized_ledger),
            'optimized_decision_sha256': sha256_file(decisions),
            'anchors': ordered,
        })
    return {
        'protocol': config['protocol'], 'pdf_sha256': actual_pdf_hash,
        'config_sha256': sha256_file(config_path),
        'label_scope': config['label_scope'], 'cases': cases,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.config)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    for case in result['cases']:
        print(case['name'], f"baseline {case['baseline_anchor_hits']}/{case['anchor_count']}",
              f"optimized {case['optimized_anchor_hits']}/{case['anchor_count']}")


if __name__ == '__main__':
    main()
