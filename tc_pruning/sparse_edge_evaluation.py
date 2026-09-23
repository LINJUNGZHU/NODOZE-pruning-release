"""Strict event-wise evaluation for SPARSE-style dependency graphs.

Unreviewed events are unknown unless a reference certifies complete event labels
for the exact candidate ledger. A node list cannot provide that certification.
"""

from __future__ import annotations

import gzip
import hashlib
import json
from contextlib import ExitStack
from pathlib import Path


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def evaluate_ledger(
    ledger_path: str | Path,
    reference_path: str | Path,
    budget_key: str,
    *,
    decision_path: str | Path | None = None,
    decision_key: str | None = None,
) -> dict:
    """Evaluate frozen decisions, withholding FP/FN until labels are exhaustive.

    ``metadata.exhaustive_event_labels`` must be the literal boolean ``true``
    and ``metadata.candidate_ledger_sha256`` must bind the exact ledger bytes.
    """
    ledger_path, reference_path = Path(ledger_path), Path(reference_path)
    if (decision_path is None) != (decision_key is None):
        raise ValueError('decision_path and decision_key must be supplied together')
    decision_path = Path(decision_path) if decision_path is not None else None
    reference = json.loads(reference_path.read_text(encoding='utf-8'))
    positives_raw = reference.get('attack_event_ids')
    if not isinstance(positives_raw, list) or not all(isinstance(x, str) and x for x in positives_raw):
        raise ValueError('reference attack_event_ids must be a list of event IDs')
    positives = set(positives_raw)
    if len(positives) != len(positives_raw):
        raise ValueError('duplicate reference event ID')
    poi_raw = reference.get('poi_event_ids', [])
    if not isinstance(poi_raw, list) or not all(isinstance(x, str) and x for x in poi_raw):
        raise ValueError('poi_event_ids must be a list of event IDs')
    poi_ids = set(poi_raw)
    if len(poi_ids) != len(poi_raw) or not poi_ids <= positives:
        raise ValueError('POI IDs must be unique known positive events')
    metadata = reference.get('metadata') or {}
    complete = metadata.get('exhaustive_event_labels') is True
    ledger_sha256 = sha256_file(ledger_path)
    if complete and metadata.get('candidate_ledger_sha256') != ledger_sha256:
        raise ValueError('exhaustive reference candidate ledger hash mismatch')

    seen: set[str] = set()
    output_edges = known_hits = poi_hits = unreviewed_selected = 0
    def open_text(path):
        opener = gzip.open if path.suffix.lower() == '.gz' else open
        return opener(path, 'rt', encoding='utf-8')

    with ExitStack() as stack:
        stream = stack.enter_context(open_text(ledger_path))
        alternative = stack.enter_context(open_text(decision_path)) if decision_path else None
        for line_number, line in enumerate(stream, start=1):
            row = json.loads(line)
            event_id = row.get('event_id')
            if not isinstance(event_id, str) or not event_id:
                raise ValueError(f'missing event ID at ledger line {line_number}')
            if event_id in seen:
                raise ValueError(f'duplicate candidate event ID: {event_id}')
            seen.add(event_id)
            if alternative:
                alt_line = alternative.readline()
                if not alt_line:
                    raise ValueError('alternative decision identity set is shorter than candidate ledger')
                alt_row = json.loads(alt_line)
                if alt_row.get('event_id') != event_id:
                    raise ValueError(f'alternative decision identity mismatch at line {line_number}')
                alt_decisions = alt_row.get('decisions')
                if not isinstance(alt_decisions, dict):
                    raise ValueError(f'alternative decisions must be an object for {event_id}')
                kept = alt_decisions.get(decision_key)
                if type(kept) is not bool:
                    raise ValueError(f'missing boolean alternative budget decision for {event_id}')
            else:
                decision_rows = row.get('decisions')
                if not isinstance(decision_rows, list) or not all(isinstance(d, dict) for d in decision_rows):
                    raise ValueError(f'ledger decisions must be a list of objects for {event_id}')
                decisions = [d for d in decision_rows if d.get('budget_key') == budget_key]
                if len(decisions) != 1 or type(decisions[0].get('kept')) is not bool:
                    raise ValueError(f'expected one boolean budget decision for {event_id}')
                kept = decisions[0]['kept']
            if kept:
                output_edges += 1
                if event_id in positives:
                    known_hits += 1
                    if event_id in poi_ids:
                        poi_hits += 1
                else:
                    unreviewed_selected += 1
        if alternative and alternative.readline():
            raise ValueError('alternative decision identity set is longer than candidate ledger')

    missing = positives - seen
    if missing and complete:
        raise ValueError(f'reference event outside candidate universe: {sorted(missing)[:3]}')
    known_misses = len(positives) - known_hits
    non_poi_count = len(positives) - len(poi_ids)
    non_poi_hits = known_hits - poi_hits
    result = {
        'ledger_sha256': ledger_sha256,
        'reference_sha256': sha256_file(reference_path),
        'decision_sha256': sha256_file(decision_path) if decision_path else ledger_sha256,
        'decision_key': decision_key if decision_path else budget_key,
        'budget_key': budget_key,
        'reference_complete': complete,
        'candidate_edges': len(seen),
        'output_edges': output_edges,
        'known_positive_edges': len(positives),
        'known_positive_outside_candidate': len(missing),
        'candidate_positive_coverage': (len(positives) - len(missing)) / len(positives) if positives else None,
        'known_positive_hits': known_hits,
        'known_positive_misses': known_misses,
        'observed_positive_recall': known_hits / len(positives) if positives else None,
        'poi_positive_edges': len(poi_ids),
        'non_poi_positive_edges': non_poi_count,
        'non_poi_positive_hits': non_poi_hits,
        'non_poi_observed_recall': non_poi_hits / non_poi_count if non_poi_count else None,
        'unreviewed_selected_edges': unreviewed_selected if not complete else 0,
        'tp': None, 'fp': None, 'fn': None, 'tn': None,
        'precision': None, 'recall': None, 'f1': None,
        'paper_fpr': None, 'standard_fpr': None,
    }
    if complete:
        tp, fp, fn = known_hits, unreviewed_selected, known_misses
        tn = len(seen) - tp - fp - fn
        precision = tp / output_edges if output_edges else 0.0
        recall = tp / len(positives) if positives else None
        result.update({
            'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
            'precision': precision, 'recall': recall,
            'f1': 2 * precision * recall / (precision + recall) if recall is not None and precision + recall else 0.0,
            'paper_fpr': fp / len(seen) if seen else None,
            'standard_fpr': fp / (fp + tn) if fp + tn else None,
        })
    return result
