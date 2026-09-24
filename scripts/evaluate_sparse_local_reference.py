"""Evaluate frozen NODOZE decisions against the explicit *local proxy* edge set.

The proxy assumes all candidate edges outside the analyst-selected parallel
groups are noncritical. It cannot be reported as SPARSE's unpublished truth.
"""

from __future__ import annotations

import argparse
import gzip
import json
from contextlib import ExitStack
from pathlib import Path

from tc_pruning.sparse_edge_evaluation import sha256_file


def _open_text(path: Path):
    return gzip.open(path, 'rt', encoding='utf-8') if path.suffix == '.gz' else path.open(encoding='utf-8')


def evaluate_case(
    ledger: Path, reference: dict, *, budget_key: str,
    decision_path: Path | None = None, decision_key: str | None = None,
) -> dict:
    """Calculate a closed-world proxy confusion matrix on one candidate ledger."""
    if (decision_path is None) != (decision_key is None):
        raise ValueError('decision path and key must be supplied together')
    positives = set(reference['critical_event_ids'])
    if len(positives) != len(reference['critical_event_ids']):
        raise ValueError('duplicate critical event ID')
    uncertain = set(reference.get('uncertain_event_ids', []))
    if positives & uncertain:
        raise ValueError('critical and uncertain IDs overlap')
    seen = set()
    selected_positives = set()
    output_edges = selected_uncertain = proxy_fp = 0
    with ExitStack() as stack:
        candidate_stream = stack.enter_context(_open_text(ledger))
        decision_stream = stack.enter_context(_open_text(decision_path)) if decision_path else None
        for line_number, line in enumerate(candidate_stream, start=1):
            row = json.loads(line)
            event_id = row['event_id']
            if event_id in seen:
                raise ValueError(f'duplicate candidate event ID: {event_id}')
            seen.add(event_id)
            if decision_stream:
                decision_line = decision_stream.readline()
                if not decision_line:
                    raise ValueError('decision/candidate length mismatch')
                decision = json.loads(decision_line)
                if decision.get('event_id') != event_id:
                    raise ValueError(f'decision identity mismatch at line {line_number}')
                kept = decision.get('decisions', {}).get(decision_key)
            else:
                matches = [d for d in row['decisions'] if d.get('budget_key') == budget_key]
                if len(matches) != 1:
                    raise ValueError(f'ambiguous baseline decision for {event_id}')
                kept = matches[0].get('kept')
            if type(kept) is not bool:
                raise ValueError(f'missing boolean decision for {event_id}')
            if not kept:
                continue
            output_edges += 1
            if event_id in positives:
                selected_positives.add(event_id)
            elif event_id in uncertain:
                selected_uncertain += 1
            else:
                proxy_fp += 1
        if decision_stream and decision_stream.readline():
            raise ValueError('decision/candidate length mismatch')

    proxy_tp = len(selected_positives)
    proxy_fn = len(positives) - proxy_tp
    candidate_positives = len(positives & seen)
    candidate_uncertain = len(uncertain & seen)
    proxy_tn = len(seen) - candidate_positives - candidate_uncertain - proxy_fp
    if proxy_tn < 0:
        raise ValueError('negative proxy TN: reference/decision mismatch')
    precision = proxy_tp / (proxy_tp + proxy_fp) if proxy_tp + proxy_fp else None
    recall = proxy_tp / len(positives) if positives else None
    f1 = 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else None
    groups_hit = [bool(selected_positives.intersection(row['parallel_event_ids']))
                  for row in reference['exemplars']]
    stages = {}
    for row, hit in zip(reference['exemplars'], groups_hit):
        stages[row['stage']] = stages.get(row['stage'], False) or hit
    return {
        'ledger_sha256': sha256_file(ledger),
        'decision_sha256': sha256_file(decision_path) if decision_path else sha256_file(ledger),
        'decision_key': decision_key if decision_path else budget_key,
        'candidate_edges': len(seen), 'output_edges': output_edges,
        'reference_critical_events': len(positives),
        'reference_outside_candidate': len(positives - seen),
        'proxy_tp': proxy_tp, 'proxy_fp': proxy_fp, 'proxy_fn': proxy_fn,
        'proxy_tn': proxy_tn,
        'proxy_precision': precision, 'proxy_recall': recall, 'proxy_f1': f1,
        'proxy_fpr': proxy_fp / (proxy_fp + proxy_tn) if proxy_fp + proxy_tn else None,
        'proxy_fnr': proxy_fn / (proxy_fn + proxy_tp) if proxy_fn + proxy_tp else None,
        'proxy_fp_per_candidate': proxy_fp / len(seen) if seen else None,
        'selected_uncertain_edges': selected_uncertain,
        'critical_groups_hit': sum(groups_hit),
        'critical_groups_total': len(groups_hit),
        'attack_stages_hit': sum(stages.values()),
        'attack_stages_total': len(stages),
        'official_equivalent_metrics': {
            'fp': None, 'fn': None, 'precision': None, 'recall': None, 'f1': None,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--choices', type=Path, required=True)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--variants', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    reference = json.loads(args.reference.read_text(encoding='utf-8'))
    if reference['choices_sha256'] != sha256_file(args.choices):
        raise ValueError('frozen local choices have changed')
    inventory = json.loads(args.inventory.read_text(encoding='utf-8'))
    variants = json.loads(args.variants.read_text(encoding='utf-8'))
    if not len(reference['cases']) == len(inventory['cases']) == len(variants['variants']):
        raise ValueError('five-case configuration lengths differ')
    cases = []
    for case, baseline, optimized in zip(
        reference['cases'], inventory['cases'], variants['variants']
    ):
        name = case['name']
        if baseline['name'] != name or not optimized['name'].startswith(name):
            raise ValueError(f'case order/name mismatch: {name}')
        if case['ledger_sha256'] != sha256_file(Path(optimized['ledger'])):
            raise ValueError(f'frozen reference ledger differs for {name}')
        comparison_ledger = Path(optimized.get('comparison_baseline_ledger', baseline['ledger']))
        if case['ledger_sha256'] != sha256_file(comparison_ledger):
            raise ValueError(f'comparison baseline ledger differs from frozen reference for {name}')
        baseline_metrics = evaluate_case(
            comparison_ledger, case, budget_key=baseline['budget_key'],
        )
        optimized_metrics = evaluate_case(
            Path(optimized['ledger']), case, budget_key=optimized['budget_key'],
            decision_path=Path(optimized['decision_path']),
            decision_key=optimized['decision_key'],
        )
        case_result = {'name': name, 'baseline': baseline_metrics,
                       'optimized': optimized_metrics}
        if comparison_ledger != Path(baseline['ledger']):
            case_result['one_poi_ablation'] = evaluate_case(
                Path(baseline['ledger']), case, budget_key=baseline['budget_key'],
            )
        cases.append(case_result)
        print(name, f"baseline {baseline_metrics['proxy_tp']}/{baseline_metrics['reference_critical_events']}",
              f"optimized {optimized_metrics['proxy_tp']}/{optimized_metrics['reference_critical_events']}")
    output = {
        'protocol': 'sparse-local-critical-proxy-evaluation-v1',
        'reference_sha256': sha256_file(args.reference),
        'choices_sha256': reference['choices_sha256'],
        'label_status': 'analyst-curated local operational proxy; not SPARSE ground truth',
        'cases': cases,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
