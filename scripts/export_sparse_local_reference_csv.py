"""Export the explicitly local, closed-world edge-proxy performance table."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def export_table(results: dict, output: Path) -> None:
    columns = [
        'case', 'method', 'candidate_edges', 'output_edges',
        'proxy_tp', 'proxy_fp', 'proxy_fn', 'proxy_tn',
        'proxy_precision_pct', 'proxy_recall_pct', 'proxy_f1_pct',
        'proxy_fpr_pct', 'proxy_fnr_pct',
        'critical_groups_hit', 'critical_groups_total',
        'attack_stages_hit', 'attack_stages_total',
        'sparse_equivalent_fp', 'sparse_equivalent_fn',
        'sparse_equivalent_precision', 'sparse_equivalent_recall',
        'sparse_equivalent_f1',
    ]
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, lineterminator='\n')
        writer.writeheader()
        for case in results['cases']:
            for method in ('baseline', 'optimized'):
                metrics = case[method]
                row = {'case': case['name'], 'method': method}
                for key in ('candidate_edges', 'output_edges', 'proxy_tp', 'proxy_fp',
                            'proxy_fn', 'proxy_tn', 'critical_groups_hit',
                            'critical_groups_total', 'attack_stages_hit',
                            'attack_stages_total'):
                    row[key] = metrics[key]
                for key in ('precision', 'recall', 'f1', 'fpr', 'fnr'):
                    value = metrics[f'proxy_{key}']
                    row[f'proxy_{key}_pct'] = 'NA' if value is None else f'{100 * value:.6f}'
                for key in ('fp', 'fn', 'precision', 'recall', 'f1'):
                    if metrics['official_equivalent_metrics'][key] is not None:
                        raise ValueError('official-equivalent metrics must stay unavailable')
                    row[f'sparse_equivalent_{key}'] = 'NA'
                writer.writerow(row)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    export_table(json.loads(args.results.read_text(encoding='utf-8')), args.output)


if __name__ == '__main__':
    main()
