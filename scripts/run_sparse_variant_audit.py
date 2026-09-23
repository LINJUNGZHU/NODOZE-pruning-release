"""Recount frozen alternative decisions against explicitly scoped event labels."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tc_pruning.sparse_edge_evaluation import evaluate_ledger, sha256_file


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--variants', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.variants.read_text())
    names = [variant['name'] for variant in config['variants']]
    if len(names) != len(set(names)):
        raise ValueError('duplicate variant name')
    rows = []
    for variant in config['variants']:
        paths = {}
        for key in ('ledger', 'reference', 'decision_path'):
            path = Path(variant[key])
            paths[key] = path if path.is_absolute() else args.variants.parent / path
        metrics = evaluate_ledger(
            paths['ledger'], paths['reference'], variant['budget_key'],
            decision_path=paths['decision_path'], decision_key=variant['decision_key'],
        )
        rows.append({'name': variant['name'], 'metrics': metrics,
                     'sources': {key: str(path.resolve()) for key, path in paths.items()}})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({
        'protocol': config['protocol'], 'variants_sha256': sha256_file(args.variants),
        'rows': rows,
    }, indent=2) + '\n')
    for row in rows:
        m = row['metrics']
        print(row['name'], m['output_edges'], m['known_positive_hits'], m['known_positive_edges'],
              m['non_poi_positive_hits'], m['non_poi_positive_edges'])


if __name__ == '__main__':
    main()
