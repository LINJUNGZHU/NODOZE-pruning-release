"""Audit frozen NODOZE event selections for the five cases in SPARSE Table V."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tc_pruning.sparse_edge_evaluation import evaluate_ledger, sha256_file


CASE_NAMES = (
    'Five Dir Case 1',
    'Five Dir Case 3',
    'Theia Case 1',
    'Theia Case 3',
    'Theia Case 5',
)


def _paths(case: dict):
    for key in ('official_report', 'poi_manifest', 'node_groundtruth', 'ledger', 'reference',
                'ingested_database', 'frequency_baseline_database'):
        value = case.get(key)
        if value:
            yield key, value
    for value in case.get('raw_logs', []):
        yield 'raw_logs', value
    for value in case.get('frequency_baseline_logs', []):
        yield 'frequency_baseline_logs', value


def audit_inventory(inventory_path: str | Path) -> dict:
    inventory_path = Path(inventory_path)
    inventory = json.loads(inventory_path.read_text(encoding='utf-8'))
    cases = inventory.get('cases')
    if not isinstance(cases, list) or [case.get('name') for case in cases] != list(CASE_NAMES):
        raise ValueError('inventory must contain exactly the five target cases in fixed order')
    result = {'inventory_sha256': sha256_file(inventory_path), 'cases': []}
    for case in cases:
        sources = {}
        for key, raw_path in _paths(case):
            if (case['name'] == 'Theia Case 5' and 'trace' in str(raw_path).lower()
                    and case.get('paper_case_identity') != 'inferred_trace_case5'):
                raise ValueError('Theia Case 5 cannot silently use TRACE inputs')
            path = Path(raw_path)
            if not path.is_absolute():
                path = inventory_path.parent / path
            sources.setdefault(key, []).append({
                'path': str(path), 'exists': path.is_file(),
                'bytes': path.stat().st_size if path.is_file() else None,
            })
        entry = {
            'name': case['name'],
            'status': 'unavailable',
            'reason': case.get('reason') or 'no frozen ledger and matching reference',
            'poi_source_kind': case.get('poi_source_kind'),
            'paper_case_identity': case.get('paper_case_identity', 'mapped_inference'),
            'label_scope': case.get('label_scope'),
            'sources': sources,
            'metrics': None,
        }
        if case.get('ledger') and case.get('reference'):
            ledger = sources['ledger'][0]
            reference = sources['reference'][0]
            if ledger['exists'] and reference['exists']:
                try:
                    entry['metrics'] = evaluate_ledger(ledger['path'], reference['path'], case.get('budget_key', '0.2'))
                    if case.get('paper_case_identity') == 'ambiguous_literal_theia':
                        entry['status'] = 'measured_literal_only'
                    else:
                        entry['status'] = 'measured'
                        entry['reason'] = None
                except (ValueError, OSError, json.JSONDecodeError) as exc:
                    entry['status'] = 'invalid'
                    entry['reason'] = str(exc)
        result['cases'].append(entry)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = audit_inventory(args.inventory)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps([{'name': case['name'], 'status': case['status'], 'reason': case['reason']} for case in result['cases']], indent=2))


if __name__ == '__main__':
    main()
