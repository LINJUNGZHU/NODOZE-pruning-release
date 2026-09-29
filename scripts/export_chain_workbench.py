"""Export one exact, validated v2 decision without reading offline labels.

python -m scripts.export_chain_workbench --frozen DIR --method reliability_chain \
    --budget 1024 --output NEWDIR

The budget is an integer count of original events. These raw-event artifacts
and POI role lists are local evidence, not public aggregate experiment data.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path

import numpy as np

from tc_pruning.retained_chains import build_retained_artifact, write_retained_export


def export_frozen(frozen, method, budget, output):
    from tc_pruning.chain_workbench import validate_variant

    frozen = Path(frozen)
    validation = validate_variant(frozen)
    manifest_bytes = (frozen / 'manifest.json').read_bytes()
    manifest = json.loads(manifest_bytes)
    if type(budget) is not int or budget < 1:
        raise ValueError('budget must be an integer count of original events')
    if not isinstance(method, str) or method not in manifest['methods'] or budget not in manifest['budgets']:
        raise ValueError('requested exact method/integer budget was not frozen')
    key = f'{method}@{budget}'
    with gzip.open(frozen / 'candidates.json.gz', 'rt', encoding='utf-8') as stream:
        rows = json.load(stream)
    bundles = []
    bundle_path = frozen / 'bundles.json.gz'
    if bundle_path.exists():
        with gzip.open(bundle_path, 'rt', encoding='utf-8') as stream:
            grouped_bundles = json.load(stream)
        if not isinstance(grouped_bundles, dict):
            raise ValueError('frozen bundles must be keyed by exact method')
        bundles = grouped_bundles.get(method, [])
        if not isinstance(bundles, list):
            raise ValueError('frozen method bundles must be a list')
    with np.load(frozen / 'decisions.npz', allow_pickle=False) as values:
        selected = values[key].copy()
    with np.load(frozen / 'scores.npz', allow_pickle=False) as values:
        scores = values[method].copy()
    artifact = build_retained_artifact(rows, selected, scores,
        case_id=manifest['case_id'], method=method, budget_edges=budget, bundles=bundles)
    source_hash = hashlib.sha256(manifest_bytes).hexdigest()
    artifact['track'] = manifest['track']
    artifact['poi_policy'] = manifest['poi_policy']
    artifact['source_manifest_sha256'] = source_hash
    artifact['frozen_source'] = {
        'directory': str(frozen.resolve()), 'decision_key': key,
        'source_manifest_sha256': source_hash,
        'case_id': manifest['case_id'], 'track': manifest['track'],
        'poi_policy': manifest['poi_policy'], 'validation': validation,
        'selection_recomputed': False, 'reference_labels_read': False,
    }
    diagnostics = manifest['poi_diagnostics']
    retained = {event['event_id'] for event in artifact['events']}
    original = list(diagnostics['original_declared_event_ids'])
    suggested = list(diagnostics['suggested_event_ids'])
    artifact['poi_roles'] = {
        'original_declared_event_ids': original,
        'selected_event_ids': list(diagnostics['selected_event_ids']),
        'suggested_event_ids': suggested,
        'retained_original_declared_event_ids': [event_id for event_id in original if event_id in retained],
        'retained_suggested_event_ids': [event_id for event_id in suggested if event_id in retained],
        'suggestions_are_verified_alerts': False,
        'event_poi_flag_meaning': 'selected investigation seed in this frozen variant; may be an algorithm suggestion',
        'scope': 'original inputs and algorithm suggestions; neither asserts a complete attack or an independently verified alert',
    }
    return write_retained_export(output, artifact)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--frozen', type=Path, required=True)
    parser.add_argument('--method', required=True)
    parser.add_argument('--budget', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    manifest = export_frozen(args.frozen, args.method, args.budget, args.output)
    print(json.dumps({'output': str(args.output), 'counts': manifest['counts'],
                      'method': args.method, 'budget': args.budget}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
