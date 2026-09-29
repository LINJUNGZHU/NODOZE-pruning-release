"""Export a validated frozen adaptive decision without opening reference labels.

python -m scripts.export_retained_chains --frozen DIR --method adaptive \
    --budget 0.2 --output NEWDIR
Exports are local raw-event artifacts and must not be added to public Git data.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import math
from pathlib import Path

import numpy as np

from tc_pruning.retained_chains import build_retained_artifact, write_retained_export


def export_frozen(frozen, method, budget, output, *, case_id=None):
    # Import only the validator. No offline annotation/evaluation entry point
    # or reference file is needed to export a previously selected event mask.
    from scripts.run_adaptive_chains import validate_frozen
    frozen = Path(frozen)
    validation = validate_frozen(frozen)
    ratio = float(budget)
    if not math.isfinite(ratio) or not 0 < ratio <= 1:
        raise ValueError('budget ratio must be finite and in (0, 1]')
    manifest = json.loads((frozen / 'manifest.json').read_text())
    if method not in manifest['config']['methods'] or ratio not in manifest['config']['budgets']:
        raise ValueError('requested method/budget was not frozen')
    key = f'{method}@{ratio!r}'
    with gzip.open(frozen / 'candidate-inputs.json.gz', 'rt', encoding='utf-8') as stream:
        rows = json.load(stream)
    with gzip.open(frozen / 'bundles.json.gz', 'rt', encoding='utf-8') as stream:
        bundles = json.load(stream).get(method, [])
    with np.load(frozen / 'decisions.npz', allow_pickle=False) as values:
        selected = values[key].copy()
    with np.load(frozen / 'scores.npz', allow_pickle=False) as values:
        scores = values[method].copy()
    artifact = build_retained_artifact(rows, selected, scores,
        case_id=case_id or frozen.name, method=method,
        budget_edges=manifest['diagnostics'][key]['budget_edges'], bundles=bundles)
    artifact['frozen_source'] = {
        'directory': str(frozen.resolve()), 'decision_key': key,
        'manifest_sha256': hashlib.sha256((frozen / 'manifest.json').read_bytes()).hexdigest(),
        'candidate_sha256': manifest['candidate_sha256'], 'input_sha256': manifest['input_sha256'],
        'validation': validation,
    }
    return write_retained_export(output, artifact)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--frozen', type=Path, required=True)
    parser.add_argument('--method', required=True)
    parser.add_argument('--budget', type=float, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case-id')
    args = parser.parse_args(argv)
    manifest = export_frozen(args.frozen, args.method, args.budget, args.output, case_id=args.case_id)
    print(json.dumps({'output': str(args.output), 'counts': manifest['counts'],
                      'method': args.method, 'budget': args.budget}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
