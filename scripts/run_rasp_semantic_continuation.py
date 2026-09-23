"""RASP-D selection with report-POI file-write/execute continuity at a fixed cap."""

from __future__ import annotations

import argparse
import gzip
import json
from pathlib import Path

import numpy as np

from scripts.run_rasp import load_candidates
from tc_pruning.poi_semantic_continuation import (
    adjacent_file_writes, command_line_executions, executable_continuations,
    network_poi_episode, poi_bridge_continuations, file_poi_io_origin,
)
from tc_pruning.rasp import propagate, temporal_fork_routes, temporal_routes
from tc_pruning.rasp_diverse import event_families, select_diverse
from tc_pruning.sparse_edge_evaluation import sha256_file


def run(ledger: Path, output_dir: Path, ratio: float, scoring_config: Path,
        raw_cdm_json: Path | None = None, file_io_origin: bool = False) -> dict:
    if not 0 < ratio <= 1:
        raise ValueError('ratio must be in (0, 1]')
    output_dir.mkdir(parents=True, exist_ok=False)
    opener = gzip.open if ledger.suffix == '.gz' else open
    relevant = []
    with opener(ledger, 'rt', encoding='utf-8') as stream:
        for line in stream:
            row = json.loads(line)
            if row.get('relation') in (
                'EVENT_WRITE', 'EVENT_EXECUTE', 'EVENT_CONNECT', 'EVENT_SENDTO',
                'EVENT_RECVFROM', 'EVENT_READ', 'EVENT_OPEN', 'EVENT_FORK',
            ) or row.get('is_declared_poi') is True:
                relevant.append(row)
    execute_continuations = executable_continuations(relevant)
    write_continuations = adjacent_file_writes(relevant)
    network_continuations = network_poi_episode(relevant)
    bridge_continuations = poi_bridge_continuations(relevant)
    io_origin_continuations = file_poi_io_origin(relevant) if file_io_origin else set()
    raw_continuations = set()
    if raw_cdm_json is not None:
        with raw_cdm_json.open('rt', encoding='utf-8') as raw_stream:
            raw_continuations = command_line_executions(relevant, raw_stream)
    continuations = (
        execute_continuations | write_continuations | network_continuations
        | bridge_continuations | io_origin_continuations | raw_continuations
    )
    candidates = load_candidates(ledger)
    index = {event_id: i for i, event_id in enumerate(candidates['ids'])}
    raw_outside = raw_continuations - index.keys()
    continuations &= index.keys()
    score, _ = propagate(
        candidates['src'], candidates['dst'], candidates['relation'], candidates['rarity'],
        candidates['poi'], candidates['process_nodes'], json.loads(scoring_config.read_text()),
    )
    backward = temporal_routes(
        candidates['src'], candidates['dst'], candidates['timestamp'], candidates['poi'],
    )[0][0]
    parent, pivot, _, _ = temporal_fork_routes(
        candidates['src'], candidates['dst'], candidates['timestamp'], candidates['poi'], backward,
    )
    families = event_families(candidates['src'], candidates['dst'], candidates['relation'])
    cap = int(len(candidates['ids']) * ratio)
    reserve = len(continuations)
    if reserve > cap:
        raise ValueError('continuations exceed edge cap')
    mask, _, _ = select_diverse(
        score, candidates['poi'], backward, parent, pivot, families,
        cap - reserve, candidates['tie'], 0.0,
    )
    mask[np.asarray([index[event_id] for event_id in continuations], dtype=int)] = True
    if int(mask.sum()) > cap or not np.all(mask[candidates['poi']]):
        raise RuntimeError('edge cap or POI guarantee violated')
    decision_key = f'rasp_semantic@{ratio:g}'
    decision_path = output_dir / 'decisions.jsonl.gz'
    with gzip.open(decision_path, 'wt', encoding='utf-8') as stream:
        for event_id, kept in zip(candidates['ids'], mask):
            stream.write(json.dumps({'event_id': event_id, 'decisions': {decision_key: bool(kept)}}) + '\n')
    report = {
        'method': decision_key,
        'candidate_edges': len(candidates['ids']),
        'budget_edges': cap,
        'selected_edges': int(mask.sum()),
        'semantic_continuation_event_ids': sorted(continuations),
        'execute_continuation_event_ids': sorted(execute_continuations),
        'adjacent_write_event_ids': sorted(write_continuations),
        'network_episode_event_ids': sorted(network_continuations),
        'poi_bridge_event_ids': sorted(bridge_continuations),
        'file_io_origin_event_ids': sorted(io_origin_continuations),
        'raw_command_line_event_ids': sorted(raw_continuations),
        'raw_command_line_outside_candidate': sorted(raw_outside),
        'poi_uses_external_alert': False,
        'attack_labels_used_for_selection': False,
        'file_io_origin_enabled': file_io_origin,
        'policy': 'For write POIs, preserve same-file writes within one second and the first same-basename EXECUTE within one second afterward. For CONNECT POIs, preserve up to eight most recent same-process CONNECT events in the preceding ten minutes and the first same-socket SENDTO within one second afterward. When CONNECT and WRITE POIs occur on one host within ten minutes, preserve up to eight same-socket RECVFROM events and bounded READ/OPEN edges joining their processes through a shared file UUID; the OPEN process may be one nearby FORK child of the CONNECT process, with its FORK edge preserved. Optional file IO origin keeps one nearby parent FORK and up to 80 READ/RECVFROM events on the highest-volume socket of the file-writing process or its parent. If raw CDM is supplied, preserve up to two same-host EXECUTEs with the POI file basename in their cmdLine within one minute. Reserve budget slots before RASP-D q=0 selection.',
        'ledger_sha256': sha256_file(ledger),
        'decision_sha256': sha256_file(decision_path),
        'scoring_config_sha256': sha256_file(scoring_config),
        'raw_cdm_json': str(raw_cdm_json.resolve()) if raw_cdm_json else None,
        'raw_cdm_sha256': sha256_file(raw_cdm_json) if raw_cdm_json else None,
        'implementation_sha256': {
            path: sha256_file(Path(path)) for path in (
                'scripts/run_rasp_semantic_continuation.py',
                'scripts/run_rasp.py',
                'tc_pruning/poi_semantic_continuation.py',
                'tc_pruning/rasp.py',
                'tc_pruning/rasp_diverse.py',
            )
        },
    }
    (output_dir / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ledger', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--ratio', type=float, default=0.2)
    parser.add_argument('--scoring-config', type=Path, default=Path('configs/rasp_v1.json'))
    parser.add_argument('--raw-cdm-json', type=Path)
    parser.add_argument('--file-io-origin', action='store_true')
    args = parser.parse_args()
    print(json.dumps(run(args.ledger, args.output_dir, args.ratio, args.scoring_config,
                         args.raw_cdm_json, args.file_io_origin), indent=2))


if __name__ == '__main__':
    main()
