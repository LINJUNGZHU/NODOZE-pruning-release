"""Offline-only known-positive accounting for detector seed benchmark runs."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .detectors.alert_evidence import load_evidence_jsonl
from .detector_seed_benchmark import _atomic_bytes, _canonical, _sha256_bytes
from .seed_utility_evaluation import CandidateStageIds, evaluate_coverage_funnel, partial_positive_metrics
from .store import ProvenanceStore


def _read_event_ids(path: Path) -> frozenset[str]:
    if not path.is_file():
        return frozenset()
    return frozenset(str(json.loads(line)["raw_event_id"]) for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


def _write(path: Path, value: dict[str, Any]) -> None:
    unsigned = dict(value)
    unsigned["content_sha256"] = _sha256_bytes(_canonical(unsigned))
    _atomic_bytes(path, _canonical(unsigned))


def evaluate_offline_benchmark(run_root: str | Path, *, known_critical_event_ids: Iterable[str], known_attack_node_ids: Iterable[str]) -> dict[str, Any]:
    """Attach partial-positive funnel results after the online run is immutable."""
    known_edges, known_nodes = frozenset(known_critical_event_ids), frozenset(known_attack_node_ids)
    root = Path(run_root)
    output: dict[str, Any] = {"status": "COMPLETED", "runs": {}}
    for directory in sorted(path for path in root.iterdir() if path.is_dir()):
        evidence = load_evidence_jsonl(directory / "evidence.jsonl")
        candidate = _read_event_ids(directory / "candidate_raw_events.jsonl")
        a_rasp = frozenset(json.loads((directory / "A_rasp_final.json").read_text())["selected_raw_event_ids"])
        branch = frozenset(json.loads((directory / "C_branch_fair_final.json").read_text())["selected_raw_event_ids"])
        evidence_ids = frozenset(event for item in evidence for event in item.event_ids)
        resolved = json.loads((directory / "resolved_config.json").read_text(encoding="utf-8"))
        with ProvenanceStore(resolved["database_path"]) as store:
            raw_database = frozenset(event for event in known_edges if store.get_edge_by_event_id(event) is not None)
        # Adapter-normalized records are the actual inference identity boundary:
        # node-only artifacts do not fabricate an event-level scored identity.
        stages = CandidateStageIds(raw_database, evidence_ids, evidence_ids, evidence_ids,
            frozenset(event for item in evidence if item.native_decision for event in item.event_ids), evidence_ids, candidate, a_rasp)
        payload = {"schema_version": "detector-seed-benchmark-offline-evaluation-v1", "status": "COMPLETED",
                   "candidate": partial_positive_metrics(candidate, known_edges), "A_rasp_final": partial_positive_metrics(a_rasp, known_edges),
                   "C_branch_fair_final": partial_positive_metrics(branch, known_edges),
                   "known_attack_node_count": len(known_nodes),
                   "funnel": evaluate_coverage_funnel(known_critical_event_ids=known_edges, stages=stages),
                   "funnel_identity_note": "node-only evidence has no fabricated event-level inference identity"}
        _write(directory / "evaluation.json", payload)
        output["runs"][directory.name] = {"status": "COMPLETED"}
    return output


__all__ = ["evaluate_offline_benchmark"]
