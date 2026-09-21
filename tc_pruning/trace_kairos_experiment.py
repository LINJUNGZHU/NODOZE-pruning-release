"""TRACE E3 pruning experiment driven by sealed, detector-native KAIROS POIs."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from typing import Any, Iterable, Mapping

from .benchmark_contract import EdgeProjection
from .detector_seed_benchmark import _a_rasp, _causal
from .detectors.alert_evidence import AlertEvidence, EvidenceGranularity, MappingQuality, RoleHint
from .evidence_candidate_builder import CandidateSearchConfig, EvidenceDrivenCandidateBuilder
from .frequency import FrequencyModel
from .kairos_poi_experiment import _path_record, select_poi_proxies
from .pbr_experiment import a_rasp_evidence, branch_fair_checkpoints, pbr_sweep
from .store import ProvenanceStore


_OFFLINE_WORDS = ("orthrus", "groundtruth", "ground_truth", "attack_node")


def _sha(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode()).hexdigest()


def _atomic(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"), allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def scenario_scope(detector_pois: Iterable[str], attack_nodes: Iterable[str]) -> dict[str, Any]:
    detector = {str(node).casefold() for node in detector_pois}
    attack = {str(node).casefold() for node in attack_nodes}
    hits = sorted(detector & attack)
    return {
        "status": "ELIGIBLE" if hits else "NO_ATTACK_POI_HIT",
        "detector_poi_count": len(detector),
        "attack_node_count": len(attack),
        "attack_poi_node_ids": hits,
    }


def scenario_scope_for_record(
    record: Mapping[str, Any], attack_nodes: Iterable[str],
) -> dict[str, Any]:
    """Scope by sealed detector POIs and report candidate admission separately."""
    attack = {str(node).casefold() for node in attack_nodes}
    scope = scenario_scope(record["poi_node_ids"], attack)
    candidate = {str(node).casefold() for node in record["candidate_poi_node_ids"]}
    candidate_hits = sorted(candidate & attack)
    detector_hits = scope["attack_poi_node_ids"]
    scope.update({
        "candidate_detector_poi_count": len(candidate),
        "candidate_attack_poi_node_ids": candidate_hits,
        "attack_poi_candidate_recall": (
            len(candidate_hits) / len(detector_hits) if detector_hits else None
        ),
    })
    return scope


def validate_online_record(record: Mapping[str, Any]) -> None:
    rendered = json.dumps(record, sort_keys=True).casefold()
    if any(word in rendered for word in _OFFLINE_WORDS):
        raise ValueError("online record contains an offline dependency")
    candidate = str(record["candidate_sha256"])
    if len(candidate) != 64:
        raise ValueError("invalid shared candidate hash")
    for method in record["methods"].values():
        if method["candidate_sha256"] != candidate:
            raise ValueError("methods do not share one candidate envelope")


def _evidence(
    day: str, pois: Iterable[str], lower: int, upper: int, *,
    observations: Iterable[Mapping[str, Any]] | None = None,
) -> tuple[AlertEvidence, ...]:
    observed = tuple(observations or ())
    if observed:
        return tuple(AlertEvidence(
            evidence_id=f"KAIROS:TRACE_E3:{day}:{row['queue_id']}:{row['window']}",
            detector_id="KAIROS", detector_version="PIDSMaker",
            granularity=EvidenceGranularity.NODE, raw_score=None,
            calibrated_score=1.0, native_decision=True,
            event_ids=tuple(sorted(set(map(str, row.get("event_ids", ()))))) ,
            node_ids=tuple(sorted(set(map(str, row["node_ids"])))),
            timestamp_start=int(row["start_ns"]), timestamp_end=int(row["end_ns"]),
            role_hint=RoleHint.UNKNOWN, mapping_quality=MappingQuality.EXACT,
            detector_metadata={
                "dataset": "TRACE_E3", "test_day": day,
                "queue_id": str(row["queue_id"]), "window": str(row["window"]),
                "query_window_start_ns": lower, "query_window_end_ns": upper,
            },
        ) for row in observed)
    return tuple(AlertEvidence(
        evidence_id=f"KAIROS:TRACE_E3:{day}:{node}", detector_id="KAIROS",
        detector_version="PIDSMaker", granularity=EvidenceGranularity.NODE,
        raw_score=None, calibrated_score=1.0, native_decision=True,
        node_ids=(str(node),), timestamp_start=None, timestamp_end=None,
        role_hint=RoleHint.UNKNOWN, mapping_quality=MappingQuality.EXACT,
        detector_metadata={
            "dataset": "TRACE_E3", "test_day": day,
            "query_window_start_ns": lower, "query_window_end_ns": upper,
        },
    ) for node in sorted(set(map(str, pois))))


def _day_bounds(queues: Mapping[str, Any], day: str) -> tuple[int, int]:
    details = [
        window for queue in queues["queues"] for window in queue["window_details"]
        if str(window["day"]) == day
    ]
    if not details:
        raise ValueError(f"no KAIROS windows for {day}")
    return min(int(row["start_ns"]) for row in details), max(int(row["end_ns"]) for row in details)


def detector_demand_pairs(
    candidate_edges: Iterable[Any], observations: Iterable[Mapping[str, Any]],
    active_pois: Iterable[str],
) -> frozenset[tuple[str, str]]:
    """Derive scalable PBR demands from sealed detector event anchors only."""
    event_ids = {
        str(event_id).casefold() for observation in observations
        for event_id in observation.get("event_ids", ())
    }
    pois = {str(node).casefold() for node in active_pois}
    pairs = set()
    for edge in candidate_edges:
        if edge.event_id.casefold() not in event_ids:
            continue
        try:
            source, target = _causal(edge)
        except ValueError:
            continue
        normalized_source, normalized_target = source.casefold(), target.casefold()
        if normalized_source != normalized_target and normalized_source in pois and normalized_target in pois:
            pairs.add((source, target))
    return frozenset(pairs)


def _method_eval(candidate, selected, truth_nodes, hit_pois):
    from .orthrus_groundtruth import evaluate_poi_scoped_retention
    return evaluate_poi_scoped_retention(
        candidate_edges=tuple(map(_path_record, candidate)),
        selected_event_ids=set(map(str, selected)),
        groundtruth_node_ids=set(map(str, truth_nodes)),
        poi_node_ids=set(map(str, hit_pois)),
    )


def run_trace_experiment(
    *, database: str | Path, poi_seal_path: str | Path,
    queue_manifest_path: str | Path, groundtruth_paths: Iterable[str | Path],
    run_directory: str | Path, candidate_cap: int = 10_000,
    selection_cap: int = 12_000,
) -> dict[str, Any]:
    run_dir = Path(run_directory).resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    seal = json.loads(Path(poi_seal_path).read_text(encoding="utf-8"))
    queues = json.loads(Path(queue_manifest_path).read_text(encoding="utf-8"))
    if seal.get("dataset") != "TRACE_E3" or seal.get("detector") != "KAIROS":
        raise ValueError("invalid TRACE E3 KAIROS POI seal")
    if seal.get("queue_manifest_sha256") != queues.get("content_sha256"):
        raise ValueError("queue manifest does not match POI seal")
    projection = EdgeProjection(mode="DEPIMPACT_COMPATIBLE", merge_window_ns=900_000_000_000)
    online_rows = []
    runtime = {}
    with ProvenanceStore(database) as store:
        frequency = FrequencyModel.from_store(store)
        for day, raw_pois in sorted(seal["poi_node_ids_by_day"].items()):
            pois = frozenset(map(str, raw_pois))
            if not pois:
                continue
            lower, upper = _day_bounds(queues, day)
            candidate_result = EvidenceDrivenCandidateBuilder(store, CandidateSearchConfig(
                candidate_cap=candidate_cap, history_start_ns=lower, cutoff_ns=upper,
                max_strict_depth=8, max_control_depth=2,
                enable_common_cause=True, scan_multiplier=20,
            )).build(_evidence(
                day, pois, lower, upper,
                observations=seal.get("poi_observations_by_day", {}).get(day),
            ))
            candidate = candidate_result.edges
            proxies, proxy_audit = select_poi_proxies(candidate, pois, require_all=False)
            active_pois = frozenset(proxy_audit["active_poi_node_ids"])
            maximum = min(len(candidate), max(selection_cap, len(proxies)))
            a_started = time.perf_counter()
            a = _a_rasp(
                store, candidate, proxies, maximum, proxy_audit,
                frequency_model=frequency,
            )
            a_seconds = time.perf_counter() - a_started
            a_ids = frozenset(map(str, a["selected_raw_event_ids"]))
            pbr_extra_cap = min(2_000, max(0, maximum - len(proxies)))
            pbr_base_cap = maximum - pbr_extra_cap
            pbr_base_started = time.perf_counter()
            pbr_base = _a_rasp(
                store, candidate, proxies, pbr_base_cap, proxy_audit,
                frequency_model=frequency,
            )
            pbr_base_seconds = time.perf_counter() - pbr_base_started
            pbr_base_ids = frozenset(map(str, pbr_base["selected_raw_event_ids"]))
            evidence_started = time.perf_counter()
            evidence = a_rasp_evidence(candidate, proxies, frequency)
            evidence_seconds = time.perf_counter() - evidence_started
            normalized_active_pois = {node.casefold() for node in active_pois}
            pbr_pois = frozenset(
                node for edge in candidate for node in (edge.src, edge.dst)
                if node.casefold() in normalized_active_pois
            )
            demand_pairs = detector_demand_pairs(
                candidate,
                seal.get("poi_observations_by_day", {}).get(day, ()),
                pbr_pois,
            )
            pbr_started = time.perf_counter()
            pbr = pbr_sweep(
                candidate_edges=candidate,
                base_selected_event_ids=pbr_base_ids,
                poi_node_ids=pbr_pois,
                mandatory_event_ids=proxies,
                projection=projection,
                branch_provenance=candidate_result.branch_provenance,
                relevance={event: values["path_score"] for event, values in evidence.items()},
                rarity={event: values["rarity"] for event, values in evidence.items()},
                allowances=(1.0,), fixed_extra_raw=pbr_extra_cap, k_paths=3,
                demand_pairs=demand_pairs,
            )[0]
            pbr_seconds = time.perf_counter() - pbr_started
            pbr_ids = frozenset(map(str, pbr.pop("selected_raw_event_ids")))
            if len(pbr_ids) > maximum:
                raise ValueError("A_rasp-PBR exceeded the shared raw-event cap")
            targets = sorted({
                min(maximum, target)
                for target in (100, 250, 500, 1000, 2000, 4000, 8000, 10_000, 12_000)
                if min(maximum, target) >= len(proxies)
            } | {len(proxies), maximum})
            c_started = time.perf_counter()
            c_points = branch_fair_checkpoints(
                edges=candidate, mandatory=proxies,
                provenance=candidate_result.branch_provenance,
                projection=projection, projected_targets=targets,
                maximum_raw_budget=maximum,
            )
            c_seconds = time.perf_counter() - c_started
            candidate_ids = sorted(edge.event_id for edge in candidate)
            candidate_sha = _sha(candidate_ids)
            row = {
                "day": day, "poi_node_ids": sorted(pois),
                "candidate_poi_node_ids": sorted(active_pois),
                "poi_candidate_coverage": proxy_audit["poi_candidate_coverage"],
                "proxy_event_ids": sorted(proxies),
                "candidate_sha256": candidate_sha,
                "candidate": {
                    "raw_events": len(candidate),
                    "projected_edges": projection.count(candidate),
                    "stop_reason": candidate_result.stop_reason,
                    "performance": asdict(candidate_result.performance),
                },
                "methods": {
                    "A_rasp": {
                        "candidate_sha256": candidate_sha,
                        "selected_raw_event_ids": sorted(a_ids),
                        "raw_events": len(a_ids),
                        "projected_edges": projection.count(
                            edge for edge in candidate if edge.event_id in a_ids
                        ),
                        "selector_seconds": a_seconds,
                    },
                    "A_rasp-PBR": {
                        **pbr,
                        "candidate_sha256": candidate_sha,
                        "selected_raw_event_ids": sorted(pbr_ids),
                        "raw_events": len(pbr_ids),
                        "projected_edges": projection.count(
                            edge for edge in candidate if edge.event_id in pbr_ids
                        ),
                        "base_raw_budget": pbr_base_cap,
                        "rescue_raw_budget": pbr_extra_cap,
                        "detector_demand_pair_count": len(demand_pairs),
                        "base_selector_seconds": pbr_base_seconds,
                        "evidence_sidecar_seconds": evidence_seconds,
                        "rescue_selector_seconds": pbr_seconds,
                        "selector_pipeline_seconds": (
                            pbr_base_seconds + evidence_seconds + pbr_seconds
                        ),
                    },
                    "C_branch_fair": {
                        "candidate_sha256": candidate_sha,
                        "selector_pipeline_seconds": c_seconds,
                        "checkpoints": list(c_points),
                    },
                },
            }
            validate_online_record(row)
            _atomic(run_dir / f"online-{day}.json", row)
            online_rows.append(row)
            runtime[day] = (row, candidate)
    online_decisions = {
        row["day"]: {
            name: _sha(method.get("selected_raw_event_ids", method.get("checkpoints", [])))
            for name, method in row["methods"].items()
        } for row in online_rows
    }
    online_seal = {
        "schema_version": "trace-e3-kairos-pruning-online-seal-v1",
        "detector_poi_sha256": seal["content_sha256"],
        "decisions": online_decisions,
    }
    online_seal["content_sha256"] = _sha(online_seal)
    _atomic(run_dir / "online-seal.json", online_seal)

    # The first ORTHRUS import and file read occurs only after the online seal exists.
    from .orthrus_groundtruth import load_orthrus_groundtruth
    evaluations = []
    for truth_path in map(Path, groundtruth_paths):
        truth = load_orthrus_groundtruth(truth_path)
        day = "2018-04-10" if "0410" in truth_path.name else "2018-04-13"
        row, candidate = runtime.get(day, (None, None))
        if row is None:
            evaluations.append({
                "scenario": truth_path.stem, "day": day,
                "scope": scenario_scope((), truth["node_ids"]),
            })
            continue
        scope = scenario_scope_for_record(row, truth["node_ids"])
        evaluation = {"scenario": truth_path.stem, "day": day, "scope": scope}
        if scope["status"] == "ELIGIBLE":
            hits = scope["attack_poi_node_ids"]
            evaluation["attack_poi_recall"] = len(hits) / len(truth["node_ids"])
            evaluation["methods"] = {
                "A_rasp": _method_eval(
                    candidate, row["methods"]["A_rasp"]["selected_raw_event_ids"],
                    truth["node_ids"], hits,
                ),
                "A_rasp-PBR": _method_eval(
                    candidate, row["methods"]["A_rasp-PBR"]["selected_raw_event_ids"],
                    truth["node_ids"], hits,
                ),
                "C_branch_fair": [
                    {**{k: v for k, v in point.items() if k != "selected_raw_event_ids"},
                     "evaluation": _method_eval(candidate, point["selected_raw_event_ids"], truth["node_ids"], hits)}
                    for point in row["methods"]["C_branch_fair"]["checkpoints"]
                ],
            }
        evaluations.append(evaluation)
        _atomic(run_dir / f"offline-{truth_path.stem}.json", evaluation)
    result = {
        "schema_version": "trace-e3-kairos-poi-pruning-result-v1",
        "status": "COMPLETED", "online_seal_sha256": online_seal["content_sha256"],
        "evaluations": evaluations,
    }
    result["content_sha256"] = _sha(result)
    _atomic(run_dir / "evaluation.json", result)
    return result


__all__ = [
    "detector_demand_pairs", "run_trace_experiment", "scenario_scope",
    "scenario_scope_for_record", "validate_online_record",
]
