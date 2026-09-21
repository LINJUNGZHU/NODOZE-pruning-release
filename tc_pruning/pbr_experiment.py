"""Reusable online-only pieces for the A_rasp-PBR Pareto experiment."""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from typing import Any, Iterable, Mapping, Sequence

import numpy as np

from .benchmark_contract import EdgeProjection
from .investigation.branch_fair_selector import BranchFairConfig, LazyGreedySelector
from .investigation.evidence_units import EvidenceUnit, ecdf_relevance
from .models import StoredEdge
from .pbr import PBRConfig, rescue_poi_bridges
from .detector_seed_benchmark import _causal
from .frequency import FrequencyModel
from .rasp import propagate
from .detectors.alert_evidence import (
    AlertEvidence, EvidenceGranularity, MappingQuality, RoleHint,
)
from .evidence_candidate_builder import CandidateSearchConfig, EvidenceDrivenCandidateBuilder
from .kairos_poi_experiment import (
    _file_sha, _load_edges, _path_record, _require_pinned, select_poi_proxies,
)
from .store import ProvenanceStore
from .detector_seed_benchmark import _a_rasp


def _sha(value: Any) -> str:
    body = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(body.encode()).hexdigest()


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
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


def _progress(run_directory: Path, **fields: Any) -> None:
    payload = {"updated_ns": time.time_ns(), **fields}
    _atomic_json(run_directory / "progress.json", payload)
    _atomic_json(run_directory / "process-status.json", {
        "status": "RUNNING", "pid": os.getpid(), **payload,
    })


def a_rasp_evidence(
    edges: Sequence[StoredEdge], mandatory: frozenset[str],
    frequency: FrequencyModel,
) -> dict[str, dict[str, float]]:
    """Recompute the unchanged A_rasp evidence as an online sidecar."""
    causal_edges: list[StoredEdge] = []
    endpoints: list[tuple[str, str]] = []
    for edge in edges:
        try:
            pair = _causal(edge)
        except ValueError:
            continue
        causal_edges.append(edge)
        endpoints.append(pair)
    output = {
        edge.event_id: {"rarity": 0.0, "ppr": 0.0, "lift": 0.0, "path_score": 0.0}
        for edge in edges
    }
    if not causal_edges:
        return output
    poi_ids = mandatory & {edge.event_id for edge in causal_edges}
    if not poi_ids:
        return output
    nodes = sorted({node for pair in endpoints for node in pair})
    index = {node: position for position, node in enumerate(nodes)}
    src = np.asarray([index[pair[0]] for pair in endpoints])
    dst = np.asarray([index[pair[1]] for pair in endpoints])
    relation_names = sorted({edge.relation.upper() for edge in causal_edges})
    relation_index = {name: position for position, name in enumerate(relation_names)}
    relation = np.asarray([relation_index[edge.relation.upper()] for edge in causal_edges])
    rare = np.asarray([frequency.edge_rarity(edge) for edge in causal_edges])
    poi = np.asarray([edge.event_id in poi_ids for edge in causal_edges], dtype=bool)
    node_type: dict[str, str] = {}
    for edge in causal_edges:
        node_type.setdefault(edge.src, edge.src_type.lower())
        node_type.setdefault(edge.dst, edge.dst_type.lower())
    process = np.asarray([
        node_type.get(node, "") in {"process", "subject"} for node in nodes
    ], dtype=float)
    score, diagnostics = propagate(
        src, dst, relation, rare, poi, process,
        {"restart": .15, "iterations": 100, "tolerance": 1e-10,
         "rarity_floor": .2},
    )
    lift = np.asarray(diagnostics["diffusion"], dtype=float)
    if lift.size and lift.max() > 0:
        lift = lift / lift.max()
    for position, edge in enumerate(causal_edges):
        value = float(score[position])
        output[edge.event_id] = {
            "rarity": float(rare[position]),
            "ppr": value,
            "lift": float(np.clip(lift[position], 0.0, 1.0)),
            "path_score": value,
        }
    return output


def _branch_units(
    edges: Sequence[StoredEdge], mandatory: frozenset[str],
    provenance: Mapping[str, tuple[str, ...]],
) -> tuple[EvidenceUnit, ...]:
    raw = {edge.event_id: 1.0 if edge.event_id in mandatory else 0.0 for edge in edges}
    normalized = ecdf_relevance(raw)
    return tuple(EvidenceUnit(
        "edge:" + edge.event_id,
        "edge",
        (edge.event_id,),
        (edge.src, edge.dst),
        frozenset(provenance.get(edge.event_id, ("observation:" + edge.event_id,))),
        frozenset({edge.event_id}) if edge.event_id in mandatory else frozenset(),
        None,
        frozenset(),
        raw[edge.event_id],
        normalized[edge.event_id],
        0.0,
    ) for edge in edges)


def branch_fair_checkpoints(
    *,
    edges: Sequence[StoredEdge],
    mandatory: frozenset[str],
    provenance: Mapping[str, tuple[str, ...]],
    projection: EdgeProjection,
    projected_targets: Iterable[int],
    maximum_raw_budget: int,
) -> tuple[dict[str, Any], ...]:
    """Run C once and return real trajectory points nearest projected targets."""
    materialized = tuple(edges)
    by_event = {edge.event_id: edge for edge in materialized}
    if not mandatory <= by_event.keys():
        raise ValueError("mandatory C evidence is absent from the candidate")
    if maximum_raw_budget < len(mandatory):
        raise ValueError("C maximum budget is smaller than mandatory evidence")
    result = LazyGreedySelector(BranchFairConfig()).select(
        _branch_units(materialized, mandatory, provenance),
        mandatory_event_ids=set(mandatory),
        budget=min(maximum_raw_budget, len(materialized)),
    )
    selected = set(mandatory)
    trajectory: list[tuple[int, int, tuple[str, ...]]] = []

    def record() -> None:
        ids = tuple(sorted(selected))
        trajectory.append((len(ids), projection.count(by_event[event] for event in ids), ids))

    record()
    for unit_id in result.selected_unit_ids:
        event_id = unit_id.removeprefix("edge:")
        selected.add(event_id)
        record()
    rows = []
    for target in sorted(set(map(int, projected_targets))):
        raw, projected, ids = min(
            trajectory,
            key=lambda row: (abs(row[1] - target), row[1] > target, row[1], row[0]),
        )
        rows.append({
            "target_projected_edges": target,
            "actual_projected_edges": projected,
            "actual_raw_events": raw,
            "selected_raw_event_ids": list(ids),
            "decision_sha256": _sha(list(ids)),
            "trajectory_selector_seconds": result.selection_seconds,
        })
    return tuple(rows)


def pbr_sweep(
    *,
    candidate_edges: Sequence[StoredEdge],
    base_selected_event_ids: frozenset[str],
    poi_node_ids: frozenset[str],
    mandatory_event_ids: frozenset[str],
    projection: EdgeProjection,
    branch_provenance: Mapping[str, tuple[str, ...]],
    relevance: Mapping[str, float],
    rarity: Mapping[str, float],
    allowances: Iterable[float],
    fixed_extra_raw: int,
    k_paths: int = 3,
    demand_pairs: frozenset[tuple[str, str]] | None = None,
) -> tuple[dict[str, Any], ...]:
    """Return online PBR checkpoints; this interface intentionally has no GT."""
    rows = []
    for ratio in sorted(set(map(float, allowances))):
        result = rescue_poi_bridges(
            candidate_edges=candidate_edges,
            base_selected_event_ids=base_selected_event_ids,
            poi_node_ids=poi_node_ids,
            mandatory_event_ids=mandatory_event_ids,
            projection=projection,
            relevance=relevance,
            rarity=rarity,
            branch_provenance=branch_provenance,
            demand_pairs=demand_pairs,
            config=PBRConfig(
                k_paths=k_paths,
                fixed_extra_raw=fixed_extra_raw,
                rescue_ratio=ratio,
            ),
        )
        selected_ids = set(result.selected_raw_event_ids)
        rows.append({
            "allowance_ratio": ratio,
            "selected_raw_event_ids": list(result.selected_raw_event_ids),
            "added_raw_event_ids": list(result.added_raw_event_ids),
            "actual_raw_events": len(result.selected_raw_event_ids),
            "actual_projected_edges": projection.count(
                edge for edge in candidate_edges
                if edge.event_id in selected_ids
            ),
            "bridge_demands": [asdict(row) for row in result.demands],
            "bundles": [asdict(row) for row in result.considered_bundles],
            "selected_bundles": [asdict(row) for row in result.selected_bundles],
            "metrics": dict(result.metrics),
            "decision_sha256": result.decision_sha256,
        })
    return tuple(rows)


def _event_evidence(
    scenario: str, poi_ids: frozenset[str], k6_proxy_ids: frozenset[str],
) -> tuple[AlertEvidence, ...]:
    events = tuple(AlertEvidence(
        evidence_id=f"KAIROS-K6:{scenario}:event:{event_id}",
        detector_id="KAIROS", detector_version="K6",
        granularity=EvidenceGranularity.EVENT, raw_score=None,
        calibrated_score=1.0, native_decision=True, event_ids=(event_id,),
        role_hint=RoleHint.OBSERVATION, mapping_quality=MappingQuality.EXACT,
        detector_metadata={"layer": "K6", "scenario": scenario},
    ) for event_id in sorted(k6_proxy_ids))
    nodes = tuple(AlertEvidence(
        evidence_id=f"KAIROS-K6:{scenario}:{node}",
        detector_id="KAIROS", detector_version="K6",
        granularity=EvidenceGranularity.NODE, raw_score=None,
        calibrated_score=1.0, native_decision=True, node_ids=(node,),
        role_hint=RoleHint.OBSERVATION, mapping_quality=MappingQuality.EXACT,
        detector_metadata={"layer": "K6", "scenario": scenario},
    ) for node in sorted(poi_ids))
    return events + nodes


def _method_evaluation(
    candidate: Sequence[StoredEdge], selected: Iterable[str],
    truth_nodes: set[str], pois: frozenset[str],
) -> dict[str, Any]:
    from .orthrus_groundtruth import evaluate_poi_scoped_retention

    return evaluate_poi_scoped_retention(
        candidate_edges=tuple(map(_path_record, candidate)),
        selected_event_ids=set(selected), groundtruth_node_ids=truth_nodes,
        poi_node_ids=set(pois),
    )


def run_formal_experiment(config: Mapping[str, Any], run_directory: str | Path) -> dict[str, Any]:
    """Run online methods first, seal them, then load GT for offline metrics."""
    run_dir = Path(run_directory).resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    if config.get("schema_version") != "a-rasp-pbr-experiment-v1":
        raise ValueError("invalid A_rasp-PBR config schema")
    if config.get("dataset") != "DARPA_TC_E3_CADETS":
        raise ValueError("A_rasp-PBR is frozen to CADETS E3")
    config_path = Path(str(config["config_path"])).resolve()
    database = _require_pinned(config["database"]["path"], config["database"]["sha256"])
    baseline = config["baseline"]
    _require_pinned(baseline["evaluation_path"], baseline["evaluation_sha256"])
    _require_pinned(baseline["legacy_config_path"], baseline["legacy_config_sha256"])
    _require_pinned(
        baseline["legacy_selector_source_path"],
        baseline["legacy_selector_source_sha256"],
    )
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parents[1],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    _atomic_json(run_dir / "input-manifest.json", {
        "run_id": run_dir.name,
        "commit": commit,
        "config_path": str(config_path),
        "config_sha256": _file_sha(config_path),
        "database_path": str(database),
        "database_sha256": config["database"]["sha256"],
        "baseline": config["baseline"],
        "source_sha256": {
            name: _file_sha(Path(__file__).with_name(name))
            for name in ("pbr.py", "pbr_experiment.py", "detector_seed_benchmark.py")
        },
    })
    _progress(run_dir, scenario=None, method="baseline", stage="INPUTS_PINNED")
    projection = EdgeProjection(**config["projection"])
    candidate_config = CandidateSearchConfig(**config["candidate"])
    online_rows: list[dict[str, Any]] = []
    runtime: list[tuple[dict[str, Any], tuple[StoredEdge, ...], dict[str, dict[str, float]], frozenset[str]]] = []
    with ProvenanceStore(database) as store:
        cache_meta = dict(store.conn.execute("SELECT key,value FROM frequency_cache_meta"))
        if cache_meta.get("stale") != "0" or int(cache_meta.get("source_edges", -1)) != store.edge_count():
            raise ValueError("frequency cache is stale")
        frequency = FrequencyModel.from_cache(store)
        for scenario_spec in config["scenarios"]:
            scenario = str(scenario_spec["scenario"]).zfill(2)
            _progress(run_dir, scenario=scenario, method="baseline", stage="CANDIDATE_STARTED")
            online_path = _require_pinned(
                scenario_spec["kairos_online"], scenario_spec["kairos_sha256"]
            )
            online = json.loads(online_path.read_text(encoding="utf-8"))
            layers = online["kairos_ablations"]
            k6_edges = _load_edges(store, layers["K6"]["event_ids"])
            pois = frozenset(map(str, scenario_spec["poi_node_ids"]))
            priority = tuple(
                frozenset(map(str, layers[name]["event_ids"]))
                for name in ("K1", "K0", "K2", "K3", "K4", "K5", "K6")
                if name in layers
            )
            k6_proxy, _ = select_poi_proxies(k6_edges, pois, layer_priority=priority)
            candidate_started = time.perf_counter()
            candidate_result = EvidenceDrivenCandidateBuilder(store, candidate_config).build(
                _event_evidence(scenario, pois, k6_proxy)
            )
            candidate = candidate_result.edges
            candidate_seconds = time.perf_counter() - candidate_started
            proxy, proxy_audit = select_poi_proxies(candidate, pois, layer_priority=priority)
            _progress(run_dir, scenario=scenario, method="A_rasp", stage="SELECTOR_STARTED")
            a_started = time.perf_counter()
            a = _a_rasp(
                store, candidate, proxy, int(config["maximum_raw_budget"]),
                proxy_audit, frequency_model=frequency,
            )
            a_seconds = time.perf_counter() - a_started
            a_ids = frozenset(map(str, a["selected_raw_event_ids"]))
            evidence = a_rasp_evidence(candidate, proxy, frequency)
            relevance = {key: row["path_score"] for key, row in evidence.items()}
            rarity = {key: row["rarity"] for key, row in evidence.items()}
            _progress(run_dir, scenario=scenario, method="C_branch_fair", stage="TRAJECTORY_STARTED")
            c_points = branch_fair_checkpoints(
                edges=candidate, mandatory=proxy,
                provenance=candidate_result.branch_provenance,
                projection=projection,
                projected_targets=config["c_projected_targets"],
                maximum_raw_budget=int(config["maximum_raw_budget"]),
            )
            _progress(run_dir, scenario=scenario, method="A_rasp-PBR", stage="SWEEP_STARTED")
            pbr_points = pbr_sweep(
                candidate_edges=candidate, base_selected_event_ids=a_ids,
                poi_node_ids=pois, mandatory_event_ids=proxy,
                projection=projection,
                branch_provenance=candidate_result.branch_provenance,
                relevance=relevance, rarity=rarity,
                allowances=config["pbr_allowance_ratios"],
                fixed_extra_raw=int(config["fixed_extra_raw"]),
                k_paths=int(config["k_paths"]),
            )
            row = {
                "scenario": scenario,
                "poi_node_ids": sorted(pois),
                "proxy_event_ids": sorted(proxy),
                "candidate": {
                    "raw_events": len(candidate),
                    "projected_edges": projection.count(candidate),
                    "seconds": candidate_seconds,
                    "stop_reason": candidate_result.stop_reason,
                    "event_ids_sha256": _sha(sorted(edge.event_id for edge in candidate)),
                },
                "candidate_edges": [asdict(edge) for edge in candidate],
                "branch_provenance": candidate_result.branch_provenance,
                "a_rasp_evidence": evidence,
                "A_rasp": {
                    "selected_raw_event_ids": sorted(a_ids),
                    "actual_raw_events": len(a_ids),
                    "actual_projected_edges": projection.count(
                        edge for edge in candidate if edge.event_id in a_ids
                    ),
                    "selector_seconds": a_seconds,
                    "decision_sha256": _sha(sorted(a_ids)),
                },
                "C_branch_fair": list(c_points),
                "A_rasp-PBR": list(pbr_points),
            }
            _atomic_json(run_dir / f"online-scenario-{scenario}.json", row)
            online_rows.append(row)
            runtime.append((row, candidate, evidence, pois))
            _progress(run_dir, scenario=scenario, method="A_rasp-PBR", stage="ONLINE_SCENARIO_SEALED")

    online_decisions = {
        row["scenario"]: {
            "A_rasp": row["A_rasp"]["decision_sha256"],
            "C_branch_fair": [point["decision_sha256"] for point in row["C_branch_fair"]],
            "A_rasp-PBR": [point["decision_sha256"] for point in row["A_rasp-PBR"]],
        } for row in online_rows
    }
    online_seal = {"decisions": online_decisions, "decision_sha256": _sha(online_decisions)}
    _atomic_json(run_dir / "online-seal.json", online_seal)
    _progress(run_dir, scenario=None, method="offline", stage="ONLINE_ALL_SCENARIOS_SEALED")

    evaluations: list[dict[str, Any]] = []
    from .orthrus_groundtruth import load_orthrus_groundtruth
    from .pbr_audit import audit_scenario13_bridges, render_audit_markdown
    for scenario_spec, (row, candidate, evidence, pois) in zip(config["scenarios"], runtime):
        scenario = row["scenario"]
        _progress(run_dir, scenario=scenario, method="offline", stage="ORTHRUS_EVALUATION_STARTED")
        truth_path = _require_pinned(
            scenario_spec["orthrus_csv"], scenario_spec["orthrus_sha256"]
        )
        truth = load_orthrus_groundtruth(truth_path)
        truth_nodes = set(truth["node_ids"])
        evaluation = {
            "scenario": scenario,
            "A_rasp": _method_evaluation(
                candidate, row["A_rasp"]["selected_raw_event_ids"], truth_nodes, pois
            ),
            "C_branch_fair": [],
            "A_rasp-PBR": [],
        }
        for point in row["C_branch_fair"]:
            evaluation["C_branch_fair"].append({
                **{key: value for key, value in point.items() if key != "selected_raw_event_ids"},
                "evaluation": _method_evaluation(
                    candidate, point["selected_raw_event_ids"], truth_nodes, pois
                ),
            })
        for point in row["A_rasp-PBR"]:
            evaluation["A_rasp-PBR"].append({
                **{key: value for key, value in point.items() if key not in {"selected_raw_event_ids", "bundles"}},
                "evaluation": _method_evaluation(
                    candidate, point["selected_raw_event_ids"], truth_nodes, pois
                ),
            })
        evaluations.append(evaluation)
        _atomic_json(run_dir / f"offline-scenario-{scenario}.json", evaluation)
        if scenario == "13":
            largest_c = max(row["C_branch_fair"], key=lambda point: point["actual_raw_events"])
            audit = audit_scenario13_bridges(
                candidate_edges=candidate,
                a_selected_event_ids=frozenset(row["A_rasp"]["selected_raw_event_ids"]),
                c_selected_event_ids=frozenset(largest_c["selected_raw_event_ids"]),
                evaluation=evaluation["A_rasp"], poi_node_ids=pois,
                a_evidence=evidence, c_relevance={},
                branch_provenance=row["branch_provenance"],
            )
            _atomic_json(run_dir / "scenario13_bridge_audit.json", audit)
            (run_dir / "scenario13_bridge_audit.md").write_text(
                render_audit_markdown(audit), encoding="utf-8"
            )
    result = {
        "schema_version": "a-rasp-pbr-result-v1",
        "status": "COMPLETED",
        "run_id": run_dir.name,
        "online_decision_sha256": online_seal["decision_sha256"],
        "evaluations": evaluations,
    }
    result["content_sha256"] = _sha(result)
    _atomic_json(run_dir / "evaluation.json", result)
    _progress(run_dir, scenario=None, method=None, stage="COMPLETED")
    _atomic_json(run_dir / "process-status.json", {
        "status": "COMPLETED", "pid": os.getpid(), "scenario": None,
        "method": None, "stage": "COMPLETED", "updated_ns": time.time_ns(),
    })
    return result


__all__ = [
    "a_rasp_evidence", "branch_fair_checkpoints", "pbr_sweep",
    "run_formal_experiment",
]
