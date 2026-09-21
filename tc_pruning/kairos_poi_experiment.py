"""Offline oracle-assisted KAIROS-K6 POI comparison for CADETS E3.

KAIROS artifacts are frozen before ORTHRUS is loaded.  ORTHRUS-positive K6
endpoints then become evaluation-only POIs for a controlled A_rasp versus
C_branch_fair comparison.  This module must not be presented as a deployable
detector pipeline: the POI choice intentionally uses offline positive labels.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import resource
import tempfile
import time
from typing import Any, Iterable, Mapping, Sequence

from .benchmark_contract import EdgeProjection
from .detector_seed_benchmark import _a_rasp, _branch_fair
from .detectors.alert_evidence import (
    AlertEvidence,
    EvidenceGranularity,
    MappingQuality,
    RoleHint,
)
from .evidence_candidate_builder import (
    CandidateSearchConfig,
    EvidenceDrivenCandidateBuilder,
)
from .frequency import FrequencyModel
from .models import StoredEdge
from .orthrus_groundtruth import (
    evaluate_poi_scoped_retention,
    load_orthrus_groundtruth,
)
from .store import ProvenanceStore


SCHEMA_VERSION = "kairos-k6-poi-context-comparison-v1"
DATASET = "DARPA_TC_E3_CADETS"
SCENARIOS = ("06", "12", "13")


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode()


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _file_sha(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    payload = dict(value)
    unsigned = dict(payload)
    unsigned.pop("content_sha256", None)
    payload["content_sha256"] = _digest(unsigned)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_canonical(payload))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def select_poi_proxies(
    edges: Sequence[StoredEdge],
    poi_node_ids: Iterable[str],
    *,
    layer_priority: Sequence[frozenset[str]] = (),
    require_all: bool = True,
) -> tuple[frozenset[str], dict[str, Any]]:
    """Choose one deterministic incident event for each abstract node POI."""
    pois = sorted({str(node).casefold() for node in poi_node_ids})
    if not pois:
        raise ValueError("at least one K6-derived POI is required")
    rank: dict[str, int] = {}
    for layer_index, event_ids in enumerate(layer_priority):
        for event_id in event_ids:
            rank.setdefault(str(event_id), layer_index)
    incident: dict[str, list[StoredEdge]] = {node: [] for node in pois}
    for edge in edges:
        for endpoint in {edge.src.casefold(), edge.dst.casefold()} & incident.keys():
            incident[endpoint].append(edge)
    chosen: dict[str, str] = {}
    missing: list[str] = []
    for node in pois:
        if not incident[node]:
            if require_all:
                raise ValueError(f"POI has no incident event in the common candidate: {node}")
            missing.append(node)
            continue
        edge = min(
            incident[node],
            key=lambda item: (
                rank.get(item.event_id, len(layer_priority)),
                item.timestamp_ns,
                item.event_id,
            ),
        )
        chosen[node] = edge.event_id
    if not chosen:
        raise ValueError("no POI has an incident event in the common candidate")
    proxies = frozenset(chosen.values())
    return proxies, {
        "policy": "KAIROS-layer-priority,then-time,then-event-id",
        "poi_nodes": len(pois),
        "unique_proxy_events": len(proxies),
        "poi_to_proxy_event": chosen,
        "active_poi_node_ids": sorted(chosen),
        "missing_poi_node_ids": missing,
        "poi_candidate_coverage": len(chosen) / len(pois),
        "layer_priority_count": len(layer_priority),
    }


def run_selectors(
    *,
    store: ProvenanceStore,
    edges: Sequence[StoredEdge],
    poi_node_ids: Iterable[str],
    raw_event_cap: int,
    projection: EdgeProjection,
    layer_priority: Sequence[frozenset[str]] = (),
    frequency_model: FrequencyModel | None = None,
    branch_provenance: Mapping[str, tuple[str, ...]] | None = None,
) -> dict[str, Any]:
    """Run both selectors against exactly one frozen common POI candidate."""
    materialized = tuple(
        sorted(edges, key=lambda edge: (edge.timestamp_ns, edge.edge_id, edge.event_id))
    )
    if not materialized:
        raise ValueError("common POI candidate is empty")
    if raw_event_cap <= 0:
        raise ValueError("raw_event_cap must be positive")
    proxies, proxy_audit = select_poi_proxies(
        materialized, poi_node_ids, layer_priority=layer_priority
    )
    if len(proxies) > raw_event_cap:
        raise ValueError("hard event budget is smaller than mandatory POI proxies")
    input_hash = hashlib.sha256(
        "\n".join(sorted(edge.event_id for edge in materialized)).encode()
    ).hexdigest()
    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    started = time.perf_counter()
    a_payload = _a_rasp(
        store,
        materialized,
        proxies,
        raw_event_cap,
        proxy_audit,
        frequency_model=frequency_model,
    )
    a_seconds = time.perf_counter() - started
    started = time.perf_counter()
    c_payload = _branch_fair(
        materialized,
        proxies,
        raw_event_cap,
        proxy_audit,
        provenance=branch_provenance,
    )
    c_seconds = time.perf_counter() - started

    def finalize(payload: Mapping[str, Any], seconds: float) -> dict[str, Any]:
        selected = frozenset(map(str, payload["selected_raw_event_ids"]))
        if not proxies <= selected:
            raise ValueError("selector removed a mandatory POI proxy")
        if len(selected) > raw_event_cap:
            raise ValueError("selector exceeded the hard raw-event budget")
        selected_edges = tuple(
            edge for edge in materialized if edge.event_id in selected
        )
        return {
            "selected_raw_event_ids": sorted(selected),
            "raw_events": len(selected),
            "projected_edges": projection.count(selected_edges),
            "selector_seconds": seconds,
            "input_event_ids_sha256": input_hash,
            "mandatory_proxy_events": len(proxies),
        }

    return {
        "candidate_raw_events": len(materialized),
        "candidate_projected_edges": projection.count(materialized),
        "candidate_event_ids_sha256": input_hash,
        "proxy_event_ids": sorted(proxies),
        "proxy_audit": proxy_audit,
        "A_rasp": finalize(a_payload, a_seconds),
        "C_branch_fair": finalize(c_payload, c_seconds),
        "peak_rss_kb": max(
            before, resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        ),
    }


def _load_edges(store: ProvenanceStore, event_ids: Iterable[str]) -> tuple[StoredEdge, ...]:
    requested = sorted(set(map(str, event_ids)))
    found: dict[str, StoredEdge] = {}
    for offset in range(0, len(requested), 400):
        chunk = requested[offset : offset + 400]
        marks = ",".join("?" for _ in chunk)
        rows = store.conn.execute(
            "SELECT e.id,e.event_id,e.src,e.dst,e.relation,e.timestamp_ns,e.host,"
            "e.data_size,COALESCE(s.node_type,'unknown') src_type,"
            "COALESCE(d.node_type,'unknown') dst_type,"
            "COALESCE(s.semantic_key,'') src_semantic,"
            "COALESCE(d.semantic_key,'') dst_semantic "
            "FROM edges e LEFT JOIN nodes s ON s.uuid=e.src "
            "LEFT JOIN nodes d ON d.uuid=e.dst "
            f"WHERE e.event_id IN ({marks})",
            tuple(chunk),
        )
        for row in rows:
            found[str(row["event_id"])] = StoredEdge(
                int(row["id"]), str(row["event_id"]), str(row["src"]),
                str(row["dst"]), str(row["relation"]), int(row["timestamp_ns"]),
                str(row["host"]), str(row["src_type"]), str(row["dst_type"]),
                str(row["src_semantic"]), str(row["dst_semantic"]),
                row["data_size"],
            )
    missing = set(requested) - found.keys()
    if missing:
        sample = sorted(missing)[:5]
        raise ValueError(f"K6 identities missing from database: {sample}")
    return tuple(
        sorted(found.values(), key=lambda edge: (edge.timestamp_ns, edge.edge_id))
    )


def _require_pinned(path: str | Path, expected_sha256: str) -> Path:
    source = Path(path).resolve()
    if not source.is_file() or _file_sha(source) != expected_sha256:
        raise ValueError(f"pinned input changed: {source}")
    return source


def _path_record(edge: StoredEdge) -> dict[str, Any]:
    return {
        "edge_id": edge.edge_id,
        "event_id": edge.event_id,
        "src": edge.src,
        "dst": edge.dst,
        "relation": edge.relation,
        "timestamp_ns": edge.timestamp_ns,
    }


def _aggregate_selector(rows: Sequence[Mapping[str, Any]], selector: str) -> dict[str, Any]:
    def aggregate_bins(path: tuple[str, ...]) -> dict[str, Any]:
        names = rows[0][selector]["evaluation"]
        for part in path:
            names = names[part]
        aggregated: dict[str, Any] = {}
        for name in names:
            values = []
            for row in rows:
                value = row[selector]["evaluation"]
                for part in path:
                    value = value[part]
                values.append(value[name])
            eligible = sum(value["eligible_paths"] for value in values)
            exact = sum(value["canonical_complete_paths"] for value in values)
            reachable = sum(value["strict_reachable_pairs"] for value in values)
            aggregated[name] = {
                "eligible_paths": eligible,
                "canonical_complete_paths": exact,
                "strict_reachable_pairs": reachable,
                "canonical_path_retention": exact / eligible if eligible else None,
                "strict_temporal_reachability_retention": (
                    reachable / eligible if eligible else None
                ),
            }
        return aggregated

    family_names = ("backward_path", "forward_path", "poi_to_poi_path", "anomaly_path")
    families: dict[str, Any] = {}
    for family in family_names:
        eligible = sum(row[selector]["evaluation"]["path_families"][family]["eligible_paths"] for row in rows)
        exact = sum(row[selector]["evaluation"]["path_families"][family]["canonical_complete_paths"] for row in rows)
        reachable = sum(row[selector]["evaluation"]["path_families"][family]["strict_reachable_pairs"] for row in rows)
        families[family] = {
            "eligible_paths": eligible,
            "canonical_complete_paths": exact,
            "strict_reachable_pairs": reachable,
            "canonical_path_retention": exact / eligible if eligible else None,
            "strict_temporal_reachability_retention": reachable / eligible if eligible else None,
        }
    reference_edges = sum(row[selector]["evaluation"]["contexts_aligned"]["reference_subgraph_edges"] for row in rows)
    tp = sum(row[selector]["evaluation"]["contexts_aligned"]["tp"] for row in rows)
    reference_nodes = sum(
        row[selector]["evaluation"]["contexts_aligned"]["reference_subgraph_nodes"]
        for row in rows
    )
    node_tp = sum(
        row[selector]["evaluation"]["contexts_aligned"]["node_tp"] for row in rows
    )
    return {
        "raw_events": sum(row[selector]["raw_events"] for row in rows),
        "projected_edges": sum(row[selector]["projected_edges"] for row in rows),
        "selector_seconds": sum(row[selector]["selector_seconds"] for row in rows),
        "reference_subgraph_edges": reference_edges,
        "tp": tp,
        "tpr": tp / reference_edges if reference_edges else None,
        "reference_subgraph_nodes": reference_nodes,
        "node_tp": node_tp,
        "node_tpr": node_tp / reference_nodes if reference_nodes else None,
        "path_families": families,
        "time_path": {
            "by_time_interval": aggregate_bins(("time_path", "by_time_interval")),
            "by_path_length": aggregate_bins(("time_path", "by_path_length")),
        },
        "anomaly_time": aggregate_bins(("anomaly_time",)),
        "fp": None,
        "fpr": None,
        "precision": None,
        "negative_label_status": "NOT_AVAILABLE_PARTIAL_POSITIVE_GT",
    }


def run_kairos_k6_poi_comparison(
    config: Mapping[str, Any], output_path: str | Path
) -> dict[str, Any]:
    """Execute and seal the three-scenario oracle-assisted comparison."""
    if config.get("schema_version") != SCHEMA_VERSION or config.get("dataset") != DATASET:
        raise ValueError("invalid KAIROS K6 POI comparison config")
    database_spec = config.get("database", {})
    database = _require_pinned(database_spec["path"], database_spec["sha256"])
    projection_spec = config.get("projection", {})
    projection = EdgeProjection(
        projection_spec["mode"], int(projection_spec["merge_window_ns"])
    )
    raw_event_cap = int(config.get("raw_event_cap", 0))
    candidate_config = CandidateSearchConfig(**dict(config.get("candidate", {})))
    scenario_specs = config.get("scenarios", [])
    if tuple(str(row.get("scenario")).zfill(2) for row in scenario_specs) != SCENARIOS:
        raise ValueError("comparison requires scenarios 06, 12, and 13 in order")

    result_rows: list[dict[str, Any]] = []
    unique_truth: set[str] = set()
    unique_pois: set[str] = set()
    with ProvenanceStore(database) as store:
        cache_meta = dict(
            store.conn.execute("SELECT key,value FROM frequency_cache_meta")
        )
        if cache_meta.get("stale") != "0" or int(
            cache_meta.get("source_edges", -1)
        ) != store.edge_count():
            raise ValueError("frequency cache is stale or does not cover the frozen database")
        frequency_model = FrequencyModel.from_cache(store)
        for spec in scenario_specs:
            scenario = str(spec["scenario"]).zfill(2)
            online_path = _require_pinned(spec["kairos_online"], spec["kairos_sha256"])
            online = json.loads(online_path.read_text(encoding="utf-8"))
            if str(online.get("scenario")).zfill(2) != scenario or online.get("track") != "B":
                raise ValueError("KAIROS input must be the matching frozen Track-B artifact")
            layers = online.get("kairos_ablations", {})
            if "K6" not in layers or not layers["K6"].get("event_ids"):
                raise ValueError("KAIROS input lacks a nonempty K6 layer")
            k6_edges = _load_edges(store, layers["K6"]["event_ids"])

            # Offline oracle-assisted POI derivation starts only after the K6
            # alert set and exact database identities have been frozen above.
            truth_path = _require_pinned(spec["orthrus_csv"], spec["orthrus_sha256"])
            truth = load_orthrus_groundtruth(truth_path)
            truth_fold = {str(node).casefold(): str(node) for node in truth["node_ids"]}
            k6_nodes = {
                endpoint.casefold()
                for edge in k6_edges
                for endpoint in (edge.src, edge.dst)
            }
            poi_fold = k6_nodes & truth_fold.keys()
            if not poi_fold:
                raise ValueError(f"K6 recovered no ORTHRUS attack node in scenario {scenario}")
            poi_ids = {truth_fold[node] for node in poi_fold}
            unique_truth.update(truth_fold)
            unique_pois.update(poi_fold)
            priority = tuple(
                frozenset(map(str, layers[name]["event_ids"]))
                for name in ("K1", "K0", "K2", "K3", "K4", "K5", "K6")
                if name in layers
            )
            # K6 is the alert source, not the candidate graph.  Still, each
            # K6-derived POI needs one immutable incident alert witness so a
            # saturated candidate cannot silently erase that POI before the
            # two selectors receive their common input.
            k6_proxy_ids, _ = select_poi_proxies(
                k6_edges, poi_ids, layer_priority=priority
            )
            if len(k6_proxy_ids) > candidate_config.candidate_cap:
                raise ValueError("candidate cap is smaller than mandatory K6 POI witnesses")
            node_evidence = tuple(
                AlertEvidence(
                    evidence_id=f"KAIROS-K6:{scenario}:{node}",
                    detector_id="KAIROS",
                    detector_version="K6",
                    granularity=EvidenceGranularity.NODE,
                    raw_score=None,
                    calibrated_score=1.0,
                    native_decision=True,
                    node_ids=(node,),
                    role_hint=RoleHint.OBSERVATION,
                    mapping_quality=MappingQuality.EXACT,
                    detector_metadata={"layer": "K6", "scenario": scenario},
                )
                for node in sorted(poi_ids)
            )
            event_evidence = tuple(
                AlertEvidence(
                    evidence_id=f"KAIROS-K6:{scenario}:event:{event_id}",
                    detector_id="KAIROS",
                    detector_version="K6",
                    granularity=EvidenceGranularity.EVENT,
                    raw_score=None,
                    calibrated_score=1.0,
                    native_decision=True,
                    event_ids=(event_id,),
                    role_hint=RoleHint.OBSERVATION,
                    mapping_quality=MappingQuality.EXACT,
                    detector_metadata={"layer": "K6", "scenario": scenario},
                )
                for event_id in sorted(k6_proxy_ids)
            )
            evidence = event_evidence + node_evidence
            candidate_started = time.perf_counter()
            candidate = EvidenceDrivenCandidateBuilder(
                store, candidate_config
            ).build(evidence)
            candidate_seconds = time.perf_counter() - candidate_started
            if not candidate.edges:
                raise ValueError(
                    f"POI candidate reconstruction is empty in scenario {scenario}"
                )
            selector_result = run_selectors(
                store=store,
                edges=candidate.edges,
                poi_node_ids=poi_ids,
                raw_event_cap=raw_event_cap,
                projection=projection,
                layer_priority=priority,
                frequency_model=frequency_model,
                branch_provenance=candidate.branch_provenance,
            )
            edge_records = tuple(map(_path_record, candidate.edges))
            row: dict[str, Any] = {
                "scenario": scenario,
                "inputs": {
                    "kairos_online": str(online_path),
                    "kairos_sha256": spec["kairos_sha256"],
                    "orthrus_csv": str(truth_path),
                    "orthrus_sha256": spec["orthrus_sha256"],
                },
                "k6": {
                    "raw_events": len(k6_edges),
                    "projected_edges": int(
                        layers["K6"].get(
                            "projected_edge_count", projection.count(k6_edges)
                        )
                    ),
                    "attack_nodes_found": len(poi_ids),
                    "attack_nodes_total": len(truth_fold),
                    "attack_node_recall": len(poi_ids) / len(truth_fold),
                    "poi_node_ids": sorted(poi_ids),
                },
                "candidate": {
                    "raw_events": len(candidate.edges),
                    "projected_edges": projection.count(candidate.edges),
                    "nodes": len(candidate.node_ids),
                    "seconds": candidate_seconds,
                    "stop_reason": candidate.stop_reason,
                    "event_ids_sha256": selector_result[
                        "candidate_event_ids_sha256"
                    ],
                },
                "proxy_event_ids": selector_result["proxy_event_ids"],
                "proxy_audit": selector_result["proxy_audit"],
                "candidate_event_ids_sha256": selector_result["candidate_event_ids_sha256"],
                "peak_rss_kb": selector_result["peak_rss_kb"],
            }
            for selector in ("A_rasp", "C_branch_fair"):
                selection = dict(selector_result[selector])
                selection["evaluation"] = evaluate_poi_scoped_retention(
                    candidate_edges=edge_records,
                    selected_event_ids=set(selection["selected_raw_event_ids"]),
                    groundtruth_node_ids=set(truth["node_ids"]),
                    poi_node_ids=poi_ids,
                )
                row[selector] = selection
            result_rows.append(row)

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": "COMPLETED",
        "dataset": DATASET,
        "detector": "KAIROS",
        "detector_layer": "K6",
        "poi_policy": "K6 endpoints intersected with ORTHRUS positives; offline oracle-assisted",
        "groundtruth_completeness": "PARTIAL_POSITIVE_NODE_GT",
        "database": {"path": str(database), "sha256": database_spec["sha256"]},
        "config_sha256": _digest(config),
        "raw_event_cap": raw_event_cap,
        "candidate": dict(config["candidate"]),
        "projection": projection_spec,
        "frequency_cache": {
            "version": cache_meta.get("version"),
            "source_edges": int(cache_meta["source_edges"]),
            "stale": cache_meta["stale"],
        },
        "scenarios": result_rows,
        "aggregate": {
            "scenario_annotation_count": sum(row["k6"]["attack_nodes_total"] for row in result_rows),
            "unique_attack_nodes": len(unique_truth),
            "scenario_poi_hit_count": sum(row["k6"]["attack_nodes_found"] for row in result_rows),
            "unique_poi_nodes": len(unique_pois),
            "kairos_k6": {
                "raw_events": sum(row["k6"]["raw_events"] for row in result_rows),
                "projected_edges": sum(
                    row["k6"]["projected_edges"] for row in result_rows
                ),
            },
            "common_candidate": {
                "raw_events": sum(
                    row["candidate"]["raw_events"] for row in result_rows
                ),
                "projected_edges": sum(
                    row["candidate"]["projected_edges"] for row in result_rows
                ),
                "seconds": sum(
                    row["candidate"]["seconds"] for row in result_rows
                ),
                "peak_rss_kb": max(row["peak_rss_kb"] for row in result_rows),
            },
            "A_rasp": _aggregate_selector(result_rows, "A_rasp"),
            "C_branch_fair": _aggregate_selector(result_rows, "C_branch_fair"),
        },
    }
    _atomic_json(Path(output_path), payload)
    return json.loads(Path(output_path).read_text(encoding="utf-8"))


__all__ = [
    "run_kairos_k6_poi_comparison",
    "run_selectors",
    "select_poi_proxies",
]
