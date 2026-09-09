from __future__ import annotations

import ast
import csv
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from .store import ProvenanceStore
from .nodoze import NODOZEFrequencyModel
from .poi import select_poi_events
from .frequency_cache import FrequencyCache


EASTERN = ZoneInfo("America/New_York")


@dataclass(frozen=True, slots=True)
class UBCCadetsScenario:
    code: str
    filename: str
    start: str
    end: str

    def bounds_ns(self) -> tuple[int, int]:
        def parse(value: str) -> int:
            localized = datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=EASTERN
            )
            return int(localized.timestamp() * 1_000_000_000)

        return parse(self.start), parse(self.end)


CADETS_E3_SCENARIOS = {
    "06": UBCCadetsScenario(
        "06",
        "node_Nginx_Backdoor_06.csv",
        "2018-04-06 11:20:00",
        "2018-04-06 12:09:00",
    ),
    "12": UBCCadetsScenario(
        "12",
        "node_Nginx_Backdoor_12.csv",
        "2018-04-12 13:59:00",
        "2018-04-12 14:39:00",
    ),
    "13": UBCCadetsScenario(
        "13",
        "node_Nginx_Backdoor_13.csv",
        "2018-04-13 09:03:00",
        "2018-04-13 09:16:00",
    ),
}


def _poi_groups(event_ids: list[str]) -> list[dict[str, object]]:
    return [
        {"group_id": f"poi:{event_id}", "seed_event_ids": [event_id]}
        for event_id in event_ids
    ]


def _resolve_cadets_directory(path: str | Path) -> Path:
    root = Path(path)
    candidates = (root, root / "E3-CADETS", root / "darpa" / "E3-CADETS")
    for candidate in candidates:
        if all((candidate / item.filename).is_file() for item in CADETS_E3_SCENARIOS.values()):
            return candidate
    if root.is_dir():
        return root
    raise FileNotFoundError(f"UBC ground-truth directory does not exist: {root}")


def _read_labels(path: Path) -> tuple[list[str], dict[str, dict]]:
    uuids: list[str] = []
    attributes: dict[str, dict] = {}
    with path.open("r", newline="", encoding="utf-8") as stream:
        for row_number, row in enumerate(csv.reader(stream), start=1):
            if len(row) < 2:
                raise ValueError(f"{path}:{row_number}: expected at least two CSV columns")
            node_uuid = row[0].strip()
            if not node_uuid:
                raise ValueError(f"{path}:{row_number}: empty UUID")
            try:
                parsed = ast.literal_eval(row[1])
            except (SyntaxError, ValueError) as exc:
                raise ValueError(f"{path}:{row_number}: invalid attributes dictionary") from exc
            if not isinstance(parsed, dict):
                raise ValueError(f"{path}:{row_number}: attributes must be a dictionary")
            uuids.append(node_uuid)
            attributes[node_uuid.upper()] = parsed
    return sorted(set(uuids), key=str.upper), attributes


def _scenario_manifest(
    store: ProvenanceStore,
    groundtruth_dir: Path,
    scenario: UBCCadetsScenario,
    external_poi_event_ids: tuple[str, ...] | None = None,
) -> dict:
    source = groundtruth_dir / scenario.filename
    if not source.is_file():
        raise FileNotFoundError(f"missing UBC ground-truth file: {source}")
    groundtruth_ids, raw_attributes = _read_labels(source)
    source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
    start_ns, end_ns = scenario.bounds_ns()

    store.conn.execute("DROP TABLE IF EXISTS temp.ubc_groundtruth_ids")
    store.conn.execute(
        "CREATE TEMP TABLE ubc_groundtruth_ids("
        "uuid TEXT PRIMARY KEY COLLATE NOCASE)"
    )
    store.conn.executemany(
        "INSERT OR IGNORE INTO ubc_groundtruth_ids VALUES (?)",
        ((node_uuid,) for node_uuid in groundtruth_ids),
    )
    attack_nodes = sorted(
        row[0]
        for row in store.conn.execute(
            """
            SELECT n.uuid
            FROM ubc_groundtruth_ids g
            JOIN nodes n ON n.uuid=g.uuid COLLATE NOCASE
            """
        )
    )
    attack_edges = list(
        store.conn.execute(
            """
            SELECT e.event_id, e.src, e.dst, e.timestamp_ns
            FROM edges e INDEXED BY idx_edges_time
            JOIN ubc_groundtruth_ids source ON source.uuid=e.src COLLATE NOCASE
            JOIN ubc_groundtruth_ids destination ON destination.uuid=e.dst COLLATE NOCASE
            WHERE e.timestamp_ns BETWEEN ? AND ?
            ORDER BY e.timestamp_ns, e.id
            """,
            (start_ns, end_ns),
        )
    )
    store.conn.execute("DROP TABLE temp.ubc_groundtruth_ids")
    if not attack_edges:
        raise ValueError(
            f"UBC scenario {scenario.code} has no internal attack event in its "
            "documented time window"
        )

    candidate_event_ids = {row[0] for row in attack_edges}
    if external_poi_event_ids:
        seed_event_ids = list(dict.fromkeys(external_poi_event_ids))
        selected_pois = []
        missing: list[str] = []
        outside: list[str] = []
        outside_truth: list[str] = []
        for event_id in seed_event_ids:
            edge = store.get_edge_by_event_id(event_id)
            if edge is None:
                missing.append(event_id)
            elif not start_ns <= edge.timestamp_ns <= end_ns:
                outside.append(event_id)
            elif event_id not in candidate_event_ids:
                outside_truth.append(event_id)
            else:
                selected_pois.append(edge)
        if missing:
            raise ValueError(f"external POIs are missing from the database: {missing}")
        if outside:
            raise ValueError(
                f"external POIs are outside the UBC {scenario.code} attack window: {outside}"
            )
        if outside_truth:
            raise ValueError(
                "external POIs are not internal events between UBC core attack nodes: "
                f"{outside_truth}"
            )
        frequency_source = "not_used_for_ordered_analyst_pois"
        poi_selection_document = {
            "event_ids": seed_event_ids,
            "metadata": {
                "policy": "ordered_analyst_pois_from_darpa_report",
                "source_kind": "analyst_report",
                "oracle_derived": True,
            },
            "selected": [
                {
                    "event_id": edge.event_id,
                    "src": edge.src,
                    "dst": edge.dst,
                    "relation": edge.relation,
                    "timestamp_ns": edge.timestamp_ns,
                }
                for edge in selected_pois
            ],
        }
    else:
        try:
            FrequencyCache(store).require()
            frequency_model = NODOZEFrequencyModel.from_cache(
                store, before_timestamp_ns=min(row[3] for row in attack_edges)
            )
            frequency_source = "offline_daily_frequency_cache"
        except RuntimeError:
            frequency_model = NODOZEFrequencyModel.from_store(
                store, before_timestamp_ns=min(row[3] for row in attack_edges)
            )
            frequency_source = "raw_event_scan_for_manifest_preparation"
        poi_selection = select_poi_events(
            store,
            candidate_event_ids,
            frequency_model,
            max_pois=3,
            source_kind="groundtruth",
        )
        selected_pois = list(poi_selection.selected)
        seed_event_ids = [item.event_id for item in selected_pois]
        poi_selection_document = poi_selection.to_dict()
    seed_nodes = sorted({endpoint for item in selected_pois for endpoint in (item.src, item.dst)})

    stored_edges = [
        edge for event_id in candidate_event_ids
        if (edge := store.get_edge_by_event_id(event_id)) is not None
    ]
    incoming: dict[str, list] = {}
    indegree = {node: 0 for node in attack_nodes}
    for edge in stored_edges:
        incoming.setdefault(edge.dst, []).append(edge)
        indegree[edge.dst] = indegree.get(edge.dst, 0) + 1
    entries = {node for node, degree in indegree.items() if degree == 0}
    attack_paths: list[list[str]] = []
    for poi in selected_pois:
        path = [poi.event_id]
        node, anchor = poi.src, poi.timestamp_ns
        seen = {node}
        while node not in entries:
            choices = [
                edge for edge in incoming.get(node, [])
                if edge.timestamp_ns <= anchor and edge.src not in seen
            ]
            if not choices:
                break
            predecessor = max(choices, key=lambda edge: (edge.timestamp_ns, edge.edge_id))
            path.append(predecessor.event_id)
            node, anchor = predecessor.src, predecessor.timestamp_ns
            seen.add(node)
        attack_paths.append(list(reversed(path)))
    return {
        "name": f"DARPA TC E3 CADETS UBC core attack {scenario.code}",
        "seed_event_ids": seed_event_ids,
        "seed_event_groups": (
            [{
                "group_id": f"ubc-{scenario.code}-pdf-incident",
                "seed_event_ids": seed_event_ids,
                "window_start_ns": start_ns,
                "window_end_ns": end_ns,
            }]
            if external_poi_event_ids else _poi_groups(seed_event_ids)
        ),
        "seed_uuids": seed_nodes,
        "attack_paths": attack_paths,
        "attack_event_ids": sorted({row[0] for row in attack_edges}),
        "attack_node_uuids": attack_nodes,
        "attack_node_attributes": {
            node_uuid: raw_attributes.get(node_uuid.upper(), {})
            for node_uuid in attack_nodes
        },
        "metadata": {
            "groundtruth_source": str(source),
            "groundtruth_source_sha256": source_sha256,
            "groundtruth_family": "ubc-provenance/ground-truth",
            "groundtruth_source_semantics": (
                "manually reviewed malicious entity UUIDs; event labels are "
                "derived from database events between two labeled entities"
            ),
            "label_scope": "UBC manually reviewed core attack nodes",
            "scenario": scenario.code,
            "timezone": "America/New_York",
            "attack_window_start": scenario.start,
            "attack_window_end": scenario.end,
            "attack_window_start_ns": start_ns,
            "attack_window_end_ns": end_ns,
            "groundtruth_uuid_count": len(groundtruth_ids),
            "matched_attack_node_count": len(attack_nodes),
            "derived_attack_event_count": len(attack_edges),
            "attack_event_rule": (
                "event occurs inside the UBC scenario time window and both "
                "endpoints are UBC core attack nodes"
            ),
            "seed_rule": (
                "ordered analyst POIs from DARPA report"
                if external_poi_event_ids
                else "top diverse downstream POIs ranked independently inside this scenario"
            ),
            "poi_selection_scope": "per_scenario",
            "poi_selection": poi_selection_document,
            "frequency_source": frequency_source,
            "path_rule": "time-respecting UBC-core entry-to-POI event path",
            "path_quality": "derived_from_manually_reviewed_UBC_core_nodes_not_manual_edge_labels",
            "warning": (
                "seed event is a groundtruth-derived oracle alert; use an independent "
                "detector such as Orthrus for end-to-end alert evaluation"
            ),
        },
    }


def prepare_ubc_manifests(
    store: ProvenanceStore,
    groundtruth_dir: str | Path,
    *,
    output_dir: str | Path,
    scenario: str = "all",
    poi_event_ids: tuple[str, ...] | list[str] | None = None,
) -> list[dict]:
    if scenario != "all" and scenario not in CADETS_E3_SCENARIOS:
        choices = ", ".join([*CADETS_E3_SCENARIOS, "all"])
        raise ValueError(f"unknown UBC CADETS E3 scenario {scenario!r}; choose {choices}")
    if poi_event_ids and scenario == "all":
        raise ValueError("external POIs require one explicit UBC scenario")
    source_dir = _resolve_cadets_directory(groundtruth_dir)
    selected = (
        list(CADETS_E3_SCENARIOS.values())
        if scenario == "all"
        else [CADETS_E3_SCENARIOS[scenario]]
    )
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    manifests = []
    for item in selected:
        manifest = _scenario_manifest(
            store, source_dir, item,
            tuple(poi_event_ids) if poi_event_ids else None,
        )
        output = destination / f"cadets-e3-ubc-{item.code}-annotations.json"
        output.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        manifests.append(manifest)
    return manifests


__all__ = ["CADETS_E3_SCENARIOS", "UBCCadetsScenario", "prepare_ubc_manifests"]
