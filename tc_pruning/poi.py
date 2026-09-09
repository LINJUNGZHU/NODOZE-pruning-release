from __future__ import annotations

import json
from dataclasses import asdict, dataclass
import math
from pathlib import Path

from .nodoze import NODOZEFrequencyModel
from .store import ProvenanceStore


@dataclass(frozen=True, slots=True)
class POIGroup:
    group_id: str
    event_ids: tuple[str, ...]
    window_start_ns: int | None = None
    window_end_ns: int | None = None


@dataclass(frozen=True, slots=True)
class POIManifest:
    event_ids: tuple[str, ...]
    groups: tuple[POIGroup, ...]


def _ordered_unique(values: object, *, label: str) -> tuple[str, ...]:
    if not isinstance(values, list):
        raise ValueError(f"{label} must be an array")
    result: list[str] = []
    seen: set[str] = set()
    for raw_value in values:
        value = str(raw_value).strip()
        if value and value not in seen:
            result.append(value)
            seen.add(value)
    return tuple(result)


def load_poi_manifest(path: str | Path) -> POIManifest:
    source = Path(path)
    # Windows PowerShell 5 writes a UTF-8 BOM for ``Out-File -Encoding utf8``.
    # utf-8-sig accepts that form while remaining compatible with plain UTF-8.
    text = source.read_text(encoding="utf-8-sig")
    if source.suffix.lower() == ".json":
        raw = json.loads(text)
        if isinstance(raw, list):
            event_ids = _ordered_unique(raw, label="POI JSON")
            groups_raw = None
        elif isinstance(raw, dict):
            event_ids_raw = raw.get("event_ids", [])
            event_ids = _ordered_unique(event_ids_raw, label="event_ids")
            groups_raw = raw.get("seed_event_groups")
        else:
            raise ValueError("POI JSON must be an array or object")
    else:
        event_ids = _ordered_unique([
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ], label="POI text")
        groups_raw = None

    groups: list[POIGroup] = []
    flattened: list[str] = []
    if groups_raw is not None:
        if not isinstance(groups_raw, list) or not groups_raw:
            raise ValueError("seed_event_groups must be a non-empty array")
        seen_group_ids: set[str] = set()
        for index, group_raw in enumerate(groups_raw):
            if not isinstance(group_raw, dict):
                raise ValueError("each seed_event_groups item must be an object")
            group_id = str(group_raw.get("group_id", f"group-{index + 1}")).strip()
            if not group_id:
                raise ValueError("group_id must not be empty")
            if group_id in seen_group_ids:
                raise ValueError(f"duplicate group_id: {group_id}")
            seen_group_ids.add(group_id)
            group_event_ids = _ordered_unique(
                group_raw.get("seed_event_ids"), label="seed_event_ids"
            )
            if not group_event_ids:
                raise ValueError(f"seed group {group_id} has no event IDs")
            start_raw = group_raw.get("window_start_ns")
            end_raw = group_raw.get("window_end_ns")
            if (start_raw is None) != (end_raw is None):
                raise ValueError(
                    "both window_start_ns and window_end_ns must be supplied"
                )
            start_ns = int(start_raw) if start_raw is not None else None
            end_ns = int(end_raw) if end_raw is not None else None
            if start_ns is not None and end_ns is not None and end_ns < start_ns:
                raise ValueError("window_end_ns must be greater than or equal to window_start_ns")
            groups.append(POIGroup(group_id, group_event_ids, start_ns, end_ns))
            flattened.extend(group_event_ids)

        flattened_ids = _ordered_unique(flattened, label="seed_event_groups")
        if event_ids and set(event_ids) != set(flattened_ids):
            raise ValueError("event_ids must match the IDs in seed_event_groups")
        if not event_ids:
            event_ids = flattened_ids

    if not event_ids:
        raise ValueError(f"no POI event IDs found in {source}")
    if not groups:
        groups.append(POIGroup("all-pois", event_ids))
    return POIManifest(event_ids, tuple(groups))


def load_poi_event_ids(path: str | Path) -> list[str]:
    """Load POIs using the historical sorted-list interface."""
    return sorted(load_poi_manifest(path).event_ids)


@dataclass(frozen=True, slots=True)
class SelectedPOI:
    event_id: str
    src: str
    dst: str
    relation: str
    timestamp_ns: int
    score: float
    components: dict[str, float]


@dataclass(frozen=True, slots=True)
class POISelection:
    event_ids: tuple[str, ...]
    selected: tuple[SelectedPOI, ...]
    source_kind: str
    oracle_derived: bool
    policy: str = "depimpact_downstream_multi_terminal_v1"

    def to_dict(self) -> dict:
        return {
            "event_ids": list(self.event_ids),
            "metadata": {
                "policy": self.policy,
                "source_kind": self.source_kind,
                "oracle_derived": self.oracle_derived,
                "warning": (
                    "POIs are derived from evaluation ground truth and measure pruning, not detection"
                    if self.oracle_derived
                    else None
                ),
            },
            "selected": [asdict(item) for item in self.selected],
        }


def load_candidate_event_ids(path: str | Path) -> set[str]:
    raw = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if isinstance(raw, list):
        values = raw
    elif isinstance(raw, dict):
        values = (
            raw.get("attack_event_ids")
            or raw.get("event_ids")
            or raw.get("seed_event_ids")
        )
    else:
        values = None
    if not isinstance(values, list) or not values:
        raise ValueError("candidate manifest must contain attack_event_ids or event_ids")
    return {str(value) for value in values}


def select_poi_events(
    store: ProvenanceStore,
    candidate_event_ids: set[str] | list[str] | tuple[str, ...],
    model: NODOZEFrequencyModel,
    *,
    max_pois: int = 5,
    source_kind: str = "detector",
) -> POISelection:
    """Choose diverse downstream symptoms suitable for DEPIMPACT tracing."""
    if max_pois <= 0:
        raise ValueError("max_pois must be positive")
    if source_kind not in {"detector", "groundtruth"}:
        raise ValueError("source_kind must be detector or groundtruth")
    edges = [
        edge
        for event_id in sorted(set(candidate_event_ids))
        if (edge := store.get_edge_by_event_id(event_id)) is not None
    ]
    if not edges:
        raise ValueError("none of the candidate events exist in the database")
    minimum_time = min(edge.timestamp_ns for edge in edges)
    maximum_time = max(edge.timestamp_ns for edge in edges)
    span = max(1, maximum_time - minimum_time)
    max_log_size = max(
        (math.log1p(edge.data_size) for edge in edges if edge.data_size is not None),
        default=0.0,
    )
    ordered_edges = sorted(edges, key=lambda item: (item.timestamp_ns, item.edge_id))
    episode_by_edge: dict[int, int] = {}
    episode = 0
    previous_time: int | None = None
    episode_gap_ns = 30 * 1_000_000_000
    for edge in ordered_edges:
        if previous_time is not None and edge.timestamp_ns - previous_time > episode_gap_ns:
            episode += 1
        episode_by_edge[edge.edge_id] = episode
        previous_time = edge.timestamp_ns
    downstream_counts = {
        edge.edge_id: sum(
            other.src == edge.dst and other.timestamp_ns >= edge.timestamp_ns
            for other in edges
            if other.edge_id != edge.edge_id
            and episode_by_edge[other.edge_id] == episode_by_edge[edge.edge_id]
        )
        for edge in edges
    }
    ranked: list[SelectedPOI] = []
    for edge in edges:
        downstream = downstream_counts[edge.edge_id]
        relation_upper = edge.relation.upper()
        relation_relevance = (
            1.0
            if any(
                token in relation_upper
                for token in ("WRITE", "SEND", "EXEC", "CREATE", "CONNECT", "RENAME")
            )
            else 0.5
            if any(token in relation_upper for token in ("READ", "RECV", "ACCEPT"))
            else 0.0
        )
        components = {
            "rarity": model.edge_anomaly(edge),
            "terminality": 1.0 if downstream == 0 else 0.0,
            "sinkness": 1.0 / (1.0 + downstream),
            "data_flow": (
                math.log1p(edge.data_size) / max_log_size
                if edge.data_size is not None and max_log_size > 0.0
                else 0.0
            ),
            "temporal_rank": (edge.timestamp_ns - minimum_time) / span,
            "relation_relevance": relation_relevance,
            "episode": float(episode_by_edge[edge.edge_id]),
        }
        score = (
            0.35 * components["rarity"]
            + 0.30 * components["terminality"]
            + 0.20 * components["sinkness"]
            + 0.10 * components["data_flow"]
            + 0.03 * components["temporal_rank"]
            + 0.02 * components["relation_relevance"]
        )
        ranked.append(
            SelectedPOI(
                edge.event_id, edge.src, edge.dst, edge.relation,
                edge.timestamp_ns, score, components,
            )
        )
    ranked.sort(key=lambda item: (-item.score, -item.timestamp_ns, item.event_id))
    terminal_ranked = [
        item
        for item in ranked
        if item.components["terminality"] == 1.0
        and item.components["relation_relevance"] >= 1.0
    ]
    if terminal_ranked:
        ranked = terminal_ranked
    selected: list[SelectedPOI] = []
    destinations: set[str] = set()
    episode_destinations: set[tuple[int, str]] = set()
    # First cover different downstream entities (NODLINK-style terminal
    # diversity), then add later attack episodes for already-seen entities.
    for item in ranked:
        if item.dst in destinations:
            continue
        diversity_key = (int(item.components["episode"]), item.dst)
        selected.append(item)
        destinations.add(item.dst)
        episode_destinations.add(diversity_key)
        if len(selected) == max_pois:
            break
    if len(selected) < max_pois:
        chosen = {item.event_id for item in selected}
        for item in ranked:
            diversity_key = (int(item.components["episode"]), item.dst)
            if item.event_id in chosen or diversity_key in episode_destinations:
                continue
            selected.append(item)
            episode_destinations.add(diversity_key)
            if len(selected) == max_pois:
                break
    return POISelection(
        tuple(item.event_id for item in selected),
        tuple(selected),
        source_kind,
        source_kind == "groundtruth",
    )


__all__ = [
    "POIGroup",
    "POIManifest",
    "POISelection",
    "SelectedPOI",
    "load_candidate_event_ids",
    "load_poi_event_ids",
    "load_poi_manifest",
    "select_poi_events",
]
