"""Offline-only explanation of scenario-13 C evidence absent from A_rasp."""
from __future__ import annotations

from typing import Any, Mapping, Sequence

from .models import StoredEdge
from .pbr import _index, _strict_paths


def audit_scenario13_bridges(
    *,
    candidate_edges: Sequence[StoredEdge],
    a_selected_event_ids: frozenset[str],
    c_selected_event_ids: frozenset[str],
    evaluation: Mapping[str, Any],
    poi_node_ids: frozenset[str],
    a_evidence: Mapping[str, Mapping[str, float]],
    c_relevance: Mapping[str, float],
    branch_provenance: Mapping[str, tuple[str, ...]],
) -> dict[str, Any]:
    """Explain frozen C-minus-A reference evidence; never used by online PBR."""
    paths = tuple(evaluation.get("paths", ()))
    reference = {str(event) for path in paths for event in path.get("event_ids", ())}
    event_ids = sorted((c_selected_event_ids - a_selected_event_ids) & reference)
    by_event = {edge.event_id: edge for edge in candidate_edges}
    outgoing, _ = _index(candidate_edges)
    records = []
    for event_id in event_ids:
        edge = by_event[event_id]
        memberships = [path for path in paths if event_id in path.get("event_ids", ())]
        lost: list[str] = []
        alternative_count = 0
        minimum_alternative_cost: float | None = None
        for path in memberships:
            source, target = str(path["source"]), str(path["target"])
            alternatives = _strict_paths(
                outgoing, source, target, costs={}, k=10, max_events=12,
                max_states=20_000, banned=frozenset({event_id}),
            )
            alternative_count += len(alternatives)
            if not alternatives:
                lost.append(f"{source}->{target}")
            else:
                cost = alternatives[0].cost
                minimum_alternative_cost = cost if minimum_alternative_cost is None else min(minimum_alternative_cost, cost)
        evidence = a_evidence.get(event_id, {})
        records.append({
            "raw_event_id": event_id,
            "src": edge.src,
            "dst": edge.dst,
            "relation": edge.relation,
            "timestamp_ns": edge.timestamp_ns,
            "a_rasp": {
                "rarity": float(evidence.get("rarity", 0.0)),
                "ppr": float(evidence.get("ppr", 0.0)),
                "lift": float(evidence.get("lift", 0.0)),
                "path_score": float(evidence.get("path_score", 0.0)),
            },
            "c_branch_fair": {
                "relevance": float(c_relevance.get(event_id, 0.0)),
                "branch_provenance": list(branch_provenance.get(event_id, ())),
            },
            "poi_to_poi_path": any(
                path.get("family") == "poi_to_poi_path"
                and str(path.get("source")) in poi_node_ids
                and str(path.get("target")) in poi_node_ids
                for path in memberships
            ),
            "reference_path_pairs": sorted(
                f"{path['source']}->{path['target']}" for path in memberships
            ),
            "lost_poi_demands_without_event": sorted(lost),
            "alternative_path_count": alternative_count,
            "minimum_alternative_cost": minimum_alternative_cost,
        })
    return {
        "schema_version": "scenario13-bridge-audit-v1",
        "scenario": "13",
        "offline_only": True,
        "may_feed_online_selector": False,
        "c_only_reference_event_count": len(records),
        "events": records,
    }


def render_audit_markdown(audit: Mapping[str, Any]) -> str:
    lines = [
        "# Scenario 13 Bridge Audit",
        "",
        "Offline explanation only; this artifact must not feed A_rasp-PBR.",
        "",
        "| Event | Relation | POI→POI | Lost demands | Alternatives |",
        "|---|---|---:|---:|---:|",
    ]
    for row in audit.get("events", ()):
        lines.append(
            f"| `{row['raw_event_id']}` | {row['relation']} | "
            f"{'yes' if row['poi_to_poi_path'] else 'no'} | "
            f"{len(row['lost_poi_demands_without_event'])} | "
            f"{row['alternative_path_count']} |"
        )
    lines.append("")
    return "\n".join(lines)


__all__ = ["audit_scenario13_bridges", "render_audit_markdown"]
