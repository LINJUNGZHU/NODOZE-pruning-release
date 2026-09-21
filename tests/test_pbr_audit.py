from __future__ import annotations

from tc_pruning.models import StoredEdge


def e(number, event, src, dst, time, relation="EVENT_WRITE",
      src_type="process", dst_type="file"):
    return StoredEdge(number, event, src, dst, relation, time, "h", src_type, dst_type)


def read(number, event, src, dst, time):
    return e(number, event, src, dst, time, "EVENT_READ", "file", "process")


def test_scenario13_audit_reports_c_only_reference_bridge_and_alternatives():
    from tc_pruning.pbr_audit import audit_scenario13_bridges, render_audit_markdown

    candidate = (
        e(1, "bridge-a", "p1", "x", 1),
        read(2, "bridge-b", "x", "p2", 2),
        e(3, "alt-a", "p1", "y", 1),
        read(4, "alt-b", "y", "p2", 3),
    )
    evaluation = {
        "paths": [{
            "source": "p1", "target": "p2", "event_ids": ["bridge-a", "bridge-b"],
            "family": "poi_to_poi_path", "canonical_complete": False,
        }]
    }
    audit = audit_scenario13_bridges(
        candidate_edges=candidate,
        a_selected_event_ids=frozenset({"bridge-a"}),
        c_selected_event_ids=frozenset({"bridge-a", "bridge-b"}),
        evaluation=evaluation,
        poi_node_ids=frozenset({"p1", "p2"}),
        a_evidence={"bridge-b": {"rarity": 0.2, "ppr": 0.1, "lift": 0.0, "path_score": 0.1}},
        c_relevance={"bridge-b": 0.8},
        branch_provenance={"bridge-b": ("forward:one",)},
    )
    assert audit["scenario"] == "13"
    assert audit["c_only_reference_event_count"] == 1
    row = audit["events"][0]
    assert row["raw_event_id"] == "bridge-b"
    assert row["poi_to_poi_path"] is True
    assert row["alternative_path_count"] == 1
    assert row["a_rasp"]["rarity"] == 0.2
    assert row["c_branch_fair"]["branch_provenance"] == ["forward:one"]
    assert "bridge-b" in render_audit_markdown(audit)
