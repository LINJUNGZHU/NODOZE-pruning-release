import gzip
import hashlib
import io
import json
from dataclasses import replace

from tc_pruning.models import Neighborhood, NodeRecord, StoredEdge
from tc_pruning.score_ledger import verify_score_ledger, write_score_ledger


def _fixture():
    edges = [
        StoredEdge(1, "e1", "a", "b", "EVENT_WRITE", 1, "h", "process", "file"),
        StoredEdge(2, "e2", "b", "c", "EVENT_READ", 2, "h", "file", "process"),
    ]
    graph = Neighborhood(
        {name: NodeRecord(name, "process", name) for name in "abc"}, edges,
    )
    verified = 1 - (1 - .5 * .2) * (1 - .5 * .3) * (1 - .5 * .4)
    propagation = {
        edge.edge_id: {
            "relation_family": "file", "relation_transition_weight": .5,
            "temporal_weight": 1., "fanout_weight": 1.,
            "forward_normalized": .3, "backward_normalized": .2,
            "root_forward_normalized": .4,
            "roundtrip_verification_score": .4,
            "diffusion_legacy": .1,
            "diffusion_relation_aware": 1 - (1 - .5 * .2) * (1 - .5 * .3),
            "diffusion_verified": verified,
        }
        for edge in edges
    }
    propagation[2]["diffusion_relation_aware"] = 1.
    propagation[2]["diffusion_verified"] = 1.
    for row in propagation.values():
        row["poi_event_id"] = "e2"
    progressive = {
        "0.5": {
            1: {"group_id": 1, "raw_cost": 1, "removal_priority": .1,
                "removal_attempted": True, "attempt_count": 1,
                "removal_allowed": True, "removal_round": 1,
                "rejection_reason": None},
            2: {"group_id": 2, "raw_cost": 1, "removal_priority": .9,
                "removal_attempted": False, "attempt_count": 0,
                "removal_allowed": False, "removal_round": None,
                "rejection_reason": None},
        }
    }
    context = {
        "scope": "winner_poi", "config": {
            "channel_weights": {"backward": .5, "forward": .5,
                                "verification": .5},
        },
        "poi_event_ids": ["e2"],
        "roots": [{
            "event_id": "e1", "node_uuid": "a", "timestamp_ns": 1,
            "score": .8, "seed_weight": 1., "poi_event_id": "e2",
            "witness_event_ids": ["e1", "e2"],
        }],
    }
    return graph, propagation, progressive, context


def _write(path):
    graph, propagation, progressive, context = _fixture()
    write_score_ledger(
        path, graph=graph, scores={1: .2, 2: .8}, components={},
        rarity_evidence={}, decisions={"0.5": {2: ("progressive_retained",)}},
        propagation_evidence=propagation, progressive_evidence=progressive,
        rcvp_context=context,
    )


def _rewrite_rows(path, mutate):
    score_path = path / "edge-scores.jsonl.gz"
    with gzip.open(score_path, "rt", encoding="utf-8") as stream:
        rows = [json.loads(line) for line in stream]
    mutate(rows)
    with score_path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
            with io.TextIOWrapper(zipped, encoding="utf-8") as text:
                for row in rows:
                    text.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    manifest_path = path / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["artifacts"][score_path.name] = hashlib.sha256(score_path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest, sort_keys=True))


def test_rcvp_extension_round_trips_without_changing_v3_schema(tmp_path):
    _write(tmp_path)
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert manifest["schema_version"] == "rdp-edge-score-ledger-v3"
    assert manifest["rcvp_extension"]["schema_version"] == "rcvp-edge-evidence-v1"
    assert verify_score_ledger(tmp_path)["valid"] is True


def test_rcvp_writer_requires_complete_propagation_and_budget_coverage(tmp_path):
    graph, propagation, progressive, context = _fixture()
    propagation.pop(1)
    try:
        write_score_ledger(
            tmp_path, graph=graph, scores={1: .2, 2: .8}, components={},
            rarity_evidence={}, decisions={"0.5": {2: ("kept",)}},
            propagation_evidence=propagation, progressive_evidence=progressive,
            rcvp_context=context,
        )
    except ValueError as exc:
        assert "cover" in str(exc)
    else:
        raise AssertionError("incomplete propagation evidence was accepted")


def test_rcvp_validator_recomputes_channels_after_outer_hash_refresh(tmp_path):
    _write(tmp_path)
    _rewrite_rows(
        tmp_path,
        lambda rows: rows[0]["rcvp"]["propagation"].__setitem__(
            "diffusion_verified", .99
        ),
    )
    result = verify_score_ledger(tmp_path)
    assert result["valid"] is False
    assert any("diffusion_verified" in error for error in result["validation_errors"])


def test_rcvp_validator_rejects_broken_root_witness_continuity(tmp_path):
    graph, propagation, progressive, context = _fixture()
    context["roots"][0]["witness_event_ids"] = ["e2", "e1"]
    try:
        write_score_ledger(
            tmp_path, graph=graph, scores={1: .2, 2: .8}, components={},
            rarity_evidence={}, decisions={"0.5": {2: ("kept",)}},
            propagation_evidence=propagation, progressive_evidence=progressive,
            rcvp_context=context,
        )
    except ValueError as exc:
        assert "witness" in str(exc)
    else:
        raise AssertionError("broken root witness was accepted")


def test_rcvp_validator_rejects_decision_audit_tamper_after_hash_refresh(tmp_path):
    _write(tmp_path)
    def mutate(rows):
        row = next(item for item in rows if item["edge_id"] == 2)
        row["rcvp"]["pruning"]["0.5"]["removal_allowed"] = True
    _rewrite_rows(tmp_path, mutate)
    result = verify_score_ledger(tmp_path)
    assert result["valid"] is False
    assert any("kept edge" in error for error in result["validation_errors"])


def test_rcvp_root_witness_rejects_equal_timestamps(tmp_path):
    graph, propagation, progressive, context = _fixture()
    graph.edges[1] = replace(
        graph.edges[1], timestamp_ns=graph.edges[0].timestamp_ns
    )
    try:
        write_score_ledger(
            tmp_path, graph=graph, scores={1: .2, 2: .8}, components={},
            rarity_evidence={}, decisions={"0.5": {2: ("kept",)}},
            propagation_evidence=propagation, progressive_evidence=progressive,
            rcvp_context=context,
        )
    except ValueError as exc:
        assert "witness" in str(exc)
    else:
        raise AssertionError("equal-timestamp witness was accepted")


def test_rcvp_extension_supports_propagation_only_ablation(tmp_path):
    graph, propagation, _, context = _fixture()
    write_score_ledger(
        tmp_path, graph=graph, scores={1: .2, 2: .8}, components={},
        rarity_evidence={}, decisions={"0.5": {2: ("kept",)}},
        propagation_evidence=propagation, rcvp_context=context,
    )
    assert verify_score_ledger(tmp_path)["valid"] is True


def test_rcvp_extension_supports_progressive_only_ablation(tmp_path):
    graph, _, progressive, _ = _fixture()
    write_score_ledger(
        tmp_path, graph=graph, scores={1: .2, 2: .8}, components={},
        rarity_evidence={}, decisions={"0.5": {2: ("kept",)}},
        progressive_evidence=progressive,
    )
    assert verify_score_ledger(tmp_path)["valid"] is True


def test_rcvp_extension_accepts_finite_negative_removal_priority(tmp_path):
    graph, _, progressive, _ = _fixture()
    progressive["0.5"][1]["removal_priority"] = -.01
    write_score_ledger(
        tmp_path, graph=graph, scores={1: .2, 2: .8}, components={},
        rarity_evidence={}, decisions={"0.5": {2: ("kept",)}},
        progressive_evidence=progressive,
    )
    assert verify_score_ledger(tmp_path)["valid"] is True


def test_rcvp_implementation_hash_keys_are_checkout_relative(tmp_path):
    _write(tmp_path)
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    keys = manifest["rcvp_extension"]["implementation_sha256"]
    assert keys
    assert all(name.startswith("tc_pruning/") for name in keys)
    assert all(not name.startswith("/") for name in keys)
