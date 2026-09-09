import gzip
import hashlib
import io
import json
import math
from dataclasses import fields, replace

import pytest

from tc_pruning.frequency import FrequencyModel
from tc_pruning.models import Neighborhood, NodeRecord, StoredEdge
from tc_pruning.score_ledger import (
    candidate_graph_digest,
    verify_score_ledger,
    write_score_ledger,
)
from tc_pruning.rdp_guard import score_map_digest
from tc_pruning.cli import main


def _edge(edge_id, event_id, src, dst, relation="EVENT_WRITE", timestamp=1):
    return StoredEdge(
        edge_id=edge_id,
        event_id=event_id,
        src=src,
        dst=dst,
        relation=relation,
        timestamp_ns=timestamp,
        host="host-1",
        src_type="process",
        dst_type="file",
        src_semantic=f"process:{src}",
        dst_semantic=f"file:{dst}",
        data_size=7,
    )


def _graph():
    edges = [
        _edge(10, "e-low", "p", "a", timestamp=1),
        _edge(20, "e-tie-a", "p", "b", timestamp=2),
        _edge(30, "e-tie-b", "p", "c", timestamp=3),
        _edge(40, "e-high", "p", "d", relation="EVENT_CONNECT", timestamp=4),
    ]
    nodes = {
        name: NodeRecord(name, "process" if name == "p" else "file", name, "host-1")
        for name in ("p", "a", "b", "c", "d")
    }
    return Neighborhood(nodes, edges)


def _read_jsonl_gzip(path):
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        return [json.loads(line) for line in stream]


def _write_jsonl_gzip(path, rows):
    temporary = path.parent / f".{path.name}.test-tmp"
    with temporary.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with io.TextIOWrapper(compressed, encoding="utf-8", newline="\n") as text:
                for row in rows:
                    text.write(
                        json.dumps(
                            row,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        + "\n"
                    )
    temporary.replace(path)


def _refresh_artifact_hash(destination, artifact_name):
    path = destination / artifact_name
    manifest_path = destination / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"][artifact_name] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _write_standard_ledger(destination):
    graph = _graph()
    scores = {10: 0.1, 20: 0.85, 30: 0.85, 40: 1.0}
    model = FrequencyModel(
        {"process": 10, "file": 5},
        {"EVENT_WRITE": 10, "EVENT_CONNECT": 1},
        {
            ("process", "EVENT_WRITE", "file"): 10,
            ("process", "EVENT_CONNECT", "file"): 1,
        },
    )
    components = {
        edge_id: {
            "rarity": 0.1,
            "diffusion": score,
            "path": 0.0,
            "depimpact": 0.0,
            "behavior": 0.0,
            "gated_rarity": 0.1 * score,
            "gated_path": 0.0,
            "gated_depimpact": 0.0,
            "gated_behavior": 0.0,
            "raw_rdp_guard": score,
            "max_local_score": score,
            "aggregate_noisy_or": score,
            "poi_support_count": 1.0,
        }
        for edge_id, score in scores.items()
    }
    provenance = {
        edge_id: {
            "aggregation": "noisy_or",
            "support_count": 1,
            "winner_poi_event_id": "poi-1",
            "winner_local_score": score,
        }
        for edge_id, score in scores.items()
    }
    local_scores = {edge_id: score for edge_id, score in scores.items()}
    return write_score_ledger(
        destination,
        graph=graph,
        scores=scores,
        components=components,
        rarity_evidence={
            edge.edge_id: model.edge_rarity_evidence(edge) for edge in graph.edges
        },
        decisions={
            "0.5": {
                20: ("positive_score_rank",),
                40: ("protected_alert",),
            }
        },
        score_provenance=provenance,
        local_score_contributions={"poi-1": local_scores},
        absolute_threshold=0.8,
        high_score_quantile=0.5,
        context={
            "local_score_digests": {"poi-1": score_map_digest(local_scores)},
            "scoring_parameters": {
                "fusion_mode": "rdp_guard",
                "poi_aggregation": "joint",
                "edge_score_aggregation": "noisy_or",
            },
            "pruning_parameters": {"keep_ratios": [0.5]},
        },
    )


def test_frequency_model_exposes_auditable_rarity_evidence():
    model = FrequencyModel(
        node_type_counts={"process": 10, "file": 5},
        relation_counts={"EVENT_WRITE": 20, "EVENT_CONNECT": 1},
        pattern_counts={("process", "EVENT_WRITE", "file"): 8},
    )

    evidence = model.edge_rarity_evidence(_graph().edges[0])

    assert evidence["src_type_count"] == 10
    assert evidence["dst_type_count"] == 5
    assert evidence["relation_count"] == 20
    assert evidence["pattern_count"] == 8
    assert evidence["weights"] == {"node": 0.2, "relation": 0.3, "pattern": 0.5}
    assert evidence["score"] == pytest.approx(model.edge_rarity(_graph().edges[0]))


def test_score_ledger_persists_every_edge_and_exact_high_score_index(tmp_path):
    graph = _graph()
    model = FrequencyModel(
        {"process": 10, "file": 5},
        {"EVENT_WRITE": 10, "EVENT_CONNECT": 1},
        {
            ("process", "EVENT_WRITE", "file"): 10,
            ("process", "EVENT_CONNECT", "file"): 1,
        },
    )
    scores = {10: 0.1, 20: 0.85, 30: 0.85, 40: 1.0}
    components = {
        edge_id: {"rarity": model.edge_rarity(edge), "diffusion": score}
        for edge, (edge_id, score) in zip(graph.edges, scores.items())
    }
    destination = tmp_path / "ledger"

    manifest = write_score_ledger(
        destination,
        graph=graph,
        scores=scores,
        components=components,
        rarity_evidence={
            edge.edge_id: model.edge_rarity_evidence(edge) for edge in graph.edges
        },
        decisions={
            "0.5": {
                20: ("positive_score_rank",),
                40: ("protected_alert", "ordered_stage_backbone"),
            }
        },
        score_provenance={
            40: {"support_count": 2, "winner_poi_event_id": "poi-2"}
        },
        absolute_threshold=0.8,
        high_score_quantile=0.5,
        context={"scenario": "mini", "online_uses_groundtruth": False},
    )

    with gzip.open(destination / "edge-scores.jsonl.gz", "rt", encoding="utf-8") as stream:
        rows = [json.loads(line) for line in stream]
    high = json.loads((destination / "high-anomaly-edges.json").read_text())

    assert len(rows) == len(graph.edges) == manifest["candidate_edge_count"]
    assert [row["edge_id"] for row in rows] == [40, 20, 30, 10]
    assert [row["rank"] for row in rows] == [1, 2, 3, 4]
    assert len({row["edge_id"] for row in rows}) == len(rows)
    assert {item["edge_id"] for item in high["edges"]} == {
        row["edge_id"] for row in rows if row["high_score"]
    }
    assert {item["edge_id"] for item in high["edges"]} == {20, 30, 40}
    assert rows[0]["score_semantics"] == "heuristic_importance_not_probability"
    assert rows[0]["provenance"]["support_count"] == 2
    assert rows[0]["decisions"] == [
        {
            "budget_key": "0.5",
            "kept": True,
            "reasons": ["ordered_stage_backbone", "protected_alert"],
        }
    ]
    assert rows[-1]["decisions"][0]["kept"] is False
    assert manifest["complete"] is True
    assert manifest["schema_version"] == "rdp-edge-score-ledger-v3"
    assert manifest["unique_edge_ids"] == len(graph.edges)
    assert manifest["high_score_count"] == 3
    assert manifest["online_uses_groundtruth"] is False
    assert "candidate-graph.jsonl.gz" in manifest["artifacts"]
    assert "poi-local-contributions.jsonl.gz" in manifest["artifacts"]
    assert manifest["local_contribution_encoding"] == (
        "sparse_positive_rows_missing_pairs_are_exact_zero"
    )
    verification = verify_score_ledger(destination)
    assert verification["valid"] is True
    assert verification["validation_errors"] == []


def test_score_ledger_artifact_hashes_detect_tampering(tmp_path):
    destination = tmp_path / "ledger"
    graph = _graph()
    write_score_ledger(
        destination,
        graph=graph,
        scores={edge.edge_id: edge.edge_id / 40 for edge in graph.edges},
        components={},
        rarity_evidence={},
        decisions={},
    )
    high_path = destination / "high-anomaly-edges.json"
    high_path.write_text(high_path.read_text() + "\n", encoding="utf-8")

    verification = verify_score_ledger(destination)

    assert verification["valid"] is False
    assert "high-anomaly-edges.json" in verification["hash_mismatches"]


def test_score_ledger_is_byte_deterministic(tmp_path):
    graph = _graph()
    kwargs = dict(
        graph=graph,
        scores={10: 0.1, 20: 0.4, 30: 0.6, 40: 0.9},
        components={},
        rarity_evidence={},
        decisions={},
    )
    write_score_ledger(tmp_path / "one", **kwargs)
    write_score_ledger(tmp_path / "two", **kwargs)

    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    for name in (
        "candidate-graph.jsonl.gz",
        "edge-scores.jsonl.gz",
        "high-anomaly-edges.json",
        "manifest.json",
    ):
        assert digest(tmp_path / "one" / name) == digest(tmp_path / "two" / name)
    assert not list(tmp_path.rglob("*.tmp"))


def test_verifier_recomputes_noisy_or_from_every_poi_local_contribution(tmp_path):
    destination = tmp_path / "ledger"
    _write_standard_ledger(destination)
    contribution_path = destination / "poi-local-contributions.jsonl.gz"
    rows = _read_jsonl_gzip(contribution_path)
    rows[0]["local_score"] = 0.7
    _write_jsonl_gzip(contribution_path, rows)
    _refresh_artifact_hash(destination, contribution_path.name)

    verification = verify_score_ledger(destination)

    assert verification["valid"] is False
    errors = "\n".join(verification["validation_errors"])
    assert "local score digest" in errors
    assert "noisy-OR aggregate" in errors


def test_writer_requires_complete_local_contributions_when_digests_are_declared(
    tmp_path,
):
    graph = _graph()
    scores = {edge.edge_id: 0.5 for edge in graph.edges}

    with pytest.raises(ValueError, match="local_score_contributions"):
        write_score_ledger(
            tmp_path / "ledger",
            graph=graph,
            scores=scores,
            components={edge.edge_id: {"score": 0.5} for edge in graph.edges},
            rarity_evidence={edge.edge_id: {"score": 0.5} for edge in graph.edges},
            decisions={},
            context={
                "local_score_digests": {"poi-1": score_map_digest(scores)},
                "scoring_parameters": {"edge_score_aggregation": "noisy_or"},
            },
        )


def test_candidate_digest_covers_every_node_and_stored_edge_field():
    graph = _graph()
    node_changes = {
        "uuid": "changed-uuid",
        "node_type": "changed-type",
        "label": "changed-label",
        "host": "changed-host",
        "semantic_key": "changed-semantic",
        "properties": {"changed": "property"},
    }
    edge_changes = {
        "edge_id": 999,
        "event_id": "changed-event",
        "src": "changed-src",
        "dst": "changed-dst",
        "relation": "EVENT_CHANGED",
        "timestamp_ns": 999,
        "host": "changed-host",
        "src_type": "changed-src-type",
        "dst_type": "changed-dst-type",
        "src_semantic": "changed-src-semantic",
        "dst_semantic": "changed-dst-semantic",
        "data_size": 999,
    }

    assert set(node_changes) == {field.name for field in fields(NodeRecord)}
    assert set(edge_changes) == {field.name for field in fields(StoredEdge)}
    for field_name, value in node_changes.items():
        changed = Neighborhood(
            {**graph.nodes, "p": replace(graph.nodes["p"], **{field_name: value})},
            graph.edges,
        )
        assert candidate_graph_digest(graph) != candidate_graph_digest(changed)
    for field_name, value in edge_changes.items():
        changed = Neighborhood(
            graph.nodes,
            [replace(graph.edges[0], **{field_name: value}), *graph.edges[1:]],
        )
        assert candidate_graph_digest(graph) != candidate_graph_digest(changed)


def test_candidate_identity_artifact_contains_every_dataclass_field(tmp_path):
    destination = tmp_path / "ledger"
    _write_standard_ledger(destination)

    records = _read_jsonl_gzip(destination / "candidate-graph.jsonl.gz")
    node = next(record for record in records if record["record_type"] == "node")
    edge = next(record for record in records if record["record_type"] == "edge")

    assert set(node) == {
        "schema_version",
        "record_type",
        *(field.name for field in fields(NodeRecord)),
    }
    assert set(edge) == {
        "schema_version",
        "record_type",
        *(field.name for field in fields(StoredEdge)),
    }


def test_verifier_recomputes_candidate_identity_after_hash_consistent_tamper(tmp_path):
    destination = tmp_path / "ledger"
    _write_standard_ledger(destination)
    identity_path = destination / "candidate-graph.jsonl.gz"
    records = _read_jsonl_gzip(identity_path)
    edge = next(record for record in records if record["record_type"] == "edge")
    edge["data_size"] = 123456
    _write_jsonl_gzip(identity_path, records)
    _refresh_artifact_hash(destination, identity_path.name)

    verification = verify_score_ledger(destination)

    assert verification["valid"] is False
    assert any(
        "candidate_identity_sha256" in error
        for error in verification["validation_errors"]
    )


def test_verifier_rejects_incomplete_duplicate_and_misordered_ledger_rows(tmp_path):
    destination = tmp_path / "ledger"
    _write_standard_ledger(destination)
    score_path = destination / "edge-scores.jsonl.gz"
    rows = _read_jsonl_gzip(score_path)
    rows[0], rows[1] = rows[1], rows[0]
    rows[-1] = dict(rows[0])
    _write_jsonl_gzip(score_path, rows)
    _refresh_artifact_hash(destination, score_path.name)

    verification = verify_score_ledger(destination)

    assert verification["valid"] is False
    errors = "\n".join(verification["validation_errors"])
    assert "duplicate" in errors
    assert "candidate edge" in errors
    assert "sort" in errors or "rank" in errors


def test_verifier_requires_rank_to_be_an_integer_not_boolean(tmp_path):
    destination = tmp_path / "ledger"
    _write_standard_ledger(destination)
    score_path = destination / "edge-scores.jsonl.gz"
    rows = _read_jsonl_gzip(score_path)
    rows[0]["rank"] = True
    _write_jsonl_gzip(score_path, rows)
    _refresh_artifact_hash(destination, score_path.name)

    verification = verify_score_ledger(destination)

    assert verification["valid"] is False
    assert any("rank" in error for error in verification["validation_errors"])


@pytest.mark.parametrize("invalid_score", [math.nan, math.inf, -0.1, 1.1])
def test_verifier_rejects_nonfinite_or_out_of_range_scores(tmp_path, invalid_score):
    destination = tmp_path / "ledger"
    _write_standard_ledger(destination)
    score_path = destination / "edge-scores.jsonl.gz"
    rows = _read_jsonl_gzip(score_path)
    rows[0]["score"] = invalid_score
    _write_jsonl_gzip(score_path, rows)
    _refresh_artifact_hash(destination, score_path.name)

    verification = verify_score_ledger(destination)

    assert verification["valid"] is False
    assert any("finite [0, 1]" in error for error in verification["validation_errors"])


def test_verifier_recomputes_high_score_threshold_and_complete_tie_set(tmp_path):
    destination = tmp_path / "ledger"
    _write_standard_ledger(destination)
    high_path = destination / "high-anomaly-edges.json"
    high = json.loads(high_path.read_text(encoding="utf-8"))
    high["effective_cutoff"] = 0.9
    high["edges"] = [edge for edge in high["edges"] if edge["edge_id"] != 30]
    high_path.write_text(
        json.dumps(high, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    _refresh_artifact_hash(destination, high_path.name)

    verification = verify_score_ledger(destination)

    assert verification["valid"] is False
    errors = "\n".join(verification["validation_errors"])
    assert "effective_cutoff" in errors
    assert "high-score edge set" in errors


def test_verifier_requires_complete_budget_decisions_and_kept_reasons(tmp_path):
    destination = tmp_path / "ledger"
    _write_standard_ledger(destination)
    score_path = destination / "edge-scores.jsonl.gz"
    rows = _read_jsonl_gzip(score_path)
    rows[0]["decisions"][0]["reasons"] = []
    rows[1]["decisions"] = []
    _write_jsonl_gzip(score_path, rows)
    _refresh_artifact_hash(destination, score_path.name)

    verification = verify_score_ledger(destination)

    assert verification["valid"] is False
    errors = "\n".join(verification["validation_errors"])
    assert "missing decision" in errors
    assert "non-empty reasons" in errors


def test_verifier_requires_all_edge_identity_fields_in_every_ledger_row(tmp_path):
    destination = tmp_path / "ledger"
    _write_standard_ledger(destination)
    score_path = destination / "edge-scores.jsonl.gz"
    rows = _read_jsonl_gzip(score_path)
    del rows[-1]["data_size"]
    _write_jsonl_gzip(score_path, rows)
    _refresh_artifact_hash(destination, score_path.name)

    verification = verify_score_ledger(destination)

    assert verification["valid"] is False
    assert any(
        "missing StoredEdge fields" in error
        for error in verification["validation_errors"]
    )


def test_verifier_reports_malformed_high_score_identity_without_raising(tmp_path):
    destination = tmp_path / "ledger"
    _write_standard_ledger(destination)
    high_path = destination / "high-anomaly-edges.json"
    high = json.loads(high_path.read_text(encoding="utf-8"))
    high["edges"][0]["edge_id"] = []
    high_path.write_text(
        json.dumps(high, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    _refresh_artifact_hash(destination, high_path.name)

    verification = verify_score_ledger(destination)

    assert verification["valid"] is False
    assert any("edge_id" in error for error in verification["validation_errors"])


def test_writer_rejects_kept_decision_without_reason(tmp_path):
    graph = _graph()

    with pytest.raises(ValueError, match="non-empty reason"):
        write_score_ledger(
            tmp_path / "ledger",
            graph=graph,
            scores={edge.edge_id: 0.5 for edge in graph.edges},
            components={},
            rarity_evidence={},
            decisions={"0.5": {10: ()}},
        )


def test_manifest_records_complete_score_evidence_key_schema(tmp_path):
    destination = tmp_path / "ledger"

    manifest = _write_standard_ledger(destination)

    assert manifest["evidence_key_schema"] == {
        "components": [
            "aggregate_noisy_or",
            "behavior",
            "depimpact",
            "diffusion",
            "gated_behavior",
            "gated_depimpact",
            "gated_path",
            "gated_rarity",
            "max_local_score",
            "path",
            "poi_support_count",
            "rarity",
            "raw_rdp_guard",
        ],
        "provenance": [
            "aggregation",
            "support_count",
            "winner_local_score",
            "winner_poi_event_id",
        ],
        "rarity_evidence": [
            "dst_type",
            "dst_type_count",
            "max_node_type_count",
            "max_pattern_count",
            "max_relation_count",
            "node_rarity",
            "pattern",
            "pattern_count",
            "pattern_rarity",
            "relation",
            "relation_count",
            "relation_rarity",
            "score",
            "src_type",
            "src_type_count",
            "weights",
        ],
    }


@pytest.mark.parametrize("incomplete_field", ["components", "rarity_evidence"])
def test_writer_rejects_inconsistent_required_evidence_schema(
    tmp_path, incomplete_field
):
    graph = _graph()
    components = {edge.edge_id: {"first": 1, "second": 2} for edge in graph.edges}
    rarity_evidence = {
        edge.edge_id: {"count": 1, "score": 0.5} for edge in graph.edges
    }
    if incomplete_field == "components":
        del components[graph.edges[-1].edge_id]["second"]
    else:
        del rarity_evidence[graph.edges[-1].edge_id]["count"]

    with pytest.raises(ValueError, match=f"inconsistent {incomplete_field} key schema"):
        write_score_ledger(
            tmp_path / "ledger",
            graph=graph,
            scores={edge.edge_id: 0.5 for edge in graph.edges},
            components=components,
            rarity_evidence=rarity_evidence,
            decisions={"0.5": {}},
            context={
                "scoring_parameters": {"poi_aggregation": "max"},
                "pruning_parameters": {"keep_ratios": [0.5]},
            },
        )


def test_writer_requires_complete_noisy_or_provenance(tmp_path):
    graph = _graph()
    provenance = {
        edge.edge_id: {"aggregation": "noisy_or", "support_count": 1}
        for edge in graph.edges[:-1]
    }

    with pytest.raises(ValueError, match="inconsistent provenance key schema"):
        write_score_ledger(
            tmp_path / "ledger",
            graph=graph,
            scores={edge.edge_id: 0.5 for edge in graph.edges},
            components={edge.edge_id: {"score": 0.5} for edge in graph.edges},
            rarity_evidence={
                edge.edge_id: {"score": 0.5} for edge in graph.edges
            },
            decisions={"0.5": {}},
            score_provenance=provenance,
            context={
                "scoring_parameters": {"poi_aggregation": "noisy_or"},
                "pruning_parameters": {"keep_ratios": [0.5]},
            },
        )


@pytest.mark.parametrize(
    "evidence_field,removed_key",
    [
        ("components", "rarity"),
        ("rarity_evidence", "score"),
        ("provenance", "support_count"),
    ],
)
def test_verifier_rejects_score_rows_that_violate_manifest_evidence_schema(
    tmp_path, evidence_field, removed_key
):
    destination = tmp_path / "ledger"
    _write_standard_ledger(destination)
    score_path = destination / "edge-scores.jsonl.gz"
    rows = _read_jsonl_gzip(score_path)
    del rows[-1][evidence_field][removed_key]
    _write_jsonl_gzip(score_path, rows)
    _refresh_artifact_hash(destination, score_path.name)

    verification = verify_score_ledger(destination)

    assert verification["valid"] is False
    assert any(
        f"{evidence_field} key schema" in error
        for error in verification["validation_errors"]
    )


def test_writer_requires_formatted_keep_ratios_to_equal_decision_budget_keys(tmp_path):
    graph = _graph()

    with pytest.raises(ValueError, match="keep_ratios.*decision budget keys"):
        write_score_ledger(
            tmp_path / "ledger",
            graph=graph,
            scores={edge.edge_id: 0.5 for edge in graph.edges},
            components={edge.edge_id: {"score": 0.5} for edge in graph.edges},
            rarity_evidence={
                edge.edge_id: {"score": 0.5} for edge in graph.edges
            },
            decisions={"0.333333333333": {}},
            context={
                "scoring_parameters": {"poi_aggregation": "max"},
                "pruning_parameters": {"keep_ratios": [0.5]},
            },
        )

    manifest = write_score_ledger(
        tmp_path / "matching-ledger",
        graph=graph,
        scores={edge.edge_id: 0.5 for edge in graph.edges},
        components={edge.edge_id: {"score": 0.5} for edge in graph.edges},
        rarity_evidence={edge.edge_id: {"score": 0.5} for edge in graph.edges},
        decisions={"0.333333333333": {}},
        context={
            "scoring_parameters": {"poi_aggregation": "max"},
            "pruning_parameters": {"keep_ratios": [1 / 3]},
        },
    )
    assert manifest["decision_budget_keys"] == ["0.333333333333"]


def test_verifier_rejects_manifest_keep_ratio_and_budget_key_mismatch(tmp_path):
    destination = tmp_path / "ledger"
    _write_standard_ledger(destination)
    manifest_path = destination / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["context"]["pruning_parameters"]["keep_ratios"] = [0.25]
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )

    verification = verify_score_ledger(destination)

    assert verification["valid"] is False
    assert any(
        "keep_ratios" in error and "decision_budget_keys" in error
        for error in verification["validation_errors"]
    )


def test_verifier_checks_observed_optional_provenance_union_schema(tmp_path):
    destination = tmp_path / "ledger"
    graph = _graph()
    manifest = write_score_ledger(
        destination,
        graph=graph,
        scores={edge.edge_id: 0.5 for edge in graph.edges},
        components={edge.edge_id: {"score": 0.5} for edge in graph.edges},
        rarity_evidence={edge.edge_id: {"score": 0.5} for edge in graph.edges},
        decisions={"0.5": {}},
        score_provenance={10: {"source": "a"}, 20: {"support_count": 1}},
        context={
            "scoring_parameters": {"poi_aggregation": "max"},
            "pruning_parameters": {"keep_ratios": [0.5]},
        },
    )
    assert manifest["evidence_key_schema"]["provenance"] == [
        "source",
        "support_count",
    ]
    score_path = destination / "edge-scores.jsonl.gz"
    rows = _read_jsonl_gzip(score_path)
    rows[1]["provenance"] = {}
    _write_jsonl_gzip(score_path, rows)
    _refresh_artifact_hash(destination, score_path.name)

    verification = verify_score_ledger(destination)

    assert verification["valid"] is False
    assert any(
        "observed provenance key schema" in error
        for error in verification["validation_errors"]
    )


def test_writer_rejects_nonfinite_nested_score_evidence(tmp_path):
    graph = _graph()
    components = {
        edge.edge_id: {"score": 0.5, "nested": {"finite": 1.0}}
        for edge in graph.edges
    }
    components[graph.edges[-1].edge_id]["nested"]["finite"] = math.nan

    with pytest.raises(ValueError, match="numeric evidence must be finite"):
        write_score_ledger(
            tmp_path / "ledger",
            graph=graph,
            scores={edge.edge_id: 0.5 for edge in graph.edges},
            components=components,
            rarity_evidence={
                edge.edge_id: {"score": 0.5} for edge in graph.edges
            },
            decisions={"0.5": {}},
            context={
                "scoring_parameters": {"poi_aggregation": "max"},
                "pruning_parameters": {"keep_ratios": [0.5]},
            },
        )


def test_verifier_rejects_invalid_noisy_or_provenance_semantics(tmp_path):
    destination = tmp_path / "ledger"
    _write_standard_ledger(destination)
    score_path = destination / "edge-scores.jsonl.gz"
    rows = _read_jsonl_gzip(score_path)
    rows[-1]["provenance"]["support_count"] = -1
    _write_jsonl_gzip(score_path, rows)
    _refresh_artifact_hash(destination, score_path.name)

    verification = verify_score_ledger(destination)

    assert verification["valid"] is False
    assert any(
        "support_count" in error for error in verification["validation_errors"]
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda row: row["components"].__setitem__("aggregate_noisy_or", 0.777),
        lambda row: row["components"].__setitem__("max_local_score", 0.777),
        lambda row: row["components"].__setitem__("poi_support_count", 9.0),
    ],
)
def test_verifier_rejects_internally_inconsistent_noisy_or_evidence(
    tmp_path, mutate
):
    destination = tmp_path / "ledger"
    _write_standard_ledger(destination)
    score_path = destination / "edge-scores.jsonl.gz"
    rows = _read_jsonl_gzip(score_path)
    mutate(rows[-1])
    _write_jsonl_gzip(score_path, rows)
    _refresh_artifact_hash(destination, score_path.name)

    verification = verify_score_ledger(destination)

    assert verification["valid"] is False
    assert any(
        "noisy_or evidence mismatch" in error
        for error in verification["validation_errors"]
    )


def test_score_ledger_cli_returns_success_only_for_valid_artifact(tmp_path):
    graph = _graph()
    destination = tmp_path / "ledger"
    write_score_ledger(
        destination,
        graph=graph,
        scores={edge.edge_id: edge.edge_id / 40 for edge in graph.edges},
        components={},
        rarity_evidence={},
        decisions={},
    )

    assert main(["verify-score-ledger", "--ledger", str(destination)]) == 0

    (destination / "high-anomaly-edges.json").write_text("{}", encoding="utf-8")
    assert main(["verify-score-ledger", "--ledger", str(destination)]) == 1
