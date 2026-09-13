import json
import copy
from pathlib import Path

import numpy as np
import pytest

from tc_pruning.rcvp_web import score_candidate
from tc_pruning.rcvp_web_config import validate_fusion_config
from tc_pruning.optc_investigation import rescore
from webapp.backend import app as backend
from webapp.scripts.prepare_optc import build_index


def test_rcvp_adapter_uses_relation_names_and_returns_fused_channels(monkeypatch):
    captured = {}

    def fake_propagate(src, dst, timestamp, relation_names, rarity, poi, process_nodes, config=None):
        captured.update(relation_names=list(relation_names), config=config)
        return np.array([0.2, 1.0]), {
            "edge_fields": {"lift": np.array([0.1, 0.8]), "roundtrip": np.array([0.0, 0.7])},
            "roots": [{"node": 0, "score": 0.7}],
        }

    monkeypatch.setattr("tc_pruning.rcvp_web.rcvp_propagate", fake_propagate)
    monkeypatch.setattr("tc_pruning.rcvp_web.preset", lambda name: {"preset": name})
    result = score_candidate(
        src=np.array([0, 1]), dst=np.array([1, 2]), timestamp=np.array([1, 2]),
        relation_names=["READ", "WRITE"], rarity=np.array([1.0, 0.5]),
        poi=np.array([False, True]), process_nodes=np.array([True, True, False]),
        preset_name="relation_aware",
    )

    assert captured["relation_names"] == ["READ", "WRITE"]
    assert result.algorithm["mode"] == "relation_aware"
    assert result.algorithm["preset"] == "relation_aware"
    assert len(result.algorithm["config_sha256"]) == 64
    assert result.scores.shape == (2,)
    assert result.edge_fields["lift"].tolist() == [0.1, 0.8]
    assert result.roots == [{"node": 0, "score": 0.7}]


def test_rcvp_adapter_rejects_unknown_mode():
    with pytest.raises(ValueError, match="unknown algorithm mode"):
        score_candidate(
            src=np.array([], dtype=int), dst=np.array([], dtype=int),
            timestamp=np.array([], dtype=np.int64), relation_names=[],
            rarity=np.array([]), poi=np.array([], dtype=bool),
            process_nodes=np.array([], dtype=bool), preset_name="labels",
        )


def test_real_rcvp_adapter_is_json_safe_and_keeps_original_edge_count():
    result = score_candidate(
        src=np.array([0, 1]), dst=np.array([1, 2]),
        timestamp=np.array([1, 2], dtype=np.int64),
        relation_names=["EVENT_WRITE", "EVENT_EXECUTE"], rarity=np.array([0.8, 1.0]),
        poi=np.array([False, True]), process_nodes=np.array([True, True, True]),
        preset_name="full",
    )
    assert len(result.scores) == 2
    assert result.edge_fields["relation_family"].tolist() == ["file_write", "execution"]
    assert result.algorithm["operator"] == "exact_temporal_max_product"
    assert result.algorithm["truth_used"] is False
    json.dumps({"algorithm": result.algorithm, "roots": result.roots})


def test_fusion_config_is_validated_and_changes_algorithm_identity():
    args = dict(src=np.array([0, 1]), dst=np.array([1, 2]),
        timestamp=np.array([1, 2], dtype=np.int64), relation_names=["EVENT_WRITE", "EVENT_EXECUTE"],
        rarity=np.array([0.8, 1.0]), poi=np.array([False, True]),
        process_nodes=np.array([True, True, True]), preset_name="relation_aware")
    default = score_candidate(**args)
    changed = score_candidate(**args, fusion_config={"rarity_weight": 0.5})
    assert default.algorithm["rcvp_fusion"] == {
        "rarity_weight": 0.25, "path_weight": 0.0,
        "impact_weight": 0.0, "behavior_weight": 0.0,
    }
    assert changed.algorithm["config_sha256"] != default.algorithm["config_sha256"]
    with pytest.raises(ValueError, match="fusion weights"):
        validate_fusion_config({"rarity_weight": .8, "path_weight": .3})
    with pytest.raises(ValueError, match="unknown web fusion"):
        validate_fusion_config({"label_weight": 1})


@pytest.fixture
def optc_candidate(tmp_path):
    def record(event_id, minute):
        return dict(id=event_id, actorID="process-a", objectID="object-" + event_id,
                    hostname="SysClient0201.systemia.com", pid=5452, object="FILE", action="WRITE",
                    timestamp=f"2019-09-23T11:{minute}:00-04:00",
                    properties={"image_path": "cmd.exe", "file_path": "normal.txt"})
    rows = [record("history", "15"), record("before", "22"), record("seed", "23"),
            record("later", "24"), record("after", "26")]
    database = tmp_path / "history.sqlite"
    edges, index_id = build_index((("fixture", i, row) for i, row in enumerate(rows)), database)
    return dict(schema_version=2, edges=edges, history_index=dict(path=str(database), id=index_id),
        dataset=dict(id="optc-0201", name="test", description="test", sources=["fixture"]),
        poi_presets=[dict(event_id="seed", label="fixture", evidence="fixture")],
        truth=dict(source="fixture"), display_event_ids=[edge["id"] for edge in edges],
        algorithm=dict(name="RASP-D", budget_ratio=.2,
            config=json.loads((Path(__file__).resolve().parents[2] / "configs/rasp_v1.json").read_text())))


def test_full_rcvp_progressive_result_is_label_independent(optc_candidate, monkeypatch):
    import tc_pruning.optc_investigation as pipeline
    first = rescore(copy.deepcopy(optc_candidate), "seed", .2, "progressive", algorithm_mode="rcvp")
    monkeypatch.setattr(pipeline, "reference_evidence", lambda edge: ["changed ground truth"])
    second = rescore(copy.deepcopy(optc_candidate), "seed", .2, "progressive", algorithm_mode="rcvp")
    assert [(e["score"], e["retained"]) for e in first["edges"]] == [
        (e["score"], e["retained"]) for e in second["edges"]]
    assert first["decision_trace"] == second["decision_trace"]
    assert first["metrics"]["candidate_edges"] == len(optc_candidate["edges"])
    assert first["algorithm"]["mode"] == "rcvp"
    assert first["algorithm"]["preset"] == "full"
    assert first["decision_certificate"]["certificate_kind"] == "exact_temporal_witness"
    assert first["decision_contract"]["numerical_bound"] == "exact timestamp sweep; no iterative residual bound"
    assert "PPR" not in first["decision_contract"]["eligibility"]


@pytest.mark.parametrize("selection_mode", ["evidence", "context", "progressive"])
def test_new_algorithms_never_claim_ppr_residual_certification(optc_candidate, selection_mode):
    result = rescore(copy.deepcopy(optc_candidate), "seed", .2, selection_mode,
                     algorithm_mode="relation_aware")
    assert result["decision_certificate"]["certificate_kind"] == "exact_temporal_witness"
    contract = result["decision_contract"]
    assert contract["certificate_kind"] == "exact_temporal_witness"
    assert "PPR" not in json.dumps(contract, ensure_ascii=False)
    assert "residual" in contract["numerical_bound"]
    assert all(edge["evidence_score"] == edge["score"] for edge in result["edges"])


def test_progressive_web_path_does_not_expand_witness_bundles(optc_candidate, monkeypatch):
    import tc_pruning.optc_investigation as pipeline
    monkeypatch.setattr(pipeline, "witness_bundle",
                        lambda *args: (_ for _ in ()).throw(AssertionError("expanded witness")))
    result = rescore(copy.deepcopy(optc_candidate), "seed", .2, "progressive",
                     algorithm_mode="rcvp")
    assert result["decision_certificate"]["complete_witnesses"] is True
    assert all("progressive" in edge["decision"] for edge in result["edges"])
    assert all("rcvp" in edge for edge in result["edges"])


def _cache(tmp_path):
    path = tmp_path / "demo.json"
    path.write_text(json.dumps({
        "schema_version": 2,
        "dataset": {"id": "demo", "name": "Demo", "description": "test"},
        "metrics": {"candidate_edges": 1}, "nodes": [], "edges": [],
        "algorithm": {"budget_ratio": 0.2, "selection_mode": "context", "config": {}},
    }))
    return path


@pytest.mark.parametrize("field,value", [
    ("algorithm_mode", "truth_aware"),
    ("selection_mode", "top_k"),
    ("budget_ratio", 1.1),
])
def test_prune_rejects_unsupported_experimental_options_without_rescoring(tmp_path, monkeypatch, field, value):
    monkeypatch.setattr(backend, "rescore", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("called")))
    client = backend.create_app(_cache(tmp_path)).test_client()
    payload = {"poi_event_id": "e1", field: value}
    response = client.post("/api/datasets/demo/prune", json=payload)
    assert response.status_code == 400


def test_prune_defaults_to_legacy_context_and_passes_explicit_modes(tmp_path, monkeypatch):
    calls = []

    def fake_rescore(data, poi, budget, selection, quantile, detector, algorithm_mode=None):
        calls.append((budget, selection, algorithm_mode))

    monkeypatch.setattr(backend, "rescore", fake_rescore)
    client = backend.create_app(_cache(tmp_path)).test_client()
    assert client.post("/api/datasets/demo/prune", json={"poi_event_id": "e1"}).status_code == 200
    assert calls[-1] == (None, None, "legacy")
    assert client.post("/api/datasets/demo/prune", json={
        "poi_event_id": "e1", "budget_ratio": 0.1,
        "selection_mode": "progressive", "algorithm_mode": "rcvp",
    }).status_code == 200
    assert calls[-1] == (0.1, "progressive", "rcvp")
