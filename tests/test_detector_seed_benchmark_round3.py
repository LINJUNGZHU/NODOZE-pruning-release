from __future__ import annotations

import json
from pathlib import Path

import pytest


def test_iter_evidence_jsonl_streams_source_order_without_materializing(tmp_path: Path) -> None:
    from tc_pruning.detectors.alert_evidence import iter_evidence_jsonl

    path = tmp_path / "evidence.jsonl"
    rows = [
        {"schema_version": "2.0", "evidence_id": "z", "detector_id": "D", "detector_version": "1", "granularity": "EVENT", "raw_score": 1.0, "calibrated_score": 1.0, "native_decision": True, "event_ids": ["e"], "node_ids": [], "supporting_event_ids": [], "structural_context": {}, "timestamp_start": None, "timestamp_end": None, "src_uuid": None, "dst_uuid": None, "relation": None, "role_hint": "UNKNOWN", "mapping_quality": "NATIVE", "detector_metadata": {}, "development_percentile": None, "query_local_percentile": None},
        {"schema_version": "2.0", "evidence_id": "a", "detector_id": "D", "detector_version": "1", "granularity": "EVENT", "raw_score": 1.0, "calibrated_score": 1.0, "native_decision": True, "event_ids": ["f"], "node_ids": [], "supporting_event_ids": [], "structural_context": {}, "timestamp_start": None, "timestamp_end": None, "src_uuid": None, "dst_uuid": None, "relation": None, "role_hint": "UNKNOWN", "mapping_quality": "NATIVE", "detector_metadata": {}, "development_percentile": None, "query_local_percentile": None},
    ]
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    assert [item.evidence_id for item in iter_evidence_jsonl(path)] == ["z", "a"]


def test_authority_guard_rejects_known_critical_and_attack_times_but_not_safe_relation_text() -> None:
    from tc_pruning.detector_seed_benchmark import _reject_bad

    for value in ("known_critical_event_ids.jsonl", "attack_times.json", {"positive_ids": ["x"]}, {"gt": True}):
        with pytest.raises(ValueError): _reject_bad(value)
    _reject_bad({"relation": "EVENT_WRITE", "source_semantic": "process:/usr/bin/bash"})


@pytest.mark.parametrize("value", ["groundtruth.json", "my_known_critical_event_ids_copy.jsonl", "cadets_attack_times_backup", {"nested": {"critical_edge_cache": 1}}])
def test_authority_guard_rejects_embedded_compound_authorities(value: object) -> None:
    from tc_pruning.detector_seed_benchmark import _reject_bad
    with pytest.raises(ValueError):
        _reject_bad(value)
