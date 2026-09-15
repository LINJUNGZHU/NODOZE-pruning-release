from __future__ import annotations

import builtins
import hashlib
import os
from pathlib import Path

from tc_pruning.detectors.alert_evidence import AlertEvidence, EvidenceGranularity, RoleHint
from tc_pruning.evidence_candidate_builder import CandidateSearchConfig, EvidenceDrivenCandidateBuilder
from tc_pruning.models import EdgeRecord, NodeRecord
from tc_pruning.store import ProvenanceStore


def _node(node: str, time: int, **changes: object) -> AlertEvidence:
    values: dict[str, object] = dict(evidence_id="seed", detector_id="detector", detector_version="v", granularity=EvidenceGranularity.NODE, raw_score=0.0, calibrated_score=0.5, native_decision=True, node_ids=(node,), timestamp_start=time, timestamp_end=time, role_hint=RoleHint.UNKNOWN)
    values.update(changes)
    return AlertEvidence(**values)


def _builder(store: ProvenanceStore, **changes: object) -> EvidenceDrivenCandidateBuilder:
    values: dict[str, object] = dict(candidate_cap=20, history_start_ns=0, cutoff_ns=30, max_strict_depth=4, max_control_depth=2)
    values.update(changes)
    return EvidenceDrivenCandidateBuilder(store, CandidateSearchConfig(**values))


def test_forward_discovery_rewinds_control_history_to_common_experiment_start(tmp_path: Path) -> None:
    with ProvenanceStore(tmp_path / "rewind.db") as store:
        store.ingest([
            NodeRecord("resource", "file", "resource", "h"), NodeRecord("process", "process", "process", "h"), NodeRecord("ancestor", "process", "ancestor", "h"),
            EdgeRecord("read", "resource", "process", "EVENT_READ", 20, "h"),
            EdgeRecord("early-parent", "ancestor", "process", "EVENT_FORK", 5, "h"),
        ])
        result = _builder(store).build([_node("resource", 10)])

    assert {"read", "early-parent"} <= result.event_ids


def test_continuation_process_reenters_control_queue_and_respects_control_depth(tmp_path: Path) -> None:
    with ProvenanceStore(tmp_path / "mixed.db") as store:
        store.ingest([
            NodeRecord("p", "process", "p", "h"), NodeRecord("child", "process", "child", "h"), NodeRecord("file", "file", "file", "h"), NodeRecord("q", "process", "q", "h"), NodeRecord("root", "process", "root", "h"),
            EdgeRecord("p-child", "p", "child", "EVENT_FORK", 5, "h"),
            EdgeRecord("p-file", "p", "file", "EVENT_WRITE", 6, "h"),
            EdgeRecord("file-q", "file", "q", "EVENT_READ", 7, "h"),
            EdgeRecord("root-q", "root", "q", "EVENT_FORK", 4, "h"),
        ])
        full = _builder(store, max_control_depth=2).build([_node("child", 10)])
        shallow = _builder(store, max_control_depth=1).build([_node("child", 10)])

    assert "root-q" in full.event_ids
    assert "root-q" not in shallow.event_ids


def test_builder_does_not_read_or_import_mutated_offline_label_sources(tmp_path: Path, monkeypatch) -> None:
    first_label = tmp_path / "groundtruth-label-one.json"
    second_label = tmp_path / "PDF-label-two.json"
    first_label.write_text('{"known": ["one"]}')
    second_label.write_text('{"known": ["two"]}')
    with ProvenanceStore(tmp_path / "isolation.db") as store:
        store.ingest([NodeRecord("p", "process", "p", "h"), NodeRecord("f", "file", "f", "h"), EdgeRecord("edge", "p", "f", "EVENT_WRITE", 11, "h")])
        builder = _builder(store)
        reads: list[str] = []
        imports: list[str] = []
        original_open, original_import, original_path_open = builtins.open, builtins.__import__, Path.open

        def guarded_open(file, *args, **kwargs):
            if any(token in str(file).lower() for token in ("groundtruth", "label", "pdf")):
                reads.append(str(file))
                raise AssertionError("online builder attempted offline label read")
            return original_open(file, *args, **kwargs)

        def guarded_import(name, *args, **kwargs):
            if any(token in name.lower() for token in ("groundtruth", "label", "pdf")):
                imports.append(name)
                raise AssertionError("online builder attempted offline label import")
            return original_import(name, *args, **kwargs)

        def guarded_path_open(path, *args, **kwargs):
            if any(token in str(path).lower() for token in ("groundtruth", "label", "pdf")):
                reads.append(str(path))
                raise AssertionError("online builder attempted offline label path read")
            return original_path_open(path, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", guarded_open)
        monkeypatch.setattr(builtins, "__import__", guarded_import)
        monkeypatch.setattr(Path, "open", guarded_path_open)
        monkeypatch.setenv("GROUNDTRUTH_PATH", str(first_label))
        before = builder.build([_node("p", 10)])
        monkeypatch.setenv("GROUNDTRUTH_PATH", str(second_label))
        after = builder.build([_node("p", 10)])

    digest = lambda result: hashlib.sha256("\x1f".join(sorted(result.event_ids | result.node_ids)).encode()).hexdigest()
    assert digest(before) == digest(after)
    assert reads == [] and imports == []
