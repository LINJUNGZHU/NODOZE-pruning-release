from tc_pruning.detectors.kairos_adapter import NativeKairosAdapter, NativeKairosEvent
from tc_pruning.models import EdgeRecord, NodeRecord
from tc_pruning.store import ProvenanceStore
from scripts.export_kairos_evidence import native_records


def _native(time=100, loss=5.0, event_id=None):
    return NativeKairosEvent(
        native_id="n1", window="w1", timestamp_ns=time,
        relation="EVENT_WRITE", srcmsg="{'subject': 'proc'}",
        dstmsg="{'file': '/tmp/x'}", raw_loss=loss,
        explicit_event_id=event_id, queue_ids=("q1",), queue_strength=9.0,
        summary_component="s1",
    )


def _store(tmp_path, extra=()):
    store = ProvenanceStore(tmp_path / "g.db")
    store.ingest([
        NodeRecord("p", "process", "proc", "h"),
        NodeRecord("f", "file", "/tmp/x", "h"),
        EdgeRecord("e1", "p", "f", "EVENT_WRITE", 100, "h"),
        *extra,
    ])
    return store


def test_exact_and_tolerant_mapping_preserve_native_layers(tmp_path):
    with _store(tmp_path) as store:
        field = NativeKairosAdapter(store, tolerance_ns=5).map_records(
            (_native(), _native(time=103, loss=1.0))
        )
    assert field.audit.exact_mapped == 1
    assert field.audit.tolerant_mapped == 1
    assert [row.raw_event_id for row in field.evidence] == ["e1", "e1"]
    assert field.evidence[0].loss_percentile == 1.0
    assert field.evidence[0].queue_ids == ("q1",)
    assert field.evidence[0].summary_membership is True
    assert len(field.mapping_sha256) == 64


def test_explicit_event_identity_has_priority(tmp_path):
    with _store(tmp_path) as store:
        field = NativeKairosAdapter(store).map_records((_native(time=999, event_id="e1"),))
    assert field.audit.identity_mapped == 1
    assert field.evidence[0].mapping_tier == "IDENTITY"


def test_ambiguous_mapping_is_rejected_instead_of_taking_first(tmp_path):
    extra = (
        NodeRecord("p2", "process", "proc", "h"),
        EdgeRecord("e2", "p2", "f", "EVENT_WRITE", 100, "h"),
    )
    with _store(tmp_path, extra) as store:
        field = NativeKairosAdapter(store).map_records((_native(),))
    assert field.evidence == ()
    assert field.audit.ambiguous == 1
    assert field.audit.mapping_rate == 0.0


def test_export_marks_only_native_threshold_exceedances_anomalous(tmp_path):
    artifact = tmp_path / "artifact"
    graph = artifact / "graph_4_6"
    graph.mkdir(parents=True)
    window = "2018-04-06 sample.txt"
    (artifact / "evaluation.log").write_text(
        f"Anomalous queue: ['{window}']\nAnomaly score: 10\n", encoding="utf-8"
    )
    rows = [
        {"time": index, "edge_type": "EVENT_WRITE", "srcmsg": "{'subject': 'p'}",
         "dstmsg": "{'file': 'f'}", "loss": loss}
        for index, loss in enumerate((1.0, 1.0, 1.0, 10.0))
    ]
    (graph / window).write_text("".join(f"{row!r}\n" for row in rows), encoding="utf-8")
    result = tuple(native_records(artifact, day=6))
    assert [row.anomalous_native for row in result] == [False, False, False, True]


def test_export_reads_selected_queues_from_label_free_manifest(tmp_path):
    artifact = tmp_path / "artifact"
    graph = artifact / "graph_4_12"
    graph.mkdir(parents=True)
    window = "2018-04-12 sample.txt"
    rows = [
        {"time": index, "edge_type": "EVENT_WRITE", "srcmsg": "{'subject': 'p'}",
         "dstmsg": "{'file': 'f'}", "loss": loss}
        for index, loss in enumerate((*([1.0] * 9), 10.0))
    ]
    (graph / window).write_text("".join(f"{row!r}\n" for row in rows), encoding="utf-8")
    manifest = tmp_path / "queues.json"
    manifest.write_text(__import__("json").dumps({"queues": [{
        "queue_id": "q12", "windows": [window], "score": 123.0, "selected": True,
    }]}), encoding="utf-8")
    result = tuple(native_records(artifact, manifest, day=12))
    assert len(result) == 10
    assert result[-1].queue_ids == ("q12",)
    assert result[-1].queue_strength == 123.0


def test_export_keeps_loss_events_outside_queues_and_summary_is_a_scaffold(tmp_path):
    artifact = tmp_path / "artifact"
    graph = artifact / "graph_4_12"
    graph.mkdir(parents=True)
    selected = "2018-04-12 selected.txt"
    outside = "2018-04-12 outside.txt"
    base = lambda loss: {
        "time": int(loss * 10), "edge_type": "EVENT_WRITE",
        "srcmsg": "{'subject': 'p'}", "dstmsg": "{'file': 'f'}", "loss": loss,
    }
    (graph / selected).write_text(
        "".join(f"{base(loss)!r}\n" for loss in (*([1.0] * 20), 10.0, 11.0)),
        encoding="utf-8",
    )
    (graph / outside).write_text(
        "".join(f"{base(loss)!r}\n" for loss in (*([1.0] * 9), 20.0)),
        encoding="utf-8",
    )
    manifest = tmp_path / "queues.json"
    manifest.write_text(__import__("json").dumps({"queues": [{
        "queue_id": "q12", "windows": [selected], "score": 123.0, "selected": True,
    }]}), encoding="utf-8")
    result = tuple(native_records(artifact, manifest, day=12))
    assert any(row.window == outside and row.anomalous_native and not row.queue_ids for row in result)
    selected_anomalies = [row for row in result if row.window == selected and row.anomalous_native]
    assert len(selected_anomalies) == 2
    assert sum(row.summary_component is not None for row in selected_anomalies) == 1
