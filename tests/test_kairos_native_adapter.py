from tc_pruning.detectors.kairos_adapter import NativeKairosAdapter, NativeKairosEvent
from tc_pruning.models import EdgeRecord, NodeRecord
from tc_pruning.store import ProvenanceStore


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
