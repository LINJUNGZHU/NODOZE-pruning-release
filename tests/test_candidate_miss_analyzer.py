from tc_pruning.offline_analysis.candidate_miss import CandidateMissAnalyzer
from tc_pruning.investigation.semantics import InvestigationSemanticsRegistry
from tc_pruning.models import EdgeRecord, NodeRecord
from tc_pruning.store import ProvenanceStore


def _store(tmp_path, edges):
    store = ProvenanceStore(tmp_path / "miss.db")
    node_types = {
        endpoint: node_type
        for edge in edges
        for endpoint, node_type in (
            (edge.src, endpoint_type(edge.src)),
            (edge.dst, endpoint_type(edge.dst)),
        )
    }
    store.ingest(
        [NodeRecord(node, kind, node, "h") for node, kind in node_types.items()]
        + edges
    )
    return store


def endpoint_type(node):
    if node == "flow":
        return "socket"
    return "file" if node.startswith("f") else "process"


def test_reports_minimum_forward_path_and_relation_sequence(tmp_path):
    edges = [
        EdgeRecord("e1", "anchor", "fdrop", "EVENT_WRITE", 10, "h"),
        EdgeRecord("e2", "fdrop", "miss", "EVENT_READ", 20, "h"),
        EdgeRecord("noise", "anchor", "other", "EVENT_FORK", 30, "h"),
    ]
    with _store(tmp_path, edges) as store:
        record = CandidateMissAnalyzer(
            store, InvestigationSemanticsRegistry.cadets(), max_hops=4
        ).analyze("miss", {"anchor"}, cutoff_ns=40)

    assert record.nearest_anchor == "anchor"
    assert record.forward_temporal_path is True
    assert record.minimum_hops == 2
    assert record.minimum_valid_path == ("e1", "e2")
    assert record.relation_sequence == ("EVENT_WRITE", "EVENT_READ")
    assert "FILE_WRITE_READ_BRIDGE" in record.taxonomy_labels


def test_reports_backward_path_from_miss_to_anchor(tmp_path):
    edges = [
        EdgeRecord("e1", "miss", "child", "EVENT_FORK", 10, "h"),
        EdgeRecord("e2", "child", "anchor", "EVENT_FORK", 20, "h"),
    ]
    with _store(tmp_path, edges) as store:
        record = CandidateMissAnalyzer(
            store, InvestigationSemanticsRegistry.cadets(), max_hops=4
        ).analyze("miss", {"anchor"}, cutoff_ns=40)

    assert record.backward_temporal_path is True
    assert record.minimum_valid_path == ("e1", "e2")
    assert "FORWARD_DESCENDANT" in record.taxonomy_labels


def test_equal_time_and_unknown_relation_do_not_form_temporal_path(tmp_path):
    edges = [
        EdgeRecord("e1", "anchor", "mid", "EVENT_FORK", 10, "h"),
        EdgeRecord("e2", "mid", "miss", "EVENT_FORK", 10, "h"),
        EdgeRecord("mystery", "anchor", "miss", "EVENT_MYSTERY", 11, "h"),
    ]
    with _store(tmp_path, edges) as store:
        record = CandidateMissAnalyzer(
            store, InvestigationSemanticsRegistry.cadets(), max_hops=4
        ).analyze("miss", {"anchor"}, cutoff_ns=40)

    assert record.forward_temporal_path is False
    assert {"RELATION_UNSUPPORTED", "NO_TEMPORAL_PATH"} <= set(
        record.taxonomy_labels
    )


def test_control_descendant_can_coexist_with_network_label(tmp_path):
    edges = [
        EdgeRecord("fork", "parent", "miss", "EVENT_FORK", 10, "h"),
        EdgeRecord("net", "miss", "flow", "EVENT_CONNECT", 20, "h"),
        EdgeRecord("anchor-edge", "flow", "anchor", "EVENT_RECVFROM", 30, "h"),
    ]
    with _store(tmp_path, edges) as store:
        record = CandidateMissAnalyzer(
            store, InvestigationSemanticsRegistry.cadets(), max_hops=4
        ).analyze("miss", {"anchor"}, cutoff_ns=40)

    assert {"CONTROL_DESCENDANT", "NETWORK_MEDIATED"} <= set(
        record.taxonomy_labels
    )
