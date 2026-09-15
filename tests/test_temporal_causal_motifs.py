from tc_pruning.investigation.motifs import MotifType, TemporalCausalMotifBuilder
from tc_pruning.models import StoredEdge


def _edge(i, src, dst, relation, timestamp, src_type="process", dst_type="file"):
    return StoredEdge(i, f"e{i}", src, dst, relation, timestamp, "h", src_type, dst_type, src, dst, None)


def test_file_transfer_requires_strict_write_then_read():
    edges = (
        _edge(1, "p1", "file", "EVENT_WRITE", 10),
        _edge(2, "file", "p2", "EVENT_READ", 20, "file", "process"),
        _edge(3, "p3", "same", "EVENT_WRITE", 30),
        _edge(4, "same", "p4", "EVENT_READ", 30, "file", "process"),
    )
    motifs = TemporalCausalMotifBuilder().build(edges)
    transfers = [m for m in motifs if m.motif_type is MotifType.FILE_TRANSFER]
    assert [m.raw_event_ids for m in transfers] == [("e1", "e2")]


def test_drop_execute_requires_both_raw_witnesses():
    complete = (
        _edge(1, "dropper", "payload", "EVENT_WRITE", 10),
        _edge(2, "runner", "payload", "EVENT_EXECUTE", 20),
    )
    assert any(m.motif_type is MotifType.DROP_EXECUTE for m in TemporalCausalMotifBuilder().build(complete))
    assert not any(m.motif_type is MotifType.DROP_EXECUTE for m in TemporalCausalMotifBuilder().build(complete[:1]))


def test_control_network_receive_and_common_cause_motifs_have_witnesses():
    edges = (
        _edge(1, "parent", "a", "EVENT_FORK", 10, "process", "process"),
        _edge(2, "parent", "b", "EVENT_FORK", 11, "process", "process"),
        _edge(3, "b", "flow", "EVENT_CONNECT", 12, "process", "socket"),
        _edge(4, "flow2", "parent", "EVENT_RECVFROM", 5, "socket", "process"),
        _edge(5, "child", "image", "EVENT_EXECUTE", 20, "process", "file"),
        _edge(6, "parent", "child", "EVENT_FORK", 15, "process", "process"),
    )
    motifs = TemporalCausalMotifBuilder().build(
        edges, anchor_ids={"a"}, verified_terminal_ids={"flow"}
    )
    kinds = {motif.motif_type for motif in motifs}
    assert {MotifType.CONTROL_SPAWN, MotifType.NETWORK_CONSEQUENCE, MotifType.RECEIVE_TO_EXECUTION, MotifType.COMMON_CAUSE_BRANCH} <= kinds
    assert all(motif.raw_event_cost == len(set(motif.raw_event_ids)) for motif in motifs)


def test_cross_anchor_bridge_and_unique_raw_event_cost():
    edges = tuple(
        _edge(i, f"n{i-1}", f"n{i}", "EVENT_FORK", i, "process", "process")
        for i in range(1, 9)
    )
    motifs = TemporalCausalMotifBuilder(max_bridge_hops=8).build(edges, anchor_ids={"n0", "n8"})
    bridge = next(m for m in motifs if m.motif_type is MotifType.CROSS_ANCHOR_BRIDGE)
    assert bridge.raw_event_cost == 8
    assert bridge.raw_event_ids == tuple(f"e{i}" for i in range(1, 9))
