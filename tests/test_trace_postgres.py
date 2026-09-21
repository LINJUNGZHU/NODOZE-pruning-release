import csv
import io

from tc_pruning.trace_postgres import CopyTextStream, event_rows, node_rows


def test_node_rows_preserve_uuid_and_kairos_features():
    source = [
        (1, "PROC", "process", "/usr/bin/bash", '{"cmdLine":"bash -c id"}'),
        (2, "FILE", "file", "/tmp/a\tfile", '{"path":"/tmp/a\\tfile"}'),
        (3, "NET", "socket", "ignored", '{"localAddress":"10.0.0.1","localPort":"1","remoteAddress":"8.8.8.8","remotePort":"53"}'),
    ]

    assert list(node_rows(source, "process")) == [
        ("PROC", "PROC", "/usr/bin/bash", "bash -c id", 1),
    ]
    assert list(node_rows(source, "file")) == [
        ("FILE", "FILE", "/tmp/a\tfile", 2),
    ]
    assert list(node_rows(source, "socket")) == [
        ("NET", "NET", "10.0.0.1", "1", "8.8.8.8", "53", 3),
    ]


def test_node_rows_can_assign_dense_ids_independent_of_sparse_sqlite_rowids():
    source = [
        (100, "A", "process", "a", "{}"),
        (9000, "B", "process", "b", "{}"),
    ]

    assert [row[-1] for row in node_rows(source, "process", index_start=17)] == [17, 18]


def test_event_rows_keep_pre_normalized_direction_and_drop_non_kairos_relations():
    source = [
        (9, "READ-ID", "FILE", 2, "EVENT_READ", "PROC", 1, 123),
        (10, "FORK-ID", "PROC", 1, "EVENT_FORK", "CHILD", 4, 124),
    ]

    assert list(event_rows(source)) == [
        ("FILE", 2, "EVENT_READ", "PROC", 1, "READ-ID", 123),
    ]


def test_copy_text_stream_emits_valid_tab_delimited_csv_in_small_reads():
    stream = CopyTextStream([("a\tb", None, 'say "hi"'), ("line\n2", "", 7)])
    encoded = ""
    while True:
        part = stream.read(3)
        if not part:
            break
        encoded += part

    rows = list(csv.reader(io.StringIO(encoded), delimiter="\t"))
    assert rows == [["a\tb", r"\N", 'say "hi"'], ["line\n2", "", "7"]]
