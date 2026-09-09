import gzip
import json

import pytest
from fastavro import writer

from tc_pruning.cdm import CDMStreamReader, normalize_cdm_record
from tc_pruning.models import EdgeRecord, NodeRecord


def _uuid(value: str) -> dict:
    return {"com.bbn.tc.schema.avro.cdm20.UUID": value}


def test_cdm20_subject_becomes_process_node_with_command_label():
    raw = {
        "datum": {
            "com.bbn.tc.schema.avro.cdm20.Subject": {
                "uuid": "subject-1",
                "type": "SUBJECT_PROCESS",
                "cmdLine": {"string": "/usr/bin/curl http://example"},
                "hostId": "host-1",
            }
        },
        "CDMVersion": "20",
    }

    assert normalize_cdm_record(raw) == [
        NodeRecord(
            uuid="subject-1",
            node_type="process",
            label="/usr/bin/curl http://example",
            host="host-1",
            properties={"cmdLine": "/usr/bin/curl http://example"},
        )
    ]


def test_subject_parent_is_preserved_as_process_lineage_edge():
    raw = {
        "datum": {
            "com.bbn.tc.schema.avro.cdm20.Subject": {
                "uuid": "child-1",
                "type": "SUBJECT_PROCESS",
                "parentSubject": _uuid("parent-1"),
                "startTimestampNanos": 123,
                "hostId": "host-1",
            }
        },
        "CDMVersion": "20",
    }

    observations = normalize_cdm_record(raw)

    assert observations[-1] == EdgeRecord(
        event_id="LINEAGE:child-1",
        src="parent-1",
        dst="child-1",
        relation="EVENT_FORK",
        timestamp_ns=123,
        host="host-1",
    )


@pytest.mark.parametrize(
    ("event_type", "expected_src", "expected_dst"),
    [
        ("EVENT_READ", "file-1", "subject-1"),
        ("EVENT_WRITE", "subject-1", "file-1"),
    ],
)
def test_event_direction_follows_information_flow(event_type, expected_src, expected_dst):
    raw = {
        "datum": {
            "com.bbn.tc.schema.avro.cdm20.Event": {
                "uuid": "event-1",
                "type": event_type,
                "subject": _uuid("subject-1"),
                "predicateObject": _uuid("file-1"),
                "timestampNanos": 1_524_000_000_000_000_000,
                "hostId": "host-1",
            }
        },
        "CDMVersion": "20",
    }

    assert normalize_cdm_record(raw) == [
        EdgeRecord(
            event_id="event-1",
            src=expected_src,
            dst=expected_dst,
            relation=event_type,
            timestamp_ns=1_524_000_000_000_000_000,
            host="host-1",
        )
    ]


def test_event_preserves_data_flow_amount_for_dependency_relevance():
    raw = {
        "datum": {
            "com.bbn.tc.schema.avro.cdm20.Event": {
                "uuid": "event-sized",
                "type": "EVENT_WRITE",
                "subject": _uuid("subject-1"),
                "predicateObject": _uuid("file-1"),
                "timestampNanos": 123,
                "hostId": "host-1",
                "size": {"long": 4096},
            }
        },
        "CDMVersion": "20",
    }

    observations = normalize_cdm_record(raw)

    assert observations[-1].data_size == 4096


def test_cadets_event_enriches_process_exec_and_predicate_path_nodes():
    raw = {
        "datum": {
            "com.bbn.tc.schema.avro.cdm18.Event": {
                "uuid": "event-enrich",
                "type": "EVENT_WRITE",
                "subject": _uuid("subject-1"),
                "predicateObject": _uuid("file-1"),
                "predicateObjectPath": {"string": "/home/alice/out.txt"},
                "timestampNanos": 10,
                "hostId": "host-1",
                "properties": {
                    "map": {"exec": "/usr/bin/python3", "ppid": "1"}
                },
            }
        },
        "CDMVersion": "18",
    }

    assert normalize_cdm_record(raw) == [
        NodeRecord(
            "subject-1",
            "process",
            "/usr/bin/python3",
            "host-1",
            properties={"exec": "/usr/bin/python3"},
        ),
        NodeRecord(
            "file-1",
            "file",
            "/home/alice/out.txt",
            "host-1",
            semantic_key="file:/home/*/out.txt",
            properties={"path": "/home/alice/out.txt"},
        ),
        EdgeRecord(
            "event-enrich",
            "subject-1",
            "file-1",
            "EVENT_WRITE",
            10,
            "host-1",
        ),
    ]


def test_cdm18_jsonl_gzip_stream_skips_bad_lines_and_tracks_stats(tmp_path):
    path = tmp_path / "trace.json.gz"
    good = {
        "datum": {
            "com.bbn.tc.schema.avro.cdm18.FileObject": {
                "uuid": "file-9",
                "baseObject": {"properties": None},
                "type": "FILE_OBJECT_FILE",
            }
        },
        "CDMVersion": "18",
    }
    with gzip.open(path, "wt", encoding="utf-8") as stream:
        stream.write(json.dumps(good) + "\n")
        stream.write("not-json\n")

    reader = CDMStreamReader([path])

    assert list(reader) == [
        NodeRecord(uuid="file-9", node_type="file", label="file-9", host="")
    ]
    assert reader.stats.records_read == 2
    assert reader.stats.records_malformed == 1
    assert reader.stats.observations_emitted == 1


def test_cdm20_file_uses_filename_as_human_readable_label():
    raw = {
        "datum": {
            "com.bbn.tc.schema.avro.cdm20.FileObject": {
                "uuid": "file-name-1",
                "type": "FILE_OBJECT_FILE",
                "filename": "/var/log/auth.log",
                "hostId": "host-1",
            }
        },
        "CDMVersion": "20",
    }

    assert normalize_cdm_record(raw) == [
        NodeRecord(
            "file-name-1",
            "file",
            "/var/log/auth.log",
            "host-1",
            properties={"filename": "/var/log/auth.log"},
        )
    ]


def test_cdm18_file_extracts_nested_path_and_builds_stable_semantic_key():
    raw = {
        "datum": {
            "com.bbn.tc.schema.avro.cdm18.FileObject": {
                "uuid": "file-nested-1",
                "type": "FILE_OBJECT_FILE",
                "baseObject": {
                    "properties": {
                        "map": {
                            "path": "/home/alice/projects/secret.txt",
                            "size": "42",
                        }
                    }
                },
                "hostId": "host-1",
            }
        },
        "CDMVersion": "18",
    }

    assert normalize_cdm_record(raw) == [
        NodeRecord(
            uuid="file-nested-1",
            node_type="file",
            label="/home/alice/projects/secret.txt",
            host="host-1",
            semantic_key="file:/home/*/projects/secret.txt",
            properties={"path": "/home/alice/projects/secret.txt", "size": "42"},
        )
    ]


def test_strict_reader_rejects_malformed_json(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text("{broken\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Malformed CDM JSON"):
        list(CDMStreamReader([path], strict=True))


def test_reader_expands_input_glob(tmp_path):
    for index in (1, 2):
        path = tmp_path / f"cadets-{index}.jsonl"
        path.write_text(json.dumps({
            "datum": {"com.bbn.tc.schema.avro.cdm20.Subject": {
                "uuid": f"subject-{index}", "type": "SUBJECT_PROCESS"
            }}
        }) + "\n", encoding="utf-8")

    observations = list(CDMStreamReader([tmp_path / "cadets-*.jsonl"]))

    assert [item.uuid for item in observations] == ["subject-1", "subject-2"]


def test_reader_reports_unmatched_input_pattern_clearly(tmp_path):
    with pytest.raises(FileNotFoundError, match="No CDM input files matched"):
        list(CDMStreamReader([tmp_path / "missing-*.json"]))


def test_avro_object_container_stream_preserves_union_record_name(tmp_path):
    path = tmp_path / "mini.bin"
    schema = {
        "type": "record",
        "name": "TCCDMDatum",
        "namespace": "com.bbn.tc.schema.avro",
        "fields": [
            {
                "name": "datum",
                "type": [
                    {
                        "type": "record",
                        "name": "Subject",
                        "fields": [
                            {"name": "uuid", "type": "string"},
                            {"name": "type", "type": "string"},
                            {"name": "cmdLine", "type": ["null", "string"], "default": None},
                            {"name": "hostId", "type": ["null", "string"], "default": None},
                        ],
                    }
                ],
            },
            {"name": "CDMVersion", "type": "string"},
        ],
    }
    with path.open("wb") as stream:
        writer(
            stream,
            schema,
            [
                {
                    "datum": {
                        "uuid": "avro-subject",
                        "type": "SUBJECT_PROCESS",
                        "cmdLine": "/usr/bin/ssh",
                        "hostId": "host-a",
                    },
                    "CDMVersion": "20",
                }
            ],
        )

    assert list(CDMStreamReader([path])) == [
        NodeRecord(
            "avro-subject",
            "process",
            "/usr/bin/ssh",
            "host-a",
            properties={"cmdLine": "/usr/bin/ssh"},
        )
    ]
