"""Local reference preparation validates the entire batch before writing."""
import importlib.util
import json
from pathlib import Path

import pytest


SCENARIOS = ("06", "12", "13")


def helper():
    assert importlib.util.find_spec("scripts.prepare_chain_references") is not None, "reference preparation helper is not implemented"
    from scripts import prepare_chain_references
    return prepare_chain_references


def source_documents(directory):
    directory.mkdir()
    documents = {}
    for code in SCENARIOS:
        document = {
            "attack_event_ids": [f"PRIVATE-EVENT-{code}"],
            "metadata": {"groundtruth_family": "CAPTAIN/human_readable_gt", "scenario": code,
                         "groundtruth_source_sha256": f"synthetic-hash-{code}"},
            "attack_node_uuids": ["PRIVATE-NODE"], "attack_paths": [["PRIVATE-PATH"]],
            "seed_event_ids": ["PRIVATE-SEED"], "name": "discard this field",
        }
        (directory / f"cadets-e3-captain-{code}-annotations.json").write_text(json.dumps(document))
        documents[code] = document
    return documents


def test_success_copies_only_ids_and_metadata_and_prints_no_event_ids(tmp_path, capsys):
    sources, output = tmp_path / "poi", tmp_path / "references"
    documents = source_documents(sources)
    assert helper().main(["--source-directory", str(sources), "--output-directory", str(output)]) == 0
    for code, document in documents.items():
        target = json.loads((output / f"cadets-{code}.json").read_text())
        assert target == {"attack_event_ids": document["attack_event_ids"], "metadata": document["metadata"]}
    captured = capsys.readouterr()
    assert "PRIVATE-" not in captured.out + captured.err
    assert str(output) in captured.out
    assert len(list(output.iterdir())) == 3


def test_preparation_is_idempotent_without_rewriting_matching_files(tmp_path):
    sources, output = tmp_path / "poi", tmp_path / "references"
    source_documents(sources)
    m = helper()
    m.prepare_references(sources, output)
    previous = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in output.iterdir()}
    summary = m.prepare_references(sources, output)
    assert previous == {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in output.iterdir()}
    assert all(row["status"] == "unchanged" for row in summary)


@pytest.mark.parametrize("change", ["family", "scenario", "invalid_id", "not_a_list", "bad_metadata", "missing"])
def test_invalid_last_source_does_not_create_partial_outputs(tmp_path, change):
    sources, output = tmp_path / "poi", tmp_path / "references"
    documents = source_documents(sources)
    last = sources / "cadets-e3-captain-13-annotations.json"
    document = documents["13"]
    if change == "family":
        document["metadata"]["groundtruth_family"] = "untrusted"
    elif change == "scenario":
        document["metadata"]["scenario"] = "12"
    elif change == "invalid_id":
        document["attack_event_ids"] = ["PRIVATE-BAD-ID", None]
    elif change == "not_a_list":
        document["attack_event_ids"] = "PRIVATE-BAD-ID"
    elif change == "bad_metadata":
        document["metadata"] = None
    if change == "missing":
        last.unlink()
    else:
        last.write_text(json.dumps(document))
    with pytest.raises((ValueError, FileNotFoundError)):
        helper().prepare_references(sources, output)
    assert not output.exists()


def test_conflicting_last_destination_prevents_all_new_writes(tmp_path):
    sources, output = tmp_path / "poi", tmp_path / "references"
    docs = source_documents(sources)
    output.mkdir()
    conflicting = {"attack_event_ids": ["PRIVATE-DIFFERENT"], "metadata": docs["13"]["metadata"]}
    path = output / "cadets-13.json"
    path.write_text(json.dumps(conflicting))
    original = path.read_bytes()
    with pytest.raises(ValueError, match="conflict"):
        helper().prepare_references(sources, output)
    assert list(output.iterdir()) == [path]
    assert path.read_bytes() == original


def test_existing_malformed_destination_is_rejected_before_writes(tmp_path):
    sources, output = tmp_path / "poi", tmp_path / "references"
    source_documents(sources)
    output.mkdir()
    path = output / "cadets-12.json"
    path.write_text('{"attack_event_ids": [null], "metadata": {}}')
    with pytest.raises(ValueError):
        helper().prepare_references(sources, output)
    assert list(output.iterdir()) == [path]


def test_same_content_with_different_json_format_is_unchanged(tmp_path):
    sources, output = tmp_path / "poi", tmp_path / "references"
    docs = source_documents(sources)
    output.mkdir()
    for code, doc in docs.items():
        (output / f"cadets-{code}.json").write_text(json.dumps({"metadata": doc["metadata"], "attack_event_ids": doc["attack_event_ids"]}, indent=4))
    summary = helper().prepare_references(sources, output)
    assert all(row["status"] == "unchanged" for row in summary)


def test_cli_error_does_not_echo_invalid_raw_ids(tmp_path, capsys):
    sources, output = tmp_path / "poi", tmp_path / "references"
    docs = source_documents(sources)
    docs["13"]["attack_event_ids"] = {"PRIVATE-DO-NOT-PRINT": True}
    (sources / "cadets-e3-captain-13-annotations.json").write_text(json.dumps(docs["13"]))
    assert helper().main(["--source-directory", str(sources), "--output-directory", str(output)]) == 1
    text = capsys.readouterr()
    assert "PRIVATE-" not in text.out + text.err
    assert not output.exists()
