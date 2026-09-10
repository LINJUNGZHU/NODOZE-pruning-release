import copy
import json

from webapp.scripts.resolve_entities import enrich


def test_enrichment_preserves_event_evidence_and_does_not_invent_labels(tmp_path):
    document = {
        "nodes": [
            {"id": "file-id", "label": "file-id", "type": "unknown"},
            {"id": "missing-id", "label": "missing-id", "type": "unknown"},
        ],
        "edges": [{"id": "event-id", "source": "missing-id", "target": "file-id",
                   "score": 0.123, "retained": False, "attack_paths": ["path-2"],
                   "components": {"depimpact": 0.00002148}}],
    }
    original = copy.deepcopy(document["edges"][0])
    source = tmp_path / "raw.json"
    source.write_text(json.dumps({"datum": {"com.bbn.tc.schema.avro.cdm18.FileObject": {
        "uuid": "file-id", "baseObject": {"properties": {
            "map": {"filename": "/etc/ld.so.cache"}}}, "type": "FILE_OBJECT_BLOCK"
    }}}) + "\n")
    result = enrich(document, [source])
    edge = result["edges"][0]
    assert "/etc/ld.so.cache" in edge["target_label"]
    assert edge["target_label_evidence"] == {"file": "raw.json", "line": 1}
    assert edge["source_label"] == "missing-id"
    assert result["entity_resolution"]["unresolved"] == 1
    for key, value in original.items():
        assert edge[key] == value
