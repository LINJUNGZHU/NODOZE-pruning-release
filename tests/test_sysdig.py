import json

from tc_pruning.cli import main
from tc_pruning.models import EdgeRecord, NodeRecord
from tc_pruning.store import ProvenanceStore
from tc_pruning.sysdig import (
    SysdigStreamReader,
    load_depimpact_property,
    resolve_depimpact_poi,
    stable_entity_id,
)


SYSDIG_LINES = """\
100 1595768979.226817322 2 0 john (18976) > write cwd=/tmp/john/ fd=1(<f>/tmp/john/password_crack.txt) size=124 latency=0 exepath=/tmp/john/john
101 1595768979.226832508 2 0 john (18976) < write cwd=/tmp/john/ res=124 data=secret latency=15186 exepath=/tmp/john/john
102 1595768982.777189455 2 0 scp (19043) > read cwd=/root/ fd=3(<f>/tmp/john/password_crack.txt) size=124 latency=0 exepath=/usr/bin/scp
103 1595768982.777193719 2 0 scp (19043) < read cwd=/root/ res=124 data=secret latency=4264 exepath=/usr/bin/scp
"""


def test_sysdig_reader_pairs_enter_exit_and_preserves_information_flow(tmp_path):
    source = tmp_path / "trace.log"
    source.write_text(SYSDIG_LINES, encoding="utf-8")

    observations = list(SysdigStreamReader([source], host="crackhost2"))

    file_id = stable_entity_id("file", "/tmp/john/password_crack.txt", "crackhost2")
    john_id = stable_entity_id("process", "18976", "crackhost2")
    scp_id = stable_entity_id("process", "19043", "crackhost2")
    assert NodeRecord(file_id, "file", "/tmp/john/password_crack.txt", "crackhost2") in observations
    assert EdgeRecord(
        "sysdig:101", john_id, file_id, "EVENT_WRITE",
        1_595_768_979_226_832_508, "crackhost2", 124,
    ) in observations
    assert EdgeRecord(
        "sysdig:103", file_id, scp_id, "EVENT_READ",
        1_595_768_982_777_193_719, "crackhost2", 124,
    ) in observations


def test_depimpact_property_resolves_matching_write_as_backward_poi(tmp_path):
    source = tmp_path / "trace.log"
    source.write_text(SYSDIG_LINES, encoding="utf-8")
    properties = tmp_path / "example.property_demo"
    properties.write_text(
        "POI = /tmp/john/password_crack.txt\n"
        "highRP = /tmp/john/password_crack.txt\n"
        "detectionSize = 124\n",
        encoding="utf-8",
    )

    specification = load_depimpact_property(properties)
    with ProvenanceStore(tmp_path / "graph.db") as store:
        store.ingest(SysdigStreamReader([source], host="crackhost2"))
        manifest = resolve_depimpact_poi(store, specification)

    assert manifest["event_ids"] == ["sysdig:101"]
    assert manifest["metadata"]["poi"] == "/tmp/john/password_crack.txt"
    assert manifest["metadata"]["selection_rule"] == "latest_matching_size_write"


def test_ingest_sysdig_cli_keeps_existing_pipeline_and_writes_poi_manifest(tmp_path):
    source = tmp_path / "trace.log"
    source.write_text(SYSDIG_LINES, encoding="utf-8")
    properties = tmp_path / "example.property_demo"
    properties.write_text(
        "POI=/tmp/john/password_crack.txt\ndetectionSize=124\n",
        encoding="utf-8",
    )
    database = tmp_path / "graph.db"
    poi_output = tmp_path / "poi.json"

    assert main([
        "ingest-sysdig",
        "--input", str(source),
        "--db", str(database),
        "--poi-property", str(properties),
        "--poi-output", str(poi_output),
        "--host", "crackhost2",
    ]) == 0

    document = json.loads(poi_output.read_text(encoding="utf-8"))
    assert document["event_ids"] == ["sysdig:101"]
    with ProvenanceStore(database) as store:
        assert store.edge_count() == 2
