import json

from webapp.backend.app import create_app


def test_health_and_demo_graph(tmp_path):
    cache = tmp_path / "demo.json"
    cache.write_text(json.dumps({
        "dataset": {"id": "demo", "name": "Demo", "description": "test"},
        "metrics": {"candidate_edges": 1},
        "nodes": [], "edges": [], "paths": [], "prefix_metrics": [], "sample": {},
    }), encoding="utf-8")
    client = create_app(cache).test_client()

    assert client.get("/api/health").get_json()["cache_ready"] is True
    assert client.get("/api/datasets").get_json()["datasets"][0]["id"] == "demo"
    assert client.get("/api/datasets/demo/graph").status_code == 200
    assert client.get("/api/datasets/missing/graph").status_code == 404


def test_import_rejects_empty_request(tmp_path):
    client = create_app(tmp_path / "missing.json").test_client()
    response = client.post("/api/imports")
    assert response.status_code == 400
