"""Offline-only evaluation of externally pinned production outputs."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3

from .detector_seed_production import RUN_IDS, file_sha, digest_json, verify_file, write_json, validate_config
from .seed_utility_evaluation import partial_positive_metrics


def _bound(root, relative):
    result = (root / relative).resolve()
    if root not in result.parents:
        raise ValueError("artifact target escapes pinned root")
    return result


def evaluate_production(pin_path, known_event_ids, known_node_ids, output, *, positives_pin=None):
    result = {"status": "NOT_COMPLETED", "runs": {}}
    if positives_pin is not None:
        result["positive_authority"] = positives_pin
    may_write = False
    try:
        pin_path, output = Path(pin_path).resolve(), Path(output).resolve()
        pin = json.loads(pin_path.read_text())
        if pin.get("status") != "COMPLETED" or tuple(pin.get("runs", ())) != RUN_IDS:
            raise ValueError("external pin is NOT_COMPLETED or has invalid run IDs")
        root = Path(pin["root"]).resolve()
        if pin_path == root or root in pin_path.parents or output == root or root in output.parents:
            raise ValueError("external pin and offline output must be outside online root")
        may_write = True
        manifest_file = root / "manifest.json"
        if file_sha(manifest_file) != pin["manifest_sha256"]:
            raise ValueError("externally pinned manifest changed")
        manifest = json.loads(manifest_file.read_text())
        if manifest.get("status") != "COMPLETED" or set(manifest["runs"]) != set(RUN_IDS):
            raise ValueError("online root is NOT_COMPLETED")
        actual_files = {str(path.relative_to(root)) for path in root.rglob("*") if path.is_file() and path != manifest_file}
        if actual_files != set(manifest["files"]):
            raise ValueError("artifact file set differs from external pin")
        for relative, info in manifest["files"].items():
            verify_file(dict(info, path=str(_bound(root, relative))))
        config = json.loads((root / "config.json").read_text())
        if manifest.get("config_source"):
            verify_file(manifest["config_source"])
        if digest_json(config) != manifest["config_sha256"]:
            raise ValueError("config derivation mismatch")
        validate_config(config, allow_test=bool(manifest.get("test_only")))
        verify_file(manifest["database_start"])
        verify_file(manifest["database_end"])
        events, nodes = set(known_event_ids), set(known_node_ids)
        db = sqlite3.connect(Path(config["database"]["path"]).resolve().as_uri() + "?mode=ro", uri=True)
        try:
            raw = {event for event in events if db.execute("SELECT 1 FROM edges WHERE event_id=?", (event,)).fetchone()}
        finally:
            db.close()
        for run_id in RUN_IDS:
            target = manifest["runs"][run_id]
            if target["run_id"] != run_id or target["status"] != "COMPLETED":
                raise ValueError("run attribution mismatch")
            expected_detector = "VELOX"
            if target["detector_id"] != expected_detector or target["directory"] != "runs/" + run_id or target["population"] != "populations/" + expected_detector:
                raise ValueError("run/population target mismatch")
            directory = _bound(root, target["directory"])
            population = _bound(root, target["population"])
            if target["evidence_sha256"] != file_sha(population / "evidence.jsonl") or target["evidence_sha256"] != manifest["population_derivation"][expected_detector]:
                raise ValueError("evidence derivation mismatch")
            summary = json.loads((population / "population.json").read_text())
            if summary["source"] != config["populations"][expected_detector] or summary["stage_sha256"] != file_sha(population / "stage.sqlite"):
                raise ValueError("native/development/stage derivation mismatch")
            candidate = json.loads((directory / "candidate.json").read_text())
            a, b = [json.loads((directory / (name + ".json")).read_text()) for name in ("A_rasp", "C_branch_fair")]
            if any(item["run_id"] != run_id or item["detector_id"] != expected_detector for item in (a, b)):
                raise ValueError("selector result attribution mismatch")
            candidate_ids, candidate_nodes = set(candidate["event_ids"]), set(candidate["node_ids"])
            a_ids, b_ids = set(a["selected_raw_event_ids"]), set(b["selected_raw_event_ids"])
            if not a_ids <= candidate_ids or not b_ids <= candidate_ids:
                raise ValueError("selector contains events outside candidate")
            conn = sqlite3.connect((population / "stage.sqlite").resolve().as_uri() + "?mode=ro", uri=True)
            try:
                stage_hits = {name: {event for event in events if conn.execute("SELECT 1 FROM stage_identity WHERE stage=? AND kind='event' AND identity=?", (name, event)).fetchone()}
                              for name in ("preprocessing", "inference", "scored", "native_threshold", "evidence")}
                direct_nodes = {node for node in nodes if conn.execute("SELECT 1 FROM stage_identity WHERE stage='native_threshold' AND kind='node' AND identity=?", (node,)).fetchone()}
            finally:
                conn.close()
            edge_nodes = {str(edge["event_id"]): {str(edge["src"]), str(edge["dst"])} for edge in candidate["edges"]}
            def final_metrics(selected, payload):
                metrics = partial_positive_metrics(selected, events)
                final_nodes = set().union(*(edge_nodes.get(event, set()) for event in selected)) if selected else set()
                metrics.update(node_recall=len(final_nodes & nodes) / len(nodes) if nodes else None,
                               known_attack_nodes=len(final_nodes & nodes),
                               raw_events=payload["raw_events"], projected_edges=payload["projected_edges"])
                return metrics
            funnel = {"raw_database": partial_positive_metrics(raw, events),
                      "preprocessing": partial_positive_metrics(stage_hits["preprocessing"], events),
                      "inference": {"status": "SCORED_OUTPUT_LOWER_BOUND", "known_ids": sorted(stage_hits["inference"])},
                      "scored": partial_positive_metrics(stage_hits["scored"], events),
                      "native_threshold": partial_positive_metrics(stage_hits["native_threshold"], events),
                      "evidence": partial_positive_metrics(stage_hits["evidence"], events),
                      "candidate": partial_positive_metrics(candidate_ids, events),
                      "final": partial_positive_metrics(a_ids, events)}
            result["runs"][run_id] = {"status": "COMPLETED", "run_id": run_id, "detector_id": expected_detector,
                "candidate": partial_positive_metrics(candidate_ids, events),
                "candidate_node_recall": len(candidate_nodes & nodes) / len(nodes) if nodes else None,
                "candidate_raw_events": candidate["raw_events"], "candidate_projected_edges": candidate["projected_edges"],
                "A_rasp": final_metrics(a_ids, a), "C_branch_fair": final_metrics(b_ids, b),
                "direct_attack_node_hits": sorted(direct_nodes), "mapping": summary["counts"], "funnel": funnel}
        result["status"] = "COMPLETED"
    except Exception as exc:
        result["status"] = "NOT_COMPLETED"
        result["reason"] = str(exc)
    if may_write:
        output = Path(output)
        output.mkdir(parents=True, exist_ok=True)
        write_json(output / "evaluation.json", result)
    return result
