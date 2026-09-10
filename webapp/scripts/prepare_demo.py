from __future__ import annotations

import argparse
import gzip
import json
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_RUN = (
    PROJECT_DIR / "output/tc/theia-case3-poi-prefix-fixed-2026-09-09_23-36-33"
)
DEFAULT_OUTPUT = PROJECT_DIR / "webapp/runtime/theia-case3-demo.json"


def read_rows(path: Path):
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        for line in stream:
            yield json.loads(line)


def is_kept(row: dict) -> bool:
    return any(
        decision.get("budget_key") == "0.2" and decision.get("kept") is True
        for decision in row.get("decisions", [])
    )


def compact_edge(row: dict, path_membership: dict[str, list[str]], truth: set[str]) -> dict:
    components = row.get("components", {})
    return {
        "id": row["event_id"],
        "source": row["src"],
        "target": row["dst"],
        "relation": row["relation"],
        "timestamp_ns": row["timestamp_ns"],
        "score": row.get("score", 0.0),
        "rank": row.get("rank"),
        "retained": is_kept(row),
        "poi": bool(row.get("is_declared_poi")),
        "attack_truth": row["event_id"] in truth,
        "attack_paths": path_membership.get(row["event_id"], []),
        "components": {
            key: components.get(key, 0.0)
            for key in ("rarity", "diffusion", "depimpact", "behavior")
        },
        "reasons": sorted({
            reason
            for decision in row.get("decisions", [])
            if decision.get("budget_key") == "0.2"
            for reason in decision.get("reasons", [])
        }),
        "source_label": row.get("src_semantic") or row["src"],
        "target_label": row.get("dst_semantic") or row["dst"],
        "source_type": row.get("src_type", "unknown"),
        "target_type": row.get("dst_type", "unknown"),
    }


def build(run_dir: Path, output: Path, context_per_class: int = 550) -> dict:
    scenario = run_dir / "scenario-theia-case3"
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    reference = json.loads((scenario / "fixed-reference.json").read_text(encoding="utf-8"))
    ledger = scenario / "poi-prefix-3-ledger/edge-scores.jsonl.gz"
    paths = [
        {"id": f"path-{index}", "event_ids": list(events)}
        for index, events in enumerate(reference.get("attack_paths", []), 1)
    ]
    membership: dict[str, list[str]] = {}
    for path in paths:
        for event_id in path["event_ids"]:
            membership.setdefault(event_id, []).append(path["id"])
    required = set(membership)
    truth = set(reference.get("attack_event_ids", []))

    path_rows: dict[str, dict] = {}
    for row in read_rows(ledger):
        if row["event_id"] in required:
            path_rows[row["event_id"]] = row
    path_nodes = {
        endpoint for row in path_rows.values() for endpoint in (row["src"], row["dst"])
    }

    selected: dict[str, dict] = dict(path_rows)
    counts = {"retained": 0, "removed": 0}
    top_counts = {"retained": 0, "removed": 0}
    for row in read_rows(ledger):
        event_id = row["event_id"]
        if event_id in selected:
            continue
        bucket = "retained" if is_kept(row) else "removed"
        contextual = row["src"] in path_nodes or row["dst"] in path_nodes
        if contextual and counts[bucket] < context_per_class:
            selected[event_id] = row
            counts[bucket] += 1
        elif top_counts[bucket] < 100:
            selected[event_id] = row
            top_counts[bucket] += 1

    edges = [compact_edge(row, membership, truth) for row in selected.values()]
    edges.sort(key=lambda row: (row["timestamp_ns"], row["id"]))
    nodes: dict[str, dict] = {}
    for edge in edges:
        for side in ("source", "target"):
            node_id = edge[side]
            nodes.setdefault(node_id, {
                "id": node_id,
                "label": edge[f"{side}_label"],
                "type": edge[f"{side}_type"],
                "attack": False,
                "poi": False,
            })
        if edge["attack_truth"] or edge["attack_paths"]:
            nodes[edge["source"]]["attack"] = True
            nodes[edge["target"]]["attack"] = True
        if edge["poi"]:
            nodes[edge["source"]]["poi"] = True
            nodes[edge["target"]]["poi"] = True

    rows = summary["rows"]
    final = rows[-1]
    document = {
        "dataset": {
            "id": "theia-case3",
            "name": "DARPA THEIA E3 Case 3",
            "description": "PDF-validated POIs with a precomputed PS-RDP 20% edge budget",
        },
        "metrics": {
            "candidate_edges": final["candidate_events"],
            "retained_edges": final["kept_events"],
            "compression_ratio": final["event_compression_ratio"],
            "attack_event_recall": final["attack_event_recall"],
            "retained_paths": final["retained_reference_paths"],
            "reference_paths": final["reference_paths"],
            "poi_count": final["poi_count"],
            "ledger_valid": final["score_ledger_valid"],
        },
        "prefix_metrics": rows,
        "paths": paths,
        "nodes": sorted(nodes.values(), key=lambda row: row["id"]),
        "edges": edges,
        "sample": {
            "edge_count": len(edges),
            "node_count": len(nodes),
            "policy": "all certified path events plus retained/removed one-hop context and top-score anchors",
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(".tmp")
    temporary.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
    temporary.replace(output)
    return document


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", type=Path, default=DEFAULT_RUN)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--context-per-class", type=int, default=550)
    args = parser.parse_args()
    result = build(args.run_dir, args.output, args.context_per_class)
    print(json.dumps({
        "output": str(args.output.resolve()),
        "nodes": len(result["nodes"]),
        "edges": len(result["edges"]),
        "paths": len(result["paths"]),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
