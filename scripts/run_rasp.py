"""Recompute RASP scores on frozen candidates; compare at matched edge caps."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import resource
import time
from pathlib import Path

import numpy as np

from tc_pruning.rasp import propagate, select_bundles, select_fork_bundles, temporal_fork_routes, temporal_routes


def write_json(path, value):
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2))
    temp.replace(path)


def load_candidates(path):
    fields = {k: [] for k in ("src", "dst", "timestamp", "relation", "rarity", "poi", "old_score", "old_kept", "tie")}
    ids, nodes, relations, process_nodes = [], {}, {}, set()
    digest = hashlib.sha256()
    with gzip.open(path, "rt") as stream:
        for i, line in enumerate(stream):
            r = json.loads(line)
            ids.append(r["event_id"])
            a = nodes.setdefault(r["src"], len(nodes))
            b = nodes.setdefault(r["dst"], len(nodes))
            for node, kind in ((a, r["src_type"]), (b, r["dst_type"])):
                if kind == "process":
                    process_nodes.add(node)
            # Match the main CDM scorer: execute carries file -> process flow.
            if r["relation"] == "EVENT_EXECUTE":
                a, b = b, a
            values = (a, b, r["timestamp_ns"], relations.setdefault(r["relation"], len(relations)),
                      r["components"]["rarity"], bool(r.get("is_declared_poi")), r["score"],
                      any(d["budget_key"] == "0.2" and d["kept"] for d in r["decisions"]),
                      int.from_bytes(hashlib.sha256(r["event_id"].encode()).digest()[:8], "big"))
            for key, value in zip(fields, values):
                fields[key].append(value)
            # Exclude old scores/decisions and labels from the new-score digest.
            digest.update(json.dumps([r["event_id"], a, b, *values[2:6]], separators=(",", ":")).encode())
            if i and i % 250000 == 0:
                print(f"loaded {i:,} candidate events", flush=True)
    data = {k: np.asarray(v, dtype=np.uint64 if k == "tie" else None) for k, v in fields.items()}
    process = np.zeros(len(nodes), dtype=bool)
    process[list(process_nodes)] = True
    data.update(ids=ids, process_nodes=process, node_ids=list(nodes), input_sha256=digest.hexdigest())
    return data


def run(ledger, reference, output, config_path, cache=None):
    config = json.loads(config_path.read_text())
    started = time.perf_counter()
    output.mkdir(parents=True, exist_ok=False)
    write_json(output/"config.json", config)
    implementation_hash = hashlib.sha256(Path("tc_pruning/rasp.py").read_bytes()).hexdigest()
    d = load_candidates(ledger)
    n = len(d["ids"])
    score_started = time.perf_counter()
    print(f"Scoring {n:,} events using new propagation", flush=True)
    args = (d["src"], d["dst"], d["relation"], d["rarity"], d["poi"], d["process_nodes"], config)
    score, evidence = propagate(*args)
    no_rarity, _ = propagate(d["src"], d["dst"], d["relation"], np.zeros(n), d["poi"], d["process_nodes"], config)
    score_seconds = time.perf_counter()-score_started
    links, direction, reachable, depth = temporal_routes(d["src"], d["dst"], d["timestamp"], d["poi"])
    fork_parent, pivot, fork_reachable, fork_depth = temporal_fork_routes(d["src"], d["dst"], d["timestamp"], d["poi"], links[0])
    masks, anchors, results = {}, {}, []
    specs = [("original_ps_rdp", .2, d["old_score"], "original")]
    for ratio in config["budgets"]:
        specs += [("old_score_top", ratio, d["old_score"], "top"),
                  ("rasp_top", ratio, score, "top"), ("rasp_paths", ratio, score, "paths"),
                  ("rasp_forks", ratio, score, "forks")]
    specs += [("rasp_no_rarity", config["primary_budget"], no_rarity, "forks")]
    specs += [("rasp_no_contrast", config["primary_budget"], evidence["uncontrasted"], "forks")]
    specs += [("rasp_hard_contrast", config["primary_budget"], evidence["contrast_only"], "forks")]
    for method, ratio, rank_score, mode in specs:
        key = f"{method}@{ratio:g}"
        budget = max(int(d["poi"].sum()), int(n*ratio))
        if budget != int(n*ratio):
            raise ValueError("budget below POI count; do not silently enlarge cap")
        tick = time.perf_counter()
        if mode == "original":
            kept = d["old_kept"].copy()
            anchor = kept.copy()
        elif mode == "top":
            kept = d["poi"].copy()
            order = np.lexsort((d["tie"], -rank_score))
            rest = order[~kept[order]][:budget-int(kept.sum())]
            kept[rest] = True
            anchor = kept.copy()
        elif mode == "forks":
            kept, anchor = select_fork_bundles(rank_score, d["poi"], links[0], fork_parent, pivot, budget, d["tie"])
        else:
            kept, anchor = select_bundles(rank_score, d["poi"], links, direction, reachable, budget, d["tie"])
        masks[key], anchors[key] = kept, anchor
        if mode != "original":
            assert kept.sum() <= budget
        # Audit actual retained reachability under the SAME CDM orientation and
        # anchored-time semantics for old and new methods.
        _, _, sub_reachable, _ = temporal_routes(d["src"][kept], d["dst"][kept], d["timestamp"][kept], d["poi"][kept])
        lost = int((kept & reachable).sum())-int(sub_reachable.sum())
        if mode == "paths":
            assert lost == 0
        _, _, retained_fork_reach, _ = temporal_fork_routes(d["src"][kept], d["dst"][kept], d["timestamp"][kept], d["poi"][kept])
        lost_fork = int((kept & fork_reachable).sum())-int(retained_fork_reach.sum())
        if mode == "forks":
            assert lost_fork == 0
        result = {"method": key, "budget_ratio": ratio, "budget_edges": budget,
                  "candidate_edges": n, "retained_edges": int(kept.sum()),
                  "compression_ratio": 1-float(kept.mean()), "unused_budget": budget-int(kept.sum()),
                  "connector_edges": int((kept & ~anchor).sum()), "lost_poi_connections": lost,
                  "lost_fork_connections": lost_fork,
                  "reachable_retained": int(sub_reachable.sum()), "selection_audit_seconds": time.perf_counter()-tick}
        results.append(result)
        print(json.dumps(result), flush=True)
    # All methods/parameters/masks fixed before loading labels.
    truth = json.loads(reference.read_text())
    attack = set(truth["attack_event_ids"])
    paths = truth["attack_paths"]
    needed = attack | {e for path in paths for e in path}
    index = {e: i for i, e in enumerate(d["ids"]) if e in needed}
    truth_index = np.asarray([index[e] for e in attack if e in index], dtype=int)
    for result in results:
        kept = masks[result["method"]]
        tp = int(kept[truth_index].sum())
        result.update(attack_events=len(attack), attack_in_candidates=len(truth_index), retained_attack_events=tp,
                      attack_event_recall=tp/len(attack) if attack else None,
                      reference_paths=len(paths), retained_paths=sum(bool(path) and all(e in index and kept[index[e]] for e in path) for path in paths))
    primary = f"rasp_forks@{config['primary_budget']:g}"
    report = {"algorithm": config["algorithm"], "config": config, "primary_method": primary,
              "selection_input_sha256": d["input_sha256"], "ground_truth_used_for_selection": False,
              "implementation_sha256": implementation_hash,
              "ledger": str(ledger.resolve()), "evaluation_scope": "development benchmark; fixed candidate graph, no held-out generalization claim",
              "load_seconds": score_started-started, "propagation_seconds": score_seconds,
              "elapsed_before_export_seconds": time.perf_counter()-started,
              "peak_rss_mib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024,
              "unique_interaction_channels": evidence["unique_channels"],
              "propagation_diagnostics": {k: evidence[k] for k in ("background", "personalized")},
              "temporally_reachable_events": int(reachable.sum()), "results": results}
    write_json(output/"comparison.json", report)
    display = json.loads(cache.read_text()) if cache else None
    wanted = {e["id"]: e for e in display["edges"]} if display else {}
    with gzip.open(output/"rasp-edge-scores.jsonl.gz", "wt") as stream:
        for i, event in enumerate(d["ids"]):
            parent = int(links[direction[i]][i])
            row = {"event_id": event, "score": float(score[i]), "rarity": float(d["rarity"][i]),
                   "contrast_diffusion": float(evidence["diffusion"][i]),
                   "winner_poi": d["ids"][evidence["winner"][i]] if evidence["winner"][i] >= 0 else None,
                   "temporal_reachable": bool(reachable[i]), "route_direction": "forward" if direction[i] else "backward",
                   "route_hops": int(depth[i]) if reachable[i] else None,
                   "route_next": d["ids"][parent] if parent >= 0 else None,
                   "fork_pivot": d["ids"][pivot[i]] if pivot[i] >= 0 else None,
                   "fork_previous": d["ids"][fork_parent[i]] if fork_parent[i] >= 0 else None,
                   "backward_next": d["ids"][links[0][i]] if links[0][i] >= 0 else None,
                   "fork_reachable": bool(fork_reachable[i]),
                   "retained": bool(masks[primary][i]), "anchor": bool(anchors[primary][i]),
                   "decisions": {k: bool(v[i]) for k, v in masks.items()}}
            stream.write(json.dumps(row)+"\n")
            if event in wanted:
                wanted[event]["rasp"] = row
    if display:
        display["rasp_experiment"] = report
        write_json(cache, display)
    print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
    print(f"COMPLETE {output}", flush=True)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=Path("configs/rasp_v1.json"))
    parser.add_argument("--cache", type=Path)
    args = parser.parse_args()
    run(args.ledger, args.reference, args.output, args.config, args.cache)
