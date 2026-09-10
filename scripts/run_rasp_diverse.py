"""Compare diminishing-return selection with frozen RASP scoring at fixed caps."""
import argparse
import gzip
import hashlib
import json
import resource
import time
from pathlib import Path

import numpy as np

from scripts.run_rasp import load_candidates, write_json
from tc_pruning.rasp import propagate, select_fork_bundles, temporal_fork_routes, temporal_routes
from tc_pruning.rasp_diverse import event_families, select_diverse


def run(ledger, reference, output, config_path, cache=None):
    config = json.loads(config_path.read_text())
    scoring = json.loads(Path(config["scoring_config"]).read_text())
    output.mkdir(parents=True, exist_ok=False)
    write_json(output/"config.json", config)
    write_json(output/"scoring-config.json", scoring)
    hashes = {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in
              ("tc_pruning/rasp.py", "tc_pruning/rasp_diverse.py", "scripts/run_rasp_diverse.py")}
    started = time.perf_counter()
    d = load_candidates(ledger)
    n = len(d["ids"])
    score, _ = propagate(d["src"], d["dst"], d["relation"], d["rarity"], d["poi"], d["process_nodes"], scoring)
    back = temporal_routes(d["src"], d["dst"], d["timestamp"], d["poi"])[0][0]
    parent, pivot, reachable, _ = temporal_fork_routes(d["src"], d["dst"], d["timestamp"], d["poi"], back)
    families = event_families(d["src"], d["dst"], d["relation"])
    masks, results = {}, []
    primary = f"rasp_d{config['primary_quality_weight']:g}@{config['primary_budget']:g}"
    primary_evidence, primary_anchors = None, None
    for ratio in config["budgets"]:
        budget = int(n*ratio)
        for quality in [None, *config["quality_weights"]]:
            tick = time.perf_counter()
            key = f"rasp_forks@{ratio:g}" if quality is None else f"rasp_d{quality:g}@{ratio:g}"
            if quality is None:
                kept, anchors = select_fork_bundles(score, d["poi"], back, parent, pivot, budget, d["tie"])
                evidence = {}
            else:
                kept, anchors, evidence = select_diverse(score, d["poi"], back, parent, pivot, families, budget, d["tie"], quality)
            assert int(kept.sum()) <= budget and np.all(kept[d["poi"]])
            _, _, after_reachable, _ = temporal_fork_routes(d["src"][kept], d["dst"][kept], d["timestamp"][kept], d["poi"][kept])
            lost = int((kept & reachable).sum())-int(after_reachable.sum())
            assert lost == 0
            masks[key] = kept
            results.append({"method": key, "budget_ratio": ratio, "quality_weight": quality,
                            "candidate_edges": n, "budget_edges": budget, "retained_edges": int(kept.sum()),
                            "compression_ratio": 1-float(kept.mean()), "connector_edges": int((kept & ~anchors).sum()),
                            "selected_families": int(len(np.unique(families[kept]))),
                            "candidate_families": int(families.max())+1,
                            "lost_fork_connections": lost, "selection_audit_seconds": time.perf_counter()-tick,
                            "lazy_recomputations": evidence.get("lazy_recomputations")})
            if key == primary:
                primary_evidence, primary_anchors = evidence, anchors
            print(json.dumps(results[-1]), flush=True)
    # All selection masks frozen before reading any attack labels or paths.
    truth = json.loads(reference.read_text())
    attack = set(truth["attack_event_ids"])
    paths = truth["attack_paths"]
    needed = attack | {e for path in paths for e in path}
    index = {e: i for i, e in enumerate(d["ids"]) if e in needed}
    truth_indices = np.asarray([index[e] for e in attack if e in index], dtype=int)
    attack_families = set(families[truth_indices])
    for result in results:
        kept = masks[result["method"]]
        retained_truth = truth_indices[kept[truth_indices]]
        result.update(attack_events=len(attack), attack_in_candidates=len(truth_indices),
                      retained_attack_events=len(retained_truth), attack_event_recall=len(retained_truth)/len(attack) if attack else None,
                      reference_paths=len(paths), retained_paths=sum(bool(path) and all(e in index and kept[index[e]] for e in path) for path in paths),
                      attack_families=len(attack_families), retained_attack_families=len(set(families[retained_truth])),
                      attack_family_recall=len(set(families[retained_truth]))/len(attack_families) if attack_families else None,
                      event_recall_upper_bound=min(result["budget_edges"], len(truth_indices))/len(attack) if attack else None)
    report = {"algorithm": config["algorithm"], "config": config, "scoring_config": scoring,
              "implementation_sha256": hashes, "selection_input_sha256": d["input_sha256"],
              "ground_truth_used_for_selection": False, "primary_method": primary,
              "candidate_source": str(ledger.resolve()), "results": results,
              "elapsed_before_export_seconds": time.perf_counter()-started,
              "peak_rss_mib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024,
              "evaluation_scope": "development cases; same POIs, scorer, candidate graph and edge cap"}
    write_json(output/"comparison.json", report)
    display = json.loads(cache.read_text()) if cache else None
    wanted = {e["id"]: e for e in display["edges"]} if display else {}
    with gzip.open(output/"diverse-decisions.jsonl.gz", "wt") as stream:
        for i, event in enumerate(d["ids"]):
            priority = primary_evidence["selection_priority"][i]
            row = {"event_id": event, "score": float(score[i]), "family": int(families[i]),
                   "primary_anchor_priority": None if np.isnan(priority) else float(priority),
                   "primary_selected_step": int(primary_evidence["selected_step"][i]),
                   "primary_reason": "poi" if d["poi"][i] else "diverse_anchor" if primary_anchors[i] else "fork_connector" if masks[primary][i] else "not_selected",
                   "decisions": {k: bool(v[i]) for k, v in masks.items()}}
            stream.write(json.dumps(row)+"\n")
            if event in wanted:
                wanted[event]["rasp_diverse"] = row
    if display:
        display["rasp_diverse_experiment"] = report
        write_json(cache, display)
    print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
    print(f"COMPLETE {output}", flush=True)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=Path("configs/rasp_diverse_v1.json"))
    parser.add_argument("--cache", type=Path)
    args = parser.parse_args()
    run(args.ledger, args.reference, args.output, args.config, args.cache)
