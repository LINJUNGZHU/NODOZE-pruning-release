"""Replay full score ledgers without training, changing POIs, or reading GT in selection."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import resource
import re
import time
from pathlib import Path

import numpy as np

from tc_pruning.adaptive_mass import close_witnesses, fit_score_mixture, select_mass, temporal_successors


def rows(path):
    with gzip.open(path, "rt") as stream:
        for line in stream:
            yield json.loads(line)


def write_json(path, value):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2))
    tmp.replace(path)


def run(ledger, reference, output, cache=None, losses=(0.05, 0.1, 0.2), publish_loss=0.1, mixture=False, preserve_atomicity=False):
    started = time.perf_counter()
    output.mkdir(parents=True, exist_ok=False)
    ids, score, source, target, timestamps, strata, poi, old = [], [], [], [], [], [], [], []
    node_ids, group_ids, display_indices = {}, {}, {}
    doc = json.loads(cache.read_text()) if cache else None
    wanted = {e["id"] for e in doc["edges"]} if doc else set()
    context_nodes = {endpoint for e in doc["edges"] if e["attack_paths"] for endpoint in (e["source"], e["target"])} if doc else set()
    context = []
    fingerprint = hashlib.sha256()
    for i, row in enumerate(rows(ledger)):
        event = row["event_id"]
        ids.append(event)
        score.append(row["score"])
        source.append(node_ids.setdefault(row["src"], len(node_ids)))
        target.append(node_ids.setdefault(row["dst"], len(node_ids)))
        timestamps.append(row["timestamp_ns"])
        group = (row.get("provenance", {}).get("winner_poi_event_id", "none"),
                 row["src_type"], row["relation"], row["dst_type"])
        strata.append(group_ids.setdefault(group, len(group_ids)))
        poi.append(bool(row.get("is_declared_poi")))
        old.append(any(d["budget_key"] == "0.2" and d["kept"] for d in row["decisions"]))
        context.append(row["src"] in context_nodes or row["dst"] in context_nodes)
        fingerprint.update(json.dumps([event, row["score"], group, bool(row.get("is_declared_poi")), row["src"], row["dst"], row["timestamp_ns"]], separators=(",", ":")).encode())
        if event in wanted:
            display_indices[event] = i
        if i and i % 250000 == 0:
            print(f"loaded {i:,} events", flush=True)
    n = len(ids)
    scores = np.asarray(score)
    src, dst, ts, strata = map(np.asarray, (source, target, timestamps, strata))
    poi, old, context = map(lambda a: np.asarray(a, dtype=bool), (poi, old, context))
    del score, source, target, timestamps, node_ids
    loaded_at = time.perf_counter()
    print(f"loaded {n:,}; constructing strict temporal witnesses", flush=True)
    successor, reachable = temporal_successors(src, dst, ts, poi, minimum_hops=mixture)
    posterior, mixture_fit = fit_score_mixture(scores) if mixture else (None, None)
    # CDM synthetic secondary edges share the original event UUID. Never split
    # these events. This is not the older DEPIMPACT merged-edge grouping.
    original_ids = {}
    atomic = np.empty(n, dtype=np.int64)
    for i, event in enumerate(ids):
        base = re.sub(r"^([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}):\d+$", r"\1", event)
        atomic[i] = original_ids.setdefault(base, len(original_ids))
    def closure(selected):
        selected = selected.copy()
        while True:
            previous = int(selected.sum())
            selected = close_witnesses(selected, successor)
            if not preserve_atomicity:
                return selected
            groups = np.zeros(len(original_ids), dtype=bool)
            groups[atomic[selected]] = True
            selected |= groups[atomic]
            if int(selected.sum()) == previous:
                return selected
    results = []
    masks = {}
    threshold_sets = {}
    configs = [("baseline_ps_rdp_20pct", None), ("score_top20pct", None)]
    configs += [(f"mass_only_{loss:g}", loss) for loss in losses]
    configs += [(f"t_mass_{loss:g}", loss) for loss in losses]
    if mixture:
        configs += [("baseline_witness_repair", None)]
        configs += [(f"mixture_only_{p:g}", p) for p in (.5, .9, .99)]
        configs += [(f"mixture_witness_{p:g}", p) for p in (.5, .9, .99)]
    for name, loss in configs:
        tick = time.perf_counter()
        thresholds = []
        if name in ("baseline_ps_rdp_20pct", "baseline_witness_repair"):
            selected = old.copy()
        elif name == "score_top20pct":
            selected = np.zeros(n, dtype=bool)
            selected[np.argsort(-scores, kind="stable")[:max(1, int(n*.2))]] = True
        elif name.startswith("mixture"):
            selected = (posterior >= loss) | poi
        else:
            selected, thresholds = select_mass(scores, strata, poi, loss)
        before_closure = int(selected.sum())
        if name.startswith(("t_mass", "mixture_witness", "baseline_witness")):
            selected = closure(selected)
        masks[name] = selected
        threshold_sets[name] = thresholds
        obligations = np.flatnonzero(selected & (successor >= 0))
        broken_witnesses = int((~selected[successor[obligations]]).sum())
        if name.startswith(("t_mass", "mixture_witness", "baseline_witness")) and broken_witnesses:
            raise AssertionError("temporal closure certificate failed")
        results.append({"method": name, "loss_tolerance": loss,
                        "parameter_semantics": "high_score_membership_cutoff" if name.startswith("mixture") else "stratum_score_mass_loss",
                        "broken_selected_witness_links": broken_witnesses,
                        "candidate_edges": n, "retained_edges": int(selected.sum()),
                        "compression_ratio": 1-float(selected.mean()),
                        "score_mass_retained": float(scores[selected].sum()/scores.sum()) if scores.sum() else 1.,
                        "witness_added_edges": int(selected.sum())-before_closure,
                        "poi_retained": int((selected & poi).sum()), "poi_count": int(poi.sum()),
                        "selected_with_temporal_witness": int((selected & reachable).sum()),
                        "selected_without_temporal_witness": int((selected & ~reachable).sum()),
                        "stratum_constraints_met": all(t["constraint_met"] for t in thresholds) if thresholds else None,
                        "selector_seconds": time.perf_counter()-tick})
        print(json.dumps(results[-1]), flush=True)
    # Independent reachability audit on each retained subgraph. Missing chosen
    # witness links alone do not prove a lost connection: alternatives may exist.
    for result in results:
        selected = masks[result["method"]]
        _, actual_reachable = temporal_successors(src[selected], dst[selected], ts[selected], poi[selected], minimum_hops=True)
        result["retained_events_reaching_poi"] = int(actual_reachable.sum())
        result["lost_retained_poi_connections"] = int((selected & reachable).sum())-int(actual_reachable.sum())
        if result["method"].startswith(("t_mass", "mixture_witness", "baseline_witness")):
            assert result["lost_retained_poi_connections"] == 0
    # Ground truth is opened ONLY after all masks are frozen. It cannot influence
    # scores, strata, thresholds, witnesses, or which preset is published.
    truth = json.loads(reference.read_text())
    attack = set(truth["attack_event_ids"])
    paths = truth["attack_paths"]
    truth_indices = np.asarray([i for i, event in enumerate(ids) if event in attack], dtype=int)
    index = {event: i for i, event in enumerate(ids) if event in {e for p in paths for e in p}}
    for result in results:
        selected = masks[result["method"]]
        tp = int(selected[truth_indices].sum())
        result.update({"attack_event_recall": tp/len(attack) if attack else None,
                       "attack_events": len(attack), "attack_events_in_candidates": len(truth_indices),
                       "retained_attack_events": tp,
                       "reference_paths": len(paths),
                       "retained_paths": sum(bool(p) and all(e in index and selected[index[e]] for e in p) for p in paths),
                       "unlabeled_retained_events": int(selected.sum())-tp})
    primary = "mixture_witness_0.9" if mixture else f"t_mass_{publish_loss:g}"
    if primary not in masks:
        raise ValueError("publish-loss must be among losses")
    report = {"algorithm": "T-MASS-v2-mixture" if mixture else "T-MASS-v1", "status": "experimental_offline_selector",
              "witness_policy": "minimum_hops_strict_time" if mixture else "latest_strict_time",
              "preserve_cdm_atomicity": preserve_atomicity,
              "mixture_fit": mixture_fit,
              "primary_method": primary, "primary_selection_rule": "preset parameter; not chosen by attack recall",
              "selection_input_sha256": fingerprint.hexdigest(), "ledger": str(ledger.resolve()),
              "ground_truth_used_for_selection": False,
              "timing_scope": "replay only; excludes original ingestion/rarity/diffusion scoring",
              "load_seconds": loaded_at-started, "elapsed_seconds": time.perf_counter()-started,
              "peak_rss_mb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024,
              "strata": [list(g) for g in group_ids], "results": results}
    write_json(output / "comparison.json", report)
    write_json(output / "thresholds.json", threshold_sets)
    print("writing complete per-edge decisions", flush=True)
    with gzip.open(output / "adaptive-decisions.jsonl.gz", "wt") as stream:
        for i, event in enumerate(ids):
            selected = bool(masks[primary][i])
            stream.write(json.dumps({"event_id": event, "score": float(scores[i]),
                                    "stratum": int(strata[i]), "temporal_reachable": bool(reachable[i]),
                                    "high_score_membership": float(posterior[i]) if mixture else None,
                                    "witness_successor": ids[successor[i]] if successor[i] >= 0 else None,
                                    "poi": bool(poi[i]), "primary_kept": selected,
                                    "decisions": {name: bool(mask[i]) for name, mask in masks.items()}}) + "\n")
    if doc:
        doc["adaptive_experiment"] = report
        threshold_map = {t["stratum"]: t["threshold"] for t in threshold_sets[primary]}
        for edge in doc["edges"]:
            i = display_indices[edge["id"]]
            edge["adaptive"] = {"retained": bool(masks[primary][i]), "stratum": int(strata[i]),
                                "repair_retained": bool(masks.get("baseline_witness_repair", old)[i]),
                                "threshold": threshold_map.get(int(strata[i])),
                                "high_score_membership": float(posterior[i]) if mixture else None,
                                "temporal_reachable": bool(reachable[i]),
                                "witness_successor": ids[successor[i]] if successor[i] >= 0 else None}
        doc["adaptive_experiment"]["full_context_counts"] = {
            "retained": int((context & masks[primary]).sum()),
            "removed": int((context & ~masks[primary]).sum())}
        repaired = masks.get("baseline_witness_repair", old)
        doc["adaptive_experiment"]["repair_context_counts"] = {
            "retained": int((context & repaired).sum()), "removed": int((context & ~repaired).sum())}
        write_json(cache, doc)
    print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
    print(f"COMPLETE output={output}", flush=True)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--losses", type=float, nargs="+", default=[0.05, 0.1, 0.2])
    parser.add_argument("--publish-loss", type=float, default=0.1)
    parser.add_argument("--mixture", action="store_true", help="Fit log-score mixture and use minimum-hop temporal witnesses")
    parser.add_argument("--preserve-cdm-atomicity", action="store_true", help="Optional: require every CDM secondary edge with the same original UUID")
    args = parser.parse_args()
    run(args.ledger, args.reference, args.output, args.cache, args.losses, args.publish_loss, args.mixture, args.preserve_cdm_atomicity)
