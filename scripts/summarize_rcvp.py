"""Build compact machine-readable and Markdown tables from frozen RCVP runs."""
from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / "output/rcvp-evaluation-20260913"
CASES = {"CADETS-06": "cadets-06", "CADETS-12": "cadets-12", "CADETS-13": "cadets-13"}


def value(metric):
    return metric.get("value") if isinstance(metric, dict) else metric


def main():
    rows, cases = [], {}
    for case, directory in CASES.items():
        run = RUNS / directory
        manifest = json.loads((run / "manifest.json").read_text())
        evaluation = json.loads((run / "offline-evaluation.json").read_text())
        validation = json.loads((run / "validation.json").read_text())
        cases[case] = {
            "output": str(run.relative_to(ROOT)), "candidate_edges": manifest["candidate_edges"],
            "candidate_sha256": manifest["candidate_sha256"], "decision_sha256": manifest["decision_sha256"],
            "resolved_config": manifest["config"], "config_sha256": manifest["config_sha256"],
            "audit_sha256": validation["audit_sha256"], "validator": validation,
            "implementation_sha256": manifest["implementation_sha256"],
            "timings_seconds": manifest["timings_seconds"], "memory_mib": manifest["memory_mib"],
            "resource_measurement_scope": "online scoring and selection before audit serialization, validation, and offline evaluation",
            "whole_process_elapsed_seconds": None, "whole_process_peak_rss_mib": None,
            "derived_path_source": evaluation.get("derived_path_source"),
        }
        if case == "THEIA-3" and (ROOT / "output/rcvp-validation/theia-process-monitor.json").is_file():
            cases[case]["external_process_monitor"] = json.loads((ROOT / "output/rcvp-validation/theia-process-monitor.json").read_text())
        for method, metrics in sorted(evaluation["metrics"].items()):
            base, budget = method.rsplit("@", 1); diag = manifest["method_diagnostics"][method]
            propagation = "A_rasp" if base == "A_rasp" else base if base in {"B", "C", "D", "E"} else "E" if base.startswith("G") else None
            propagation_stats = manifest["timings_seconds"].get(f"propagate_{propagation}", {}) if propagation else {}
            selection_stats = manifest["timings_seconds"].get(f"select_{method}", {})
            candidate_edge = metrics["candidate_context_edge_recall"]; final_edge = metrics["pruned_context_edge_recall"]
            candidate_node = metrics["candidate_positive_node_recall"]; final_node = metrics["pruned_positive_node_recall"]
            row = {
                "case": case, "method": base, "budget": float(budget),
                "candidate_edges": manifest["candidate_edges"], "retained_edges": diag["retained_raw_events"],
                "actual_keep_ratio": value(metrics["actual_keep_ratio"]), "edge_compression": metrics["edge_compression"], "node_compression": metrics["node_compression"],
                "candidate_context_edge_recall": value(candidate_edge), "conditional_context_edge_retention": value(metrics["conditional_context_edge_retention"]), "pruned_context_edge_recall": value(final_edge),
                "candidate_context_edge_misses": candidate_edge["denominator"] - candidate_edge["numerator"], "pruning_context_edge_misses": candidate_edge["numerator"] - final_edge["numerator"],
                "candidate_positive_entity_recall": value(candidate_node), "pruned_positive_entity_recall": value(final_node),
                "candidate_positive_entity_misses": candidate_node["denominator"] - candidate_node["numerator"], "pruning_positive_entity_misses": candidate_node["numerator"] - final_node["numerator"],
                "strict_derived_path_eligibility": value(metrics.get("strict_derived_path_eligibility", {})), "conditional_strict_derived_path_retention": value(metrics.get("conditional_strict_derived_path_retention", {})), "pruned_strict_derived_path_recall": value(metrics.get("pruned_strict_derived_path_recall", {})),
                "verified_human_path_retention": metrics["verified_attack_path_retention"],
                "budget_feasible": diag["budget_feasible"], "budget_overflow_edges": diag["budget_overflow_edges"], "path_certificate_valid": diag["path_certificate_valid"], "strict_multistage_certificate_valid": diag["strict_multistage_certificate_valid"], "certificate_reason": diag["certificate_reason"],
                "propagation_wall_seconds": propagation_stats.get("wall_seconds"), "selection_wall_seconds": selection_stats.get("wall_seconds"),
                "method_wall_seconds": (propagation_stats.get("wall_seconds", 0) + selection_stats.get("wall_seconds", 0)),
                "method_peak_rss_mib": max(propagation_stats.get("peak_rss_mib", 0), selection_stats.get("peak_rss_mib", 0)),
                "timing_context": "concurrent_four_case_run_contention_affected",
                "metric_triplets": metrics,
                "prefix_monotonicity": {"value": None, "reason": "fixed_complete_prefix_not_a_prefix_sequence_experiment"},
                "prefix_churn": {"value": None, "reason": "fixed_complete_prefix_not_a_prefix_sequence_experiment"},
            }
            rows.append(row)
    document = {"schema_version": "rasp-rcvp-results-v1", "scope": "three completed development positive-retention cases; no held-out generalization claim", "excluded_cases": {"THEIA-3": "excluded_by_user_request; existing process left running; no new execution or waiting"}, "cases": cases, "rows": rows}
    (ROOT / "docs/rasp-rcvp-results.json").write_text(json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
    def fmt(item):
        if item is None: return "N/A"
        if isinstance(item, bool): return "yes" if item else "no"
        return f"{item:.4g}" if isinstance(item, float) else str(item)
    lines = ["# RASP-RCVP frozen evaluation results", "", "Generated with `PYTHONPATH=. python scripts/summarize_rcvp.py` from `output/rcvp-evaluation-20260913`. All timings came from concurrent runs and include host contention. Runtime and peak RSS cover online scoring/selection phases only; whole-process values including audit serialization, validation, and offline evaluation are N/A for this delivery. Human-verified path retention is N/A because no independently reviewed path manifest is admitted. Prefix monotonicity/churn are N/A for these fixed complete-prefix runs. THEIA is excluded by user request; its existing process is left running, without waiting or restarting. Each row is one frozen method/budget result.", "", "| Case | Method | Budget | Keep | Edge cond. | Edge e2e | Positive entities | Strict paths cond. | Candidate/pruning edge misses | Certificate | Budget feasible | Wall s | Peak MiB |", "|---|---|---:|---:|---:|---:|---:|---:|---:|---|---|---:|---:|"]
    for row in rows:
        lines.append("| " + " | ".join(map(fmt, [row["case"], row["method"], row["budget"], row["actual_keep_ratio"], row["conditional_context_edge_retention"], row["pruned_context_edge_recall"], row["pruned_positive_entity_recall"], row["conditional_strict_derived_path_retention"], f'{row["candidate_context_edge_misses"]}/{row["pruning_context_edge_misses"]}', row["strict_multistage_certificate_valid"], row["budget_feasible"], row["method_wall_seconds"], row["method_peak_rss_mib"]])) + " |")
    lines += ["", "The companion JSON preserves numerator/denominator-derived misses, phase timings, memory, certificate fields, validator output, and candidate/decision/audit/implementation hashes.", ""]
    (ROOT / "docs/rasp-rcvp-results.md").write_text("\n".join(lines))


if __name__ == "__main__":
    main()
