from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tc_pruning.protocol_v2 import restat_result_file


def metric_text(metric: dict) -> str:
    value = metric.get("value")
    return "N/A" if value is None else f"{value:.2%} ({metric['numerator']}/{metric['denominator']})"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate combined protocol-v2 UBC report")
    parser.add_argument("--db", default="output/tc/cadets-e3-v2.db")
    parser.add_argument("--results-dir", default="output/tc/ubc-cadets-e3")
    parser.add_argument("--annotations-dir", default="output/tc/ubc-cadets-e3/ubc-provenance-source")
    parser.add_argument("--output-dir", default="output/tc/ubc-cadets-e3/protocol-v2")
    args = parser.parse_args()
    results_dir, annotations_dir, output_dir = map(Path, (args.results_dir, args.annotations_dir, args.output_dir))
    output_dir.mkdir(parents=True, exist_ok=True)
    reports = []
    for day in ("06", "12", "13"):
        reports.append(restat_result_file(
            args.db,
            str(results_dir / f"cadets-e3-ubc-{day}-e3-report-poi-results.json"),
            str(annotations_dir / f"cadets-e3-ubc-{day}-annotations.json"),
            str(output_dir / f"cadets-e3-ubc-{day}-protocol-v2.json"),
        ))

    combined = {
        "protocol_version": "tc-pruning-evaluation-v2.0",
        "reports": reports,
        "main_results_table": [row for report in reports for row in report["main_results_table"]],
        "diagnostic_table": [row for report in reports for row in report["diagnostic_table"]],
        "performance_table": [row for report in reports for row in report["performance_table"]],
    }
    (output_dir / "ubc-06-12-13-protocol-v2.json").write_text(
        json.dumps(combined, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    lines = [
        "# UBC CADETS E3 Evaluation Protocol v2 Results", "",
        "All recall values below use fixed scenario-wide denominators. Derived events and paths are not human-verified edge labels.", "",
        "## Main results", "",
        "| Scenario | Input | Requested / actual retention | Nodes before -> after | Events before -> after | Event compression | Final node recall | Final derived-event recall | Verified path retention |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for report in reports:
        for row in report["main_results_table"]:
            lines.append(
                f"| {row['scenario']} | {row['input_mode']} | {row['requested_retention']:.0%} / {row['actual_event_retention']:.2%} | "
                f"{row['nodes_before']} -> {row['nodes_after']} | {row['events_before']} -> {row['events_after']} | "
                f"{row['event_compression']:.2%} | {metric_text(row['final_node_recall'])} | "
                f"{metric_text(row['final_derived_event_recall'])} | {metric_text(row['verified_attack_path_retention'])} |"
            )
    lines += ["", "## Diagnostic results", "",
              "| Scenario | POIs | Label DB match (nodes/events) | Candidate node recall | Candidate derived-event recall | Truncated |",
              "|---|---:|---:|---:|---:|---:|"]
    for report in reports:
        row = report["diagnostic_table"][0]
        lines.append(
            f"| {row['scenario']} | {row['poi_count_and_source']['count']} | "
            f"{metric_text(row['label_database_match']['nodes'])} / {metric_text(row['label_database_match']['derived_events'])} | "
            f"{metric_text(row['candidate_node_recall'])} | {metric_text(row['candidate_derived_event_recall'])} | "
            f"{'yes' if row['incomplete'] else 'no'} |"
        )
    lines += ["", "## Performance audit", "",
              "| Scenario | Graph build | Features + diffusion | Single-budget pruning | Offline evaluation | Whole experiment | Baseline RSS | Peak RSS |",
              "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for report in reports:
        row = report["performance_table"][0]
        baseline_text = (
            f"{row['baseline_rss_mib']:.2f} MiB"
            if row["baseline_rss_mib"] is not None else "N/A"
        )
        lines.append(
            f"| {row['scenario']} | {row['candidate_construction_seconds']:.4f} s | "
            f"{row['features_and_diffusion_seconds']:.4f} s | N/A | {row['evaluation_seconds']:.4f} s | "
            f"{row['whole_experiment_seconds']:.4f} s | {baseline_text} | "
            f"{row['process_peak_rss_mib']:.2f} MiB |"
        )
    lines += ["", "Main-pipeline single-budget time, verified-event recall, verified-path retention, precision, FPR, F1, and byte compression are N/A; see each JSON's `unavailable_items`. Per-method comparison rows do record their own pruning time."]
    (output_dir / "ubc-06-12-13-protocol-v2.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    import matplotlib.pyplot as plt
    plt.rcParams.update({
        "font.family": "serif", "font.size": 9, "figure.dpi": 300,
        "savefig.dpi": 300, "savefig.bbox": "tight",
        "axes.spines.top": False, "axes.spines.right": False,
        "axes.grid": True, "grid.alpha": 0.18,
    })
    colors = ["#E69F00", "#0072B2", "#009E73"]
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 2.8))
    for color, day, report in zip(colors, ("UBC06", "UBC12", "UBC13"), reports):
        event_curve = report["curves"]["actual_event_retention_vs_derived_event_recall"]
        path_curve = report["curves"]["actual_event_retention_vs_derived_reference_path_retention"]
        axes[0].plot([x["actual_event_retention"] for x in event_curve],
                     [x["derived_event_recall"]["value"] for x in event_curve], marker="o", label=day, color=color)
        path_values = [x["derived_reference_path_retention"]["value"] for x in path_curve]
        if any(value is not None for value in path_values):
            axes[1].plot([x["actual_event_retention"] for x in path_curve],
                         path_values, marker="s", label=day, color=color)
    axes[0].set(xlabel="Actual event retention", ylabel="Derived-event recall", xlim=(0, 0.55), ylim=(0, 1.03))
    axes[1].set(xlabel="Actual event retention", ylabel="Derived-reference path retention", xlim=(0, 0.55), ylim=(0, 1.03))
    axes[0].legend(frameon=False)
    axes[1].legend(frameon=False)
    axes[1].text(
        0.53, 0.04, "UBC12, UBC13: N/A\n(invalid derived paths)",
        ha="right", va="bottom", fontsize=8, color="#555555",
    )
    fig.tight_layout()
    fig.savefig(output_dir / "retention-recall-curves.pdf")
    fig.savefig(output_dir / "retention-recall-curves.png")
    plt.close(fig)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
