from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .cdm import CDMStreamReader
from .config import load_experiment_config
from .annotations import prepare_groundtruth_manifest
from .evaluation import AttackAnnotations, run_experiment
from .kairos_alerts import prepare_kairos_alert_manifest
from .nodoze import NODOZEFrequencyModel
from .poi import (
    load_candidate_event_ids,
    load_poi_event_ids,
    load_poi_manifest,
    select_poi_events,
)
from .store import ProvenanceStore
from .sysdig import SysdigStreamReader, load_depimpact_property, resolve_depimpact_poi
from .ubc_groundtruth import CADETS_E3_SCENARIOS, prepare_ubc_manifests
from .frequency_cache import FrequencyCache
from .frequency_snapshot import compile_snapshot, default_snapshot_path
from .search_diagnostics import run_search_diagnostic
from .protocol_v2 import restat_result_file
from .poi_prefix import run_poi_prefix_sweep
from .score_ledger import verify_score_ledger


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="DARPA TC rarity + graph diffusion adaptive pruning"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    ingest = commands.add_parser("ingest", help="stream CDM18/CDM20 data into SQLite")
    ingest.add_argument("--input", nargs="+", required=True, help="JSONL/JSONL.GZ or Avro/Avro.GZ files")
    ingest.add_argument("--db", required=True, help="SQLite graph database")
    ingest.add_argument("--schema", help="optional matching TCCDMDatum.avsc")
    ingest.add_argument("--max-records", type=int)
    ingest.add_argument("--batch-size", type=int, default=10_000)
    ingest.add_argument("--strict", action="store_true")

    ingest_sysdig = commands.add_parser(
        "ingest-sysdig",
        help="stream a DEPIMPACT/sysdig text log and resolve its file POI",
    )
    ingest_sysdig.add_argument("--input", nargs="+", required=True, help="sysdig text log files")
    ingest_sysdig.add_argument("--db", required=True, help="SQLite graph database")
    ingest_sysdig.add_argument("--poi-property", required=True, help="DEPIMPACT .property_demo file")
    ingest_sysdig.add_argument("--poi-output", required=True, help="generated event POI JSON")
    ingest_sysdig.add_argument("--host", default="sysdig", help="stable host identity for generated nodes")
    ingest_sysdig.add_argument("--max-records", type=int)
    ingest_sysdig.add_argument("--batch-size", type=int, default=10_000)
    ingest_sysdig.add_argument("--strict", action="store_true")

    build_frequency = commands.add_parser(
        "build-frequency-cache",
        help="offline: persist daily NoDoze and rarity aggregates",
    )
    build_frequency.add_argument("--db", required=True)

    explain_frequency = commands.add_parser(
        "explain-frequency-cache",
        help="show SQLite query plans used by online frequency lookup",
    )
    explain_frequency.add_argument("--db", required=True)

    compile_frequency = commands.add_parser(
        "compile-frequency-snapshot",
        help="offline: compile one directly-loadable model for a cutoff day",
    )
    compile_frequency.add_argument("--db", required=True)
    compile_frequency.add_argument("--before-timestamp-ns", required=True, type=int)
    compile_frequency.add_argument("--output")

    compile_ubc = commands.add_parser(
        "compile-ubc-frequency-snapshots",
        help="offline: compile before-06, before-12, and before-13 models",
    )
    compile_ubc.add_argument("--db", required=True)

    prepare = commands.add_parser(
        "prepare-annotations",
        help="convert a ground-truth UUID list into an event-centred manifest",
    )
    prepare.add_argument("--db", required=True)
    prepare.add_argument("--groundtruth", required=True)
    prepare.add_argument("--output", required=True)

    prepare_ubc = commands.add_parser(
        "prepare-ubc-annotations",
        help="create separate UBC/Orthrus core attack manifests for CADETS E3",
    )
    prepare_ubc.add_argument("--db", required=True)
    prepare_ubc.add_argument("--groundtruth-dir", required=True)
    prepare_ubc.add_argument("--output-dir", required=True)
    prepare_ubc.add_argument(
        "--scenario", choices=("06", "12", "13", "all"), default="all"
    )
    prepare_ubc.add_argument(
        "--poi-events",
        help="ordered analyst POI manifest (requires one explicit scenario)",
    )

    prepare_kairos = commands.add_parser(
        "prepare-kairos-alerts",
        help="map a portable KAIROS alert export to NODOZE event seeds",
    )
    prepare_kairos.add_argument("--db", required=True)
    prepare_kairos.add_argument("--input", required=True)
    prepare_kairos.add_argument("--output", required=True)

    select_pois = commands.add_parser(
        "select-pois",
        help="rank candidate events and select diverse downstream DEPIMPACT POIs",
    )
    select_pois.add_argument("--db", required=True)
    select_pois.add_argument(
        "--candidates",
        required=True,
        help="manifest containing attack_event_ids or detector event_ids",
    )
    select_pois.add_argument("--output", required=True)
    select_pois.add_argument("--max-pois", type=int, default=5)
    select_pois.add_argument(
        "--source-kind",
        choices=("detector", "groundtruth"),
        default="detector",
        help="groundtruth marks the result as oracle-derived pruning input",
    )

    experiment = commands.add_parser(
        "experiment", help="run rarity, diffusion, pruning, and evaluation"
    )
    experiment.add_argument("--db", required=True)
    poi_input = experiment.add_mutually_exclusive_group(required=True)
    poi_input.add_argument(
        "--annotations",
        help="existing event-centred alert manifest (KAIROS is optional)",
    )
    poi_input.add_argument(
        "--poi-events",
        help=(
            "JSON or text event-ID list; each event uses a relation-aware "
            "investigation anchor as the POI seed"
        ),
    )
    experiment.add_argument(
        "--groundtruth-annotations",
        help=(
            "independent attack ground-truth manifest used only for evaluation; "
            "detector seeds continue to come from --annotations"
        ),
    )

    poi_prefix = commands.add_parser(
        "poi-prefix-experiment",
        help="sweep report-ordered POI prefixes over fixed CADETS windows",
    )
    poi_prefix.add_argument("--db", required=True)
    poi_prefix.add_argument("--spec", required=True)
    poi_prefix.add_argument("--config", required=True)
    poi_prefix.add_argument("--output-dir", required=True)
    experiment.add_argument("--output", required=True)
    experiment.add_argument(
        "--config",
        default=str(Path(__file__).resolve().parent.parent / "configs" / "tc_pruning.json"),
        help=(
            "JSON experiment profile; search, scoring, and pruning parameters "
            "are loaded from this file"
        ),
    )

    diagnose = commands.add_parser(
        "diagnose-search",
        help="run an independent causal search with heuristic stopping disabled",
    )
    diagnose.add_argument("--db", required=True)
    diagnose.add_argument("--annotations", required=True, help="POI annotation manifest")
    diagnose.add_argument("--groundtruth-annotations", required=True)
    diagnose.add_argument("--current-results", required=True)
    diagnose.add_argument("--output", required=True)
    diagnose.add_argument(
        "--config",
        default=str(Path(__file__).resolve().parent.parent / "configs" / "tc_pruning.json"),
    )

    protocol = commands.add_parser(
        "report-protocol-v2",
        help="offline: re-evaluate an existing result with auditable v2 metrics",
    )
    protocol.add_argument("--db", required=True)
    protocol.add_argument("--result", required=True)
    protocol.add_argument("--annotations", required=True)
    protocol.add_argument("--output", required=True)

    verify_ledger = commands.add_parser(
        "verify-score-ledger",
        help="verify complete edge rows and SHA-256 hashes in a score ledger",
    )
    verify_ledger.add_argument("--ledger", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "ingest":
        reader = CDMStreamReader(
            args.input,
            schema_path=args.schema,
            strict=args.strict,
            max_records=args.max_records,
        )
        with ProvenanceStore(args.db) as store:
            stats = store.ingest(reader, batch_size=args.batch_size)
            summary = {
                "records_read": reader.stats.records_read,
                "records_malformed": reader.stats.records_malformed,
                "observations_emitted": reader.stats.observations_emitted,
                "nodes_seen": stats.nodes_seen,
                "edges_seen": stats.edges_seen,
                "edges_inserted": stats.edges_inserted,
                "database_nodes": store.node_count(),
                "database_edges": store.edge_count(),
            }
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0

    if args.command == "ingest-sysdig":
        reader = SysdigStreamReader(
            args.input,
            host=args.host,
            strict=args.strict,
            max_records=args.max_records,
        )
        specification = load_depimpact_property(args.poi_property)
        with ProvenanceStore(args.db) as store:
            stats = store.ingest(reader, batch_size=args.batch_size)
            manifest = resolve_depimpact_poi(store, specification)
            summary = {
                "records_read": reader.stats.records_read,
                "records_malformed": reader.stats.records_malformed,
                "observations_emitted": reader.stats.observations_emitted,
                "nodes_seen": stats.nodes_seen,
                "edges_seen": stats.edges_seen,
                "edges_inserted": stats.edges_inserted,
                "database_nodes": store.node_count(),
                "database_edges": store.edge_count(),
                "poi_event_ids": manifest["event_ids"],
            }
        manifest["metadata"]["property_file"] = str(Path(args.poi_property).resolve())
        manifest["metadata"]["input_logs"] = [
            str(Path(path).resolve()) for path in args.input
        ]
        output = Path(args.poi_output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        summary["poi_output"] = str(output.resolve())
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0

    if args.command == "build-frequency-cache":
        with ProvenanceStore(args.db) as store:
            summary = FrequencyCache(store).build()
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0

    if args.command == "explain-frequency-cache":
        with ProvenanceStore(args.db) as store:
            plans = FrequencyCache(store).explain_online_queries()
        print(json.dumps(plans, ensure_ascii=False, indent=2))
        return 0

    if args.command == "compile-frequency-snapshot":
        cutoff_day = args.before_timestamp_ns // 86_400_000_000_000
        output = args.output or default_snapshot_path(args.db, cutoff_day)
        with ProvenanceStore(args.db) as store:
            summary = compile_snapshot(store, args.before_timestamp_ns, output)
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0

    if args.command == "compile-ubc-frequency-snapshots":
        summaries = []
        with ProvenanceStore(args.db) as store:
            for scenario in CADETS_E3_SCENARIOS.values():
                cutoff, _ = scenario.bounds_ns()
                output = default_snapshot_path(args.db, cutoff // 86_400_000_000_000)
                summaries.append(compile_snapshot(store, cutoff, output))
        print(json.dumps(summaries, ensure_ascii=False, indent=2))
        return 0

    if args.command == "prepare-annotations":
        with ProvenanceStore(args.db) as store:
            manifest = prepare_groundtruth_manifest(
                store, args.groundtruth, output_path=args.output
            )
        print(json.dumps(manifest, ensure_ascii=False, indent=2))
        return 0

    if args.command == "prepare-ubc-annotations":
        poi_event_ids = (
            load_poi_manifest(args.poi_events).event_ids
            if args.poi_events else None
        )
        with ProvenanceStore(args.db) as store:
            manifests = prepare_ubc_manifests(
                store,
                args.groundtruth_dir,
                output_dir=args.output_dir,
                scenario=args.scenario,
                poi_event_ids=poi_event_ids,
            )
        summary = [
            {
                "name": manifest["name"],
                "scenario": manifest["metadata"]["scenario"],
                "matched_attack_nodes": manifest["metadata"]["matched_attack_node_count"],
                "derived_attack_events": manifest["metadata"]["derived_attack_event_count"],
            }
            for manifest in manifests
        ]
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0

    if args.command == "prepare-kairos-alerts":
        with ProvenanceStore(args.db) as store:
            manifest = prepare_kairos_alert_manifest(
                store, args.input, output_path=args.output
            )
        summary = {
            "output": args.output,
            "input_alert_edges": manifest["metadata"]["input_alert_edge_count"],
            "unique_alert_edges": manifest["metadata"]["unique_alert_edge_count"],
            "duplicate_alert_edges": manifest["metadata"]["duplicate_alert_edge_count"],
            "matched_alert_edges": manifest["metadata"]["matched_alert_edge_count"],
            "unmatched_alert_edges": manifest["metadata"]["unmatched_alert_edge_count"],
            "seed_event_ids": len(manifest["seed_event_ids"]),
            "seed_event_groups": len(manifest["seed_event_groups"]),
        }
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0

    if args.command == "select-pois":
        candidate_event_ids = load_candidate_event_ids(args.candidates)
        with ProvenanceStore(args.db) as store:
            candidate_edges = [
                edge
                for event_id in candidate_event_ids
                if (edge := store.get_edge_by_event_id(event_id)) is not None
            ]
            if not candidate_edges:
                raise ValueError("none of the candidate events exist in the database")
            frequency_cutoff_ns = min(edge.timestamp_ns for edge in candidate_edges)
            model = NODOZEFrequencyModel.from_store(
                store, before_timestamp_ns=frequency_cutoff_ns
            )
            selection = select_poi_events(
                store,
                candidate_event_ids,
                model,
                max_pois=args.max_pois,
                source_kind=args.source_kind,
            )
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        document = selection.to_dict()
        document["metadata"]["candidate_manifest"] = str(
            Path(args.candidates).resolve()
        )
        document["metadata"]["frequency_cutoff_ns"] = frequency_cutoff_ns
        output.write_text(
            json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(json.dumps(document, ensure_ascii=False, indent=2))
        return 0

    if args.command == "diagnose-search":
        annotations = AttackAnnotations.load(args.annotations)
        groundtruth = AttackAnnotations.load(
            args.groundtruth_annotations, require_seeds=False
        )
        current_report = json.loads(
            Path(args.current_results).read_text(encoding="utf-8-sig")
        )
        experiment_config = load_experiment_config(args.config)
        with ProvenanceStore(args.db) as store:
            report = run_search_diagnostic(
                store, annotations, groundtruth, current_report,
                experiment_config.causal_search,
            )
        report["inputs"] = {
            "annotations": str(Path(args.annotations).resolve()),
            "groundtruth_annotations": str(
                Path(args.groundtruth_annotations).resolve()
            ),
            "current_results": str(Path(args.current_results).resolve()),
            "config": str(Path(args.config).resolve()),
        }
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0

    if args.command == "report-protocol-v2":
        report = restat_result_file(
            args.db, args.result, args.annotations, args.output
        )
        print(json.dumps({
            "output": str(Path(args.output).resolve()),
            "protocol_version": report["protocol_version"],
            "budgets": len(report["budget_reports"]),
        }, ensure_ascii=False, indent=2))
        return 0

    if args.command == "verify-score-ledger":
        verification = verify_score_ledger(args.ledger)
        print(json.dumps(verification, ensure_ascii=False, indent=2))
        return 0 if verification["valid"] else 1

    if args.command == "poi-prefix-experiment":
        def print_prefix_progress(event: dict) -> None:
            print(
                "[progress] " + json.dumps(event, ensure_ascii=False),
                file=sys.stderr,
                flush=True,
            )

        summary = run_poi_prefix_sweep(
            args.db,
            args.spec,
            args.config,
            args.output_dir,
            progress_callback=print_prefix_progress,
        )
        print(
            json.dumps(
                {
                    "output_dir": str(Path(args.output_dir).resolve()),
                    "completed_prefix_runs": summary["cross_day"][
                        "completed_prefix_runs"
                    ],
                    "days": summary["days"],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    if args.poi_events:
        poi_manifest = load_poi_manifest(args.poi_events)
        poi_event_ids = list(poi_manifest.event_ids)
        annotations = AttackAnnotations(
            name=f"event POIs from {Path(args.poi_events).name}",
            seed_uuids=set(),
            seed_event_ids=set(poi_event_ids),
            seed_event_groups=[set(group.event_ids) for group in poi_manifest.groups],
            seed_event_group_ids=[group.group_id for group in poi_manifest.groups],
            seed_event_sequences=[group.event_ids for group in poi_manifest.groups],
            investigation_windows={
                group.group_id: (group.window_start_ns, group.window_end_ns)
                for group in poi_manifest.groups
                if group.window_start_ns is not None and group.window_end_ns is not None
            },
            attack_event_ids=set(),
            attack_node_uuids=set(),
        )
        input_mode = "event_poi_file"
    else:
        annotations = AttackAnnotations.load(args.annotations)
        input_mode = "annotation_manifest"
    experiment_config = load_experiment_config(args.config)
    groundtruth_annotations = (
        AttackAnnotations.load(args.groundtruth_annotations, require_seeds=False)
        if args.groundtruth_annotations
        else None
    )
    output = Path(args.output)
    score_ledger_dir = (
        output.parent / f"{output.stem}-ledger"
        if experiment_config.score_ledger_enabled else None
    )
    progress_path = Path(str(args.output) + ".progress.json")

    def save_progress(event: dict) -> None:
        payload = {"incomplete": True, **event}
        progress_path.parent.mkdir(parents=True, exist_ok=True)
        progress_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(
            "[progress] " + json.dumps(event, ensure_ascii=False),
            file=sys.stderr,
            flush=True,
        )

    with ProvenanceStore(args.db) as store:
        report = run_experiment(
            store,
            annotations,
            keep_ratios=experiment_config.keep_ratios,
            rarity_weight=experiment_config.rarity_weight,
            damping=experiment_config.damping,
            diffusion_mode=experiment_config.diffusion_mode,
            path_weight=experiment_config.path_weight,
            impact_weight=experiment_config.impact_weight,
            behavior_weight=experiment_config.behavior_weight,
            path_decay=experiment_config.path_decay,
            pruning_mode=experiment_config.pruning_mode,
            fusion_mode=experiment_config.fusion_mode,
            score_mass_target=experiment_config.score_mass_target,
            protect_alert_edges=experiment_config.protect_alert_edges,
            groundtruth_annotations=groundtruth_annotations,
            pruning_scope=experiment_config.pruning_scope,
            causal_search_config=experiment_config.causal_search,
            merge_threshold_seconds=experiment_config.merge_threshold_seconds,
            data_flow_alpha=experiment_config.data_flow_alpha,
            kmeans_restarts=experiment_config.kmeans_restarts,
            depimpact_random_seed=experiment_config.depimpact_random_seed,
            behavior_min_cluster_size=experiment_config.behavior_min_cluster_size,
            behavior_fallback_gap_seconds=experiment_config.behavior_fallback_gap_seconds,
            embedding_dimensions=experiment_config.embedding_dimensions,
            minimum_token_frequency=experiment_config.minimum_token_frequency,
            connectivity_protection=True,
            use_frequency_cache=True,
            use_frequency_snapshot=True,
            progress_callback=save_progress,
            poi_aggregation=experiment_config.poi_aggregation,
            churn_slack_ratio=experiment_config.churn_slack_ratio,
            positive_score_only=experiment_config.positive_score_only,
            certificate_topology_policy=(
                experiment_config.certificate_topology_policy
            ),
            score_ledger_dir=score_ledger_dir,
            high_score_threshold=experiment_config.high_score_threshold,
            high_score_quantile=experiment_config.high_score_quantile,
        )
    report["config_file"] = str(Path(args.config).resolve())
    report["input_mode"] = input_mode
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    progress_path.write_text(
        json.dumps(
            {"incomplete": bool(report.get("incomplete", False)), "stage": "complete"},
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["build_parser", "main"]
