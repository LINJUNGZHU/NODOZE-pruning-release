from __future__ import annotations

import json
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

from .causal import CausalSearchConfig


@dataclass(frozen=True, slots=True)
class ExperimentConfig:
    causal_search: CausalSearchConfig
    keep_ratios: tuple[float, ...]
    rarity_weight: float
    path_weight: float
    impact_weight: float
    behavior_weight: float
    path_decay: float
    damping: float
    diffusion_mode: str
    merge_threshold_seconds: float
    data_flow_alpha: float
    kmeans_restarts: int
    depimpact_random_seed: int
    behavior_min_cluster_size: int
    behavior_fallback_gap_seconds: float
    embedding_dimensions: int
    minimum_token_frequency: int
    pruning_mode: str
    pruning_scope: str
    protect_alert_edges: bool
    fusion_mode: str
    score_mass_target: float
    poi_aggregation: str
    churn_slack_ratio: float
    positive_score_only: bool
    certificate_topology_policy: str
    score_ledger_enabled: bool
    high_score_threshold: float
    high_score_quantile: float

    def __post_init__(self) -> None:
        if not self.keep_ratios or any(
            not 0.0 < value <= 1.0 for value in self.keep_ratios
        ):
            raise ValueError("pruning.keep_ratios values must be in (0, 1]")
        if not 0.0 <= self.rarity_weight <= 1.0:
            raise ValueError("scoring.rarity_weight must be in [0, 1]")
        if not 0.0 <= self.path_weight <= 1.0:
            raise ValueError("scoring.path_weight must be in [0, 1]")
        if not 0.0 <= self.impact_weight <= 1.0:
            raise ValueError("scoring.impact_weight must be in [0, 1]")
        if not 0.0 <= self.behavior_weight <= 1.0:
            raise ValueError("scoring.behavior_weight must be in [0, 1]")
        if (
            self.rarity_weight
            + self.path_weight
            + self.impact_weight
            + self.behavior_weight
            > 1.0
        ):
            raise ValueError("scoring weights must sum to <= 1")
        if not 0.0 < self.path_decay <= 1.0:
            raise ValueError("scoring.path_decay must be in (0, 1]")
        if not 0.0 <= self.damping < 1.0:
            raise ValueError("scoring.damping must be in [0, 1)")
        if self.diffusion_mode not in {"undirected_ppr", "time_respecting_bidir"}:
            raise ValueError(
                "scoring.diffusion_mode must be undirected_ppr or time_respecting_bidir"
            )
        if self.fusion_mode not in {"additive", "rdp_guard"}:
            raise ValueError("scoring.fusion_mode must be additive or rdp_guard")
        if self.poi_aggregation not in {"joint", "noisy_or"}:
            raise ValueError("scoring.poi_aggregation must be joint or noisy_or")
        if not 0.0 < self.score_mass_target <= 1.0:
            raise ValueError("scoring.score_mass_target must be in (0, 1]")
        if self.pruning_mode not in {"ratio", "adaptive", "rdp_guard"}:
            raise ValueError("pruning.mode must be ratio, adaptive, or rdp_guard")
        if self.pruning_scope not in {"auto", "merged", "per-alert"}:
            raise ValueError("pruning.scope must be auto, merged, or per-alert")
        if not 0.0 <= self.churn_slack_ratio <= 1.0:
            raise ValueError("pruning.churn_slack_ratio must be in [0, 1]")
        if not isinstance(self.positive_score_only, bool):
            raise ValueError("pruning.positive_score_only must be a boolean")
        if self.certificate_topology_policy not in {
            "strict_chain", "causal_path_cover"
        }:
            raise ValueError(
                "pruning.certificate_topology_policy must be strict_chain or "
                "causal_path_cover"
            )
        if not isinstance(self.score_ledger_enabled, bool):
            raise ValueError("evidence.score_ledger_enabled must be a boolean")
        if not 0.0 <= self.high_score_threshold <= 1.0:
            raise ValueError("evidence.high_score_threshold must be in [0, 1]")
        if not 0.0 < self.high_score_quantile <= 1.0:
            raise ValueError("evidence.high_score_quantile must be in (0, 1]")
        if self.merge_threshold_seconds < 0.0:
            raise ValueError("depimpact.merge_threshold_seconds must be non-negative")
        if self.data_flow_alpha <= 0.0:
            raise ValueError("depimpact.data_flow_alpha must be positive")
        if self.kmeans_restarts <= 0:
            raise ValueError("depimpact.kmeans_restarts must be positive")
        if self.behavior_min_cluster_size < 2:
            raise ValueError("behavior.min_cluster_size must be at least 2")
        if self.behavior_fallback_gap_seconds <= 0.0:
            raise ValueError("behavior.fallback_gap_seconds must be positive")
        if self.embedding_dimensions <= 0 or self.minimum_token_frequency <= 0:
            raise ValueError("behavior embedding settings must be positive")


def _strict_section(
    document: dict[str, Any], section: str, allowed: set[str],
    *, optional: set[str] | None = None,
) -> dict:
    value = document.get(section)
    if not isinstance(value, dict):
        raise ValueError(f"missing or invalid {section} section")
    optional = optional or set()
    unknown = sorted(set(value) - allowed - optional)
    if unknown:
        raise ValueError(f"unknown {section} fields: {', '.join(unknown)}")
    missing = sorted(allowed - set(value))
    if missing:
        raise ValueError(f"missing {section} fields: {', '.join(missing)}")
    return value


def load_experiment_config(path: str | Path) -> ExperimentConfig:
    source = Path(path)
    document = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("experiment configuration must be a JSON object")
    unknown_sections = sorted(
        set(document) - {
            "causal_search", "scoring", "pruning", "depimpact", "behavior",
            "evidence",
        }
    )
    if unknown_sections:
        raise ValueError(f"unknown configuration sections: {', '.join(unknown_sections)}")

    causal_value = document.get("causal_search")
    if not isinstance(causal_value, dict):
        raise ValueError("missing or invalid causal_search section")
    causal_allowed = {field.name for field in fields(CausalSearchConfig)}
    causal_unknown = sorted(set(causal_value) - causal_allowed)
    if causal_unknown:
        raise ValueError(
            f"unknown causal_search fields: {', '.join(causal_unknown)}"
        )
    # Search-policy fields have dataclass defaults so older experiment profiles
    # remain reproducible while new profiles can opt into explicit tuning.
    causal_raw = dict(causal_value)
    scoring = _strict_section(
        document,
        "scoring",
        {
            "rarity_weight",
            "path_weight",
            "impact_weight",
            "behavior_weight",
            "path_decay",
            "damping",
        },
        optional={
            "diffusion_mode", "fusion_mode", "score_mass_target",
            "poi_aggregation",
        },
    )
    depimpact = _strict_section(
        document,
        "depimpact",
        {
            "merge_threshold_seconds",
            "data_flow_alpha",
            "kmeans_restarts",
            "random_seed",
        },
    )
    behavior = _strict_section(
        document,
        "behavior",
        {
            "min_cluster_size",
            "fallback_gap_seconds",
            "embedding_dimensions",
            "minimum_token_frequency",
        },
    )
    pruning = _strict_section(
        document,
        "pruning",
        {"keep_ratios", "mode", "scope", "protect_alert_edges"},
        optional={
            "churn_slack_ratio", "positive_score_only",
            "certificate_topology_policy",
        },
    )
    evidence = document.get("evidence", {})
    if not isinstance(evidence, dict):
        raise ValueError("missing or invalid evidence section")
    evidence_allowed = {
        "score_ledger_enabled", "high_score_threshold", "high_score_quantile"
    }
    evidence_unknown = sorted(set(evidence) - evidence_allowed)
    if evidence_unknown:
        raise ValueError(f"unknown evidence fields: {', '.join(evidence_unknown)}")

    def strict_boolean(
        section: dict, field: str, default: bool, *, label: str
    ) -> bool:
        value = section.get(field, default)
        if not isinstance(value, bool):
            raise ValueError(f"{label} must be a boolean")
        return value

    return ExperimentConfig(
        causal_search=CausalSearchConfig(**causal_raw),
        keep_ratios=tuple(float(value) for value in pruning["keep_ratios"]),
        rarity_weight=float(scoring["rarity_weight"]),
        path_weight=float(scoring["path_weight"]),
        impact_weight=float(scoring["impact_weight"]),
        behavior_weight=float(scoring["behavior_weight"]),
        path_decay=float(scoring["path_decay"]),
        damping=float(scoring["damping"]),
        diffusion_mode=str(scoring.get("diffusion_mode", "undirected_ppr")),
        merge_threshold_seconds=float(depimpact["merge_threshold_seconds"]),
        data_flow_alpha=float(depimpact["data_flow_alpha"]),
        kmeans_restarts=int(depimpact["kmeans_restarts"]),
        depimpact_random_seed=int(depimpact["random_seed"]),
        behavior_min_cluster_size=int(behavior["min_cluster_size"]),
        behavior_fallback_gap_seconds=float(behavior["fallback_gap_seconds"]),
        embedding_dimensions=int(behavior["embedding_dimensions"]),
        minimum_token_frequency=int(behavior["minimum_token_frequency"]),
        pruning_mode=str(pruning["mode"]),
        pruning_scope=str(pruning["scope"]),
        protect_alert_edges=strict_boolean(
            pruning,
            "protect_alert_edges",
            False,
            label="pruning.protect_alert_edges",
        ),
        fusion_mode=str(scoring.get("fusion_mode", "additive")),
        score_mass_target=float(scoring.get("score_mass_target", 0.95)),
        poi_aggregation=str(scoring.get("poi_aggregation", "joint")),
        churn_slack_ratio=float(pruning.get("churn_slack_ratio", 0.0)),
        positive_score_only=strict_boolean(
            pruning, "positive_score_only", False,
            label="pruning.positive_score_only",
        ),
        certificate_topology_policy=str(
            pruning.get("certificate_topology_policy", "strict_chain")
        ),
        score_ledger_enabled=strict_boolean(
            evidence,
            "score_ledger_enabled",
            True,
            label="evidence.score_ledger_enabled",
        ),
        high_score_threshold=float(evidence.get("high_score_threshold", 0.8)),
        high_score_quantile=float(evidence.get("high_score_quantile", 0.99)),
    )


__all__ = ["ExperimentConfig", "load_experiment_config"]
