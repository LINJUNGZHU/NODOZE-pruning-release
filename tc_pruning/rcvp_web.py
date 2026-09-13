"""Small, JSON-oriented adapter from an OPTC candidate to shared RCVP."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping, Sequence

import numpy as np

from tc_pruning.rdp_guard import fuse_rarity_diffusion
from tc_pruning.rcvp_web_config import validate_fusion_config


def rcvp_propagate(*args, **kwargs):
    from tc_pruning.rcvp import propagate
    return propagate(*args, **kwargs)


def preset(name):
    from tc_pruning.rcvp_config import preset as load_preset
    return load_preset(name)


@dataclass(frozen=True)
class CandidateScores:
    scores: np.ndarray
    components: list[dict[str, Any]]
    edge_fields: dict[str, np.ndarray]
    roots: list[dict[str, Any]]
    algorithm: dict[str, Any]


def _jsonable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, np.generic):
        return value.item()
    return value


def score_candidate(
    *,
    src: np.ndarray,
    dst: np.ndarray,
    timestamp: np.ndarray,
    relation_names: Sequence[str],
    rarity: np.ndarray,
    poi: np.ndarray,
    process_nodes: np.ndarray,
    preset_name: str,
    fusion_config: Mapping[str, Any] | None = None,
) -> CandidateScores:
    if preset_name not in {"relation_aware", "full"}:
        raise ValueError("unknown algorithm mode")
    config = preset(preset_name)
    fusion = validate_fusion_config(fusion_config)
    diffusion, diagnostics = rcvp_propagate(
        src, dst, timestamp, relation_names, rarity, poi, process_nodes, config=config
    )
    edge_fields = {
        str(name): np.asarray(values)
        for name, values in diagnostics.get("edge_fields", {}).items()
    }
    edge_count = len(src)
    if len(diffusion) != edge_count or any(len(values) != edge_count for values in edge_fields.values()):
        raise ValueError("RCVP diagnostics do not match candidate edge count")
    fused = fuse_rarity_diffusion(
        range(edge_count), rarity=dict(enumerate(map(float, rarity))),
        diffusion=dict(enumerate(map(float, diffusion))), **fusion,
    )
    scores = np.asarray([fused.scores[i] for i in range(edge_count)], dtype=float)
    components = [dict(fused.components[i]) for i in range(edge_count)]
    safe_config = _jsonable(config)
    identity_config = {"propagation": safe_config, "fusion": fusion}
    digest = hashlib.sha256(json.dumps(identity_config, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return CandidateScores(
        scores=scores,
        components=components,
        edge_fields=edge_fields,
        roots=list(diagnostics.get("roots", [])),
        algorithm={"mode": preset_name, "preset": preset_name, "config": safe_config,
                   "rcvp_fusion": fusion,
                   "config_sha256": digest, "version": diagnostics.get("version"),
                   "operator": diagnostics.get("operator"),
                   "normalization": _jsonable(diagnostics.get("normalization", {})),
                   "truth_used": bool(diagnostics.get("truth_used", False)),
                   "score_is_probability": bool(diagnostics.get("score_is_probability", False))},
    )
