"""Validated, label-free RDP-Guard fusion settings for the web investigation."""
from __future__ import annotations

import math


DEFAULT_FUSION = {
    "rarity_weight": 0.25,
    "path_weight": 0.0,
    "impact_weight": 0.0,
    "behavior_weight": 0.0,
}


def validate_fusion_config(config=None):
    if config is not None and not isinstance(config, dict):
        raise ValueError("web fusion config must be an object")
    unknown = set(config or {}) - set(DEFAULT_FUSION)
    if unknown:
        raise ValueError(f"unknown web fusion fields: {sorted(unknown)}")
    resolved = dict(DEFAULT_FUSION)
    resolved.update(config or {})
    for name, value in resolved.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError(f"{name} must be finite in [0, 1]")
        resolved[name] = float(value)
    if sum(resolved.values()) > 1 + 1e-12:
        raise ValueError("fusion weights must sum to <= 1")
    unsupported = [name for name in ("path_weight", "impact_weight", "behavior_weight") if resolved[name] != 0]
    if unsupported:
        raise ValueError("web candidate does not provide channels for: " + ", ".join(unsupported))
    return resolved


__all__ = ["DEFAULT_FUSION", "validate_fusion_config"]
