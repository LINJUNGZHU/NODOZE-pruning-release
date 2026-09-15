import ast
import json
from pathlib import Path

from tc_pruning.investigation.evidence_units import EvidenceUnit
from tc_pruning.investigation.forward_sphere import ForwardSphere
from tc_pruning.investigation.phase2 import (
    Phase2Config, canonical_online_bytes, select_residual,
)
from tc_pruning.investigation.reverse_reachability import RootCandidate
from scripts.run_a_rasp_cross_domain_phase2 import _bounded_reconstruction


def _unit(name, score):
    return EvidenceUnit(name, "edge", (name,), (name,), frozenset({name[0]}), frozenset(), None, frozenset(), score, score, 1.0)


def test_legacy_mode_returns_frozen_selection_unchanged():
    result = select_residual(
        (_unit("a1", .9), _unit("b1", .8)),
        config=Phase2Config(selector_mode="legacy"),
        budget=1,
        mandatory_event_ids={"a1"},
        legacy_selected_event_ids={"a1"},
    )
    assert result.selected_event_ids == ("a1",)


def test_online_freeze_has_no_groundtruth_argument_or_runtime_noise():
    value = {"dataset": "CADETS", "queries": [{"candidate": ["e2", "e1"]}]}
    first = canonical_online_bytes(value)
    second = canonical_online_bytes(json.loads(first))
    assert first == second
    assert b"groundtruth" not in first.lower()


def test_online_runner_has_no_groundtruth_cli_or_import_dependency():
    source = Path("scripts/run_a_rasp_cross_domain_phase2.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    option_literals = {
        node.value for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.startswith("--")
    }
    assert not any("groundtruth" in name.lower() for name in imported)
    assert not any("groundtruth" in option.lower() for option in option_literals)


def test_all_budget_ratios_derive_from_same_v0_candidate_count():
    config = Phase2Config(budget_ratios=(.05, .1, .2, .3))
    assert config.absolute_budgets(101) == {"0.05": 5, "0.10": 10, "0.20": 20, "0.30": 30}


def test_reconstruction_guard_is_bounded_and_ignores_unverified_forward_events():
    roots = (RootCandidate("root", 1.0, 1.0, 1, 1.0, 1.0, 1, ("r1", "r2", "r3")),)
    spheres = (
        ForwardSphere("sphere", "root", ("root", "x"), ("unverified",), (), 1.0, 0.0, 0.0, "low_gain"),
    )
    reverse, forward, cap = _bounded_reconstruction(
        ("baseline",), roots, spheres, minimum_new=2, maximum_new=2,
    )
    assert cap == 2
    assert reverse == ("r1",)
    assert forward == ()
