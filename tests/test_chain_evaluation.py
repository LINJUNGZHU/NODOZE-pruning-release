"""Independent chain evidence must not turn partial paths into complete attacks."""
from copy import deepcopy
import importlib.util

import pytest


def edge(event, src, dst, timestamp, relation="EVENT_WRITE"):
    return {"event_id": event, "src": src, "dst": dst,
            "timestamp_ns": timestamp, "relation": relation}


def reviewed(events, **extra):
    return {"id": "reviewed-chain", "event_ids": events,
            "provenance": {"kind": "independent_review", "source": "review.json",
                           "reviewed_by": "analyst", "scope": "entry to objective"},
            "scope_complete": True, **extra}


def evaluate(chains, rows, stages):
    assert importlib.util.find_spec("tc_pruning.chain_evaluation") is not None, "chain evaluator has not been implemented"
    from tc_pruning.chain_evaluation import evaluate_chains
    return evaluate_chains(chains, rows, stages)


def four_step_rows():
    return [edge("E1", "A", "B", 1), edge("E2", "B", "C", 2),
            edge("E3", "C", "D", 3), edge("E4", "D", "E", 4)]


def test_deleting_middle_event_destroys_complete_chain_and_attributes_first_loss():
    rows = four_step_rows()
    result = evaluate([reviewed(["E1", "E2", "E3", "E4"])], rows,
                      {"source": {"E1", "E2", "E3", "E4"},
                       "candidate": {"E1", "E2", "E3", "E4"},
                       "retained": {"E1", "E3", "E4"}})
    assert result["stages"]["candidate"]["complete_chain_count"] == 1
    assert result["stages"]["retained"]["complete_chain_retention"] == {"numerator": 0, "denominator": 1, "value": 0.0}
    assert result["first_loss_counts"]["retained"] == 1
    assert result["chains"][0]["stages"]["retained"]["missing_ids"] == ["E2"]
    assert result["event_funnel"]["stages"]["retained"]["total_retention"]["value"] == 0.75


def test_all_reference_branches_and_extra_required_evidence_are_mandatory():
    rows = [edge("E1", "A", "B", 1), edge("E2", "B", "C", 2),
            edge("E3", "B", "D", 3), edge("E4", "X", "Y", 4)]
    chain = reviewed(["E1", "E2"], branches=[["E1", "E3"]], required_event_ids=["E4"])
    result = evaluate([chain], rows, {"source": {"E1", "E2", "E3", "E4"}, "retained": {"E1", "E2", "E4"}})
    assert result["valid_complete_chain_count"] == 1
    assert result["stages"]["retained"]["complete_chain_count"] == 0
    assert result["chains"][0]["required_event_ids"] == ["E1", "E2", "E3", "E4"]
    assert result["chains"][0]["stages"]["retained"]["missing_ids"] == ["E3"]
    extra_missing = evaluate([chain], rows, {"retained": {"E1", "E2", "E3"}})
    assert extra_missing["chains"][0]["stages"]["retained"]["missing_ids"] == ["E4"]


@pytest.mark.parametrize("second,reason", [(edge("E2", "B", "C", 1), "simultaneous_timestamp"),
                                           (edge("E2", "B", "C", 0), "reversed_timestamp"),
                                           (edge("E2", "X", "C", 2), "disconnected_direction")])
def test_invalid_time_or_direction_never_counts_as_complete(second, reason):
    result = evaluate([reviewed(["E1", "E2"])], [edge("E1", "A", "B", 1), second], {"source": {"E1", "E2"}})
    assert result["invalid_chain_count"] == 1
    assert result["stages"]["source"]["complete_chain_count"] == 0
    assert reason in {p["reason"] for p in result["chains"][0]["breakpoints"]}
    assert result["first_loss_counts"]["invalid_reference"] == 1


def test_execute_reverses_stored_endpoints_for_causal_continuity():
    rows = [edge("E1", "PARENT", "BIN", 1), edge("E2", "CHILD", "BIN", 2, "EVENT_EXECUTE"), edge("E3", "CHILD", "NET", 3)]
    result = evaluate([reviewed(["E1", "E2", "E3"])], rows, {"retained": {"E1", "E2", "E3"}})
    assert result["stages"]["retained"]["complete_chain_count"] == 1


def test_missing_source_event_is_unverifiable_and_stays_in_denominator():
    result = evaluate([reviewed(["E1", "MISSING"])], [edge("E1", "A", "B", 1)], {"source": {"E1"}, "candidate": {"E1"}, "retained": {"E1"}})
    assert result["unverifiable_chain_count"] == 1
    assert result["admitted_complete_chain_count"] == 1
    assert result["chains"][0]["missing_source_ids"] == ["MISSING"]
    assert result["chains"][0]["first_loss_stage"] == "source"
    assert result["first_loss_counts"]["source"] == 1
    assert result["stages"]["retained"]["complete_chain_retention"]["denominator"] == 1
    assert result["event_funnel"]["first_loss_counts"]["source"] == 1


def test_empty_denominators_are_none():
    result = evaluate([], [], {"source": [], "retained": []})
    assert result["stages"]["retained"]["complete_chain_retention"]["value"] is None
    assert result["stages"]["retained"]["derived_chain_retention"]["value"] is None
    assert result["event_funnel"]["stages"]["retained"]["conditional_retention"]["value"] is None


def test_non_nested_stages_rejected():
    with pytest.raises(ValueError, match="nested"):
        evaluate([reviewed(["E1", "E2"])], four_step_rows(), {"candidate": ["E1"], "retained": ["E2"]})


def test_stages_cannot_claim_events_missing_from_source_graph():
    with pytest.raises(ValueError, match="source"):
        evaluate([], [], {"source": ["E1"]})


@pytest.mark.parametrize("kind", ["derived_reference", "synthetic"])
def test_derived_and_synthetic_evidence_never_upgraded_to_independent_complete(kind):
    chain = reviewed(["E1", "E2"])
    chain["provenance"]["kind"] = kind
    result = evaluate([chain], four_step_rows(), {"retained": ["E1", "E2"]})
    assert result["admitted_complete_chain_count"] == 0
    assert result["stages"]["retained"]["complete_chain_retention"]["value"] is None
    metric = "derived_chain_count" if kind == "derived_reference" else "synthetic_chain_count"
    assert result["stages"]["retained"][metric] == 1


@pytest.mark.parametrize("field", ["reviewed_by", "scope"])
def test_review_requires_identifiable_reviewer_and_explicit_scope(field):
    chain = reviewed(["E1", "E2"])
    del chain["provenance"][field]
    result = evaluate([chain], four_step_rows(), {"retained": ["E1", "E2"]})
    assert result["admitted_complete_chain_count"] == 0
    assert result["unreviewed_reference_chain_count"] == 1


def test_review_of_partial_scope_is_not_complete_attack_ground_truth():
    chain = reviewed(["E1", "E2"], scope_complete=False)
    result = evaluate([chain], four_step_rows(), {"retained": ["E1", "E2"]})
    assert result["admitted_complete_chain_count"] == 0


def test_loss_funnel_is_mutually_exclusive_and_uses_previous_stage_denominator():
    chains = [reviewed(["E1", "E2"], id="first"), reviewed(["E3", "E4"], id="second")]
    result = evaluate(chains, four_step_rows(), {"source": ["E1", "E2", "E3", "E4"], "candidate": ["E1", "E3", "E4"], "retained": ["E1", "E3"]})
    assert result["first_loss_counts"]["candidate"] == 1
    assert result["first_loss_counts"]["retained"] == 1
    assert sum(result["first_loss_counts"].values()) == 2
    assert result["stages"]["retained"]["conditional_complete_chain_retention"]["denominator"] == 1
    assert result["stages"]["retained"]["complete_chain_retention"]["denominator"] == 2


def test_evaluation_does_not_mutate_references_or_decisions():
    chains, rows = [reviewed(["E1", "E2"])], four_step_rows()
    stages = {"source": ["E1", "E2", "E3", "E4"], "retained": ["E1", "E2"]}
    original = deepcopy((chains, rows, stages))
    evaluate(chains, rows, stages)
    assert (chains, rows, stages) == original


def test_event_only_funnel_and_no_references():
    assert importlib.util.find_spec("tc_pruning.chain_evaluation") is not None
    from tc_pruning.chain_evaluation import evaluate_event_funnel
    result = evaluate_event_funnel(["E1", "E2", "E3", "E3"], {"source": ["E1", "E2"], "retained": ["E1"]})
    assert result["reference_event_count"] == 3
    assert result["stages"]["retained"]["total_retention"]["value"] == pytest.approx(1 / 3)
    assert result["stages"]["retained"]["conditional_retention"]["value"] == 0.5
    assert result["first_loss_counts"] == {"source": 1, "retained": 1, "surviving": 1}


def test_branch_with_invalid_witness_invalidates_whole_chain():
    rows = [edge("E1", "A", "B", 1), edge("E2", "B", "C", 2), edge("E3", "X", "D", 3)]
    result = evaluate([reviewed(["E1", "E2"], branches=[["E1", "E3"]])], rows, {"retained": ["E1", "E2", "E3"]})
    assert result["invalid_chain_count"] == 1
    assert result["stages"]["retained"]["complete_chain_count"] == 0
    assert result["chains"][0]["breakpoints"][0]["path"] == "branches[0]"


def test_duplicate_chain_or_source_event_identity_is_rejected():
    with pytest.raises(ValueError, match="duplicate.*chain"):
        evaluate([reviewed(["E1"]), reviewed(["E1"])], four_step_rows(), {"source": ["E1"]})
    with pytest.raises(ValueError, match="duplicate.*event"):
        evaluate([], [edge("E1", "A", "B", 1), edge("E1", "X", "Y", 2)], {"source": ["E1"]})


def test_empty_witness_is_invalid_even_when_no_evidence_is_missing():
    result = evaluate([reviewed([])], [], {"source": []})
    assert result["invalid_chain_count"] == 1
    assert result["stages"]["source"]["complete_chain_count"] == 0


def test_branch_only_reference_and_top_level_review_metadata_are_supported():
    chain = {"id": "branch-only", "branches": [["E1", "E2"]],
             "scope_complete": True, "reviewed_by": "analyst", "scope": "A to C",
             "provenance": {"kind": "independent_review", "source": "independent.json"}}
    result = evaluate([chain], four_step_rows(), {"retained": ["E1", "E2"]})
    assert result["stages"]["retained"]["complete_chain_count"] == 1


def test_reference_funnel_deduplicates_shared_events_without_merging_chains():
    chains = [reviewed(["E1", "E2"], id="short"), reviewed(["E1", "E2", "E3"], id="long")]
    result = evaluate(chains, four_step_rows(), {"source": ["E1", "E2", "E3"], "retained": ["E1", "E2"]})
    assert result["reference_chain_count"] == 2
    assert result["event_funnel"]["reference_event_count"] == 3
    assert result["stages"]["retained"]["complete_chain_retention"]["value"] == 0.5


def test_canonical_event_ids_match_uppercase_reference_to_lowercase_hash_suffix():
    row = edge("UUID#abcdef", "a", "b", 1)
    result = evaluate([reviewed(["UUID#ABCDEF"])], [row], {"retained": ["UUID#abcdef"]})
    assert result["stages"]["retained"]["complete_chain_count"] == 1


@pytest.mark.parametrize("bad_time", [True, 1.5, "not-a-timestamp"])
def test_malformed_source_time_is_not_a_valid_witness(bad_time):
    result = evaluate([reviewed(["E1"])], [edge("E1", "A", "B", bad_time)], {"source": ["E1"]})
    assert result["invalid_chain_count"] == 1
    assert result["chains"][0]["breakpoints"][0]["reason"] == "malformed_source_event"
