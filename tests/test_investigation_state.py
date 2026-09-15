from tc_pruning.investigation.investigation_state import InvestigationState


def test_incremental_checkpoint_reports_deterministic_churn():
    state = InvestigationState.empty()
    first = state.update(component_ids={"a"}, selected_event_ids={"e1"})
    second = first.update(component_ids={"a", "b"}, selected_event_ids={"e2"})
    assert (second.added_event_ids, second.removed_event_ids) == (("e2",), ("e1",))
    assert second.version == 2
