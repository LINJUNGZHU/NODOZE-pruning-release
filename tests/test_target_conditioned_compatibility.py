from tc_pruning.investigation.target_compatibility import TargetContext, TargetConditionedCompatibility


def test_incident_compatible_low_global_candidate_ranks_above_unrelated_candidate():
    matcher = TargetConditionedCompatibility()
    context = TargetContext(
        relations=frozenset({"EVENT_WRITE"}), process_lineage=frozenset({"nginx"}),
        resources=frozenset({"/tmp/drop"}), remote_endpoints=frozenset({"10.0.0.1"}),
        commands=frozenset({"drop"}), neighborhood=frozenset({"p"}),
    )
    compatible = matcher.score(context, relation="EVENT_WRITE", process="nginx",
                               resource="/tmp/drop", remote=None, command="drop", nodes={"p"})
    unrelated = matcher.score(context, relation="EVENT_READ", process="cron",
                              resource="/etc/passwd", remote=None, command="cat", nodes={"x"})
    assert compatible.total > unrelated.total
    assert compatible.relation == 1.0
