from pathlib import Path

from tc_pruning.trace_local_split import chronological_partition


def test_chronological_partition_is_label_free_and_keeps_majority_for_test():
    paths = [Path(f"window-{index:02d}.pt") for index in range(20, 0, -1)]

    split = chronological_partition(paths)

    assert [path.name for path in split["train"]] == [f"window-{i:02d}.pt" for i in range(1, 6)]
    assert [path.name for path in split["val"]] == ["window-06.pt", "window-07.pt"]
    assert [path.name for path in split["test"]] == [f"window-{i:02d}.pt" for i in range(8, 21)]


def test_chronological_partition_rejects_too_few_windows():
    try:
        chronological_partition([Path("one.pt"), Path("two.pt")])
    except ValueError as error:
        assert "at least three" in str(error)
    else:
        raise AssertionError("two windows must not produce an empty split")
