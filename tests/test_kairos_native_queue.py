import json

from tc_pruning.detectors.kairos_queue import build_native_queues


def _write_window(directory, name, rows):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(
        "".join(f"{row!r}\n" for row in rows), encoding="utf-8"
    )


def _row(src, dst, loss):
    return {
        "srcmsg": {"subject": src},
        "dstmsg": {"file": dst},
        "loss": loss,
    }


def test_native_queues_use_frozen_training_idf_and_fixed_beta(tmp_path):
    train = tmp_path / "train"
    _write_window(train, "train.txt", [_row("common", "/tmp/common", 1.0)])
    test = tmp_path / "test"
    _write_window(test, "w1.txt", [
        *[_row("new-root", "/tmp/a", 1.0) for _ in range(9)],
        _row("new-root", "/tmp/a", 10.0),
    ])
    _write_window(test, "w2.txt", [
        *[_row("new-root", "/tmp/b", 1.0) for _ in range(9)],
        _row("new-root", "/tmp/b", 20.0),
    ])

    result = build_native_queues((train,), (test,), beta=50.0)

    assert result["parameters"] == {
        "anomalous_edge_sigma": 1.5,
        "beta": 50.0,
        "idf_rareness_fraction": 0.9,
    }
    assert result["training_window_count"] == 1
    assert len(result["queues"]) == 1
    queue = result["queues"][0]
    assert queue["windows"] == ["w1.txt", "w2.txt"]
    assert queue["selected"] is True
    assert queue["score"] == 231.0


def test_native_queue_manifest_is_canonical_and_has_no_labels(tmp_path):
    test = tmp_path / "test"
    _write_window(test, "w.txt", [
        *[_row("p", "f", 1) for _ in range(9)], _row("p", "f", 9)
    ])
    first = build_native_queues((), (test,), beta=1000.0)
    second = build_native_queues((), (test,), beta=1000.0)
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert "ground" not in json.dumps(first).lower()
    assert first["queues"][0]["selected"] is False
