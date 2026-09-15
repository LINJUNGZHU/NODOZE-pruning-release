import ast
from pathlib import Path


def test_online_kairos_modules_have_no_groundtruth_or_official_evaluation_imports():
    paths = [
        Path("tc_pruning/detectors/kairos_adapter.py"),
        Path("tc_pruning/detectors/kairos_queue.py"),
        Path("scripts/export_kairos_evidence.py"),
        Path("scripts/build_kairos_native_queues.py"),
        Path("scripts/reconstruct_kairos_frozen_days.py"),
    ]
    forbidden = ("groundtruth", "ground_truth", "evaluation", "attack_investigation")
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = [
            alias.name.lower()
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        ]
        assert not any(token in name for name in imports for token in forbidden)
