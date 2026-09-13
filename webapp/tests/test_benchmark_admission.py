"""Paused truth must be rejected before reading logs or running a detector."""
import json
from pathlib import Path

from webapp.scripts import evaluate_pdf_groundtruth as runner


def test_default_evaluation_skips_unreviewed_data_before_loading_truth(tmp_path, monkeypatch, capsys):
    folder = tmp_path / 'webapp/runtime/examples'
    folder.mkdir(parents=True)
    (folder / 'catalog.json').write_text(json.dumps([
        {'id': 'optc-0201', 'cache_path': '/does/not/exist'},
        {'id': 'new-unreviewed-case', 'cache_path': '/also/missing'},
    ]))
    monkeypatch.setattr(runner, 'ROOT', tmp_path)
    monkeypatch.setattr('sys.argv', ['evaluate_pdf_groundtruth.py'])
    def forbidden():
        raise AssertionError('paused cases must not load truth or run inference')
    monkeypatch.setattr(runner, 'load_reference', forbidden)
    runner.main()
    output = json.loads((tmp_path / 'docs/benchmark-admission.json').read_text())
    assert output['eligible'] == []
    assert {x['id'] for x in output['skipped']} == {'optc-0201', 'new-unreviewed-case'}
    assert not (tmp_path / 'docs/pdf-groundtruth-evaluation.json').exists()
    assert 'SKIP' in capsys.readouterr().out


def test_explicit_diagnostic_can_reach_truth_loading(tmp_path, monkeypatch):
    import pytest
    folder = tmp_path / 'webapp/runtime/examples'
    folder.mkdir(parents=True)
    (folder / 'catalog.json').write_text('[{"id":"optc-0201"}]')
    monkeypatch.setattr(runner, 'ROOT', tmp_path)
    monkeypatch.setattr('sys.argv', ['evaluate_pdf_groundtruth.py', '--diagnostic'])
    def stop_at_truth():
        raise RuntimeError('diagnostic reached truth loader')
    monkeypatch.setattr(runner, 'load_reference', stop_at_truth)
    with pytest.raises(RuntimeError, match='diagnostic reached truth loader'):
        runner.main()
    report = json.loads((tmp_path / 'docs/benchmark-admission.json').read_text())
    assert report['mode'] == 'diagnostic_only'
    assert report['eligible'] == []
    assert (tmp_path / 'docs/pdf-diagnostics').is_dir()


def test_low_recall_is_not_a_groundtruth_exclusion_criterion():
    root = Path(__file__).resolve().parents[2]
    policy = json.loads((root / 'configs/benchmark-admission.json').read_text())
    case = policy['cases']['E3-CADETS/node_Nginx_Backdoor_13.csv']
    assert case['positive_node_retention'] is True
    assert case['formal_evaluation'] is False  # CSV has no complete negative/path labels.
    assert sum(c.get('positive_node_retention', False) for c in policy['cases'].values()) == 4
