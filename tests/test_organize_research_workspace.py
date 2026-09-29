"""Workspace moves are opt-in, bounded, and preflighted before any mutation."""
import importlib
import json
import os
from pathlib import Path

import pytest


def module():
    assert importlib.util.find_spec('scripts.organize_research_workspace') is not None
    return importlib.import_module('scripts.organize_research_workspace')


def project(tmp_path):
    root = tmp_path / 'project'
    for name, content in [
        ('output/adaptive-chain-study-20260929/case/report.json', b'{"frozen": 1}\n'),
        ('output/adaptive-chain-study-20260929-final/case/decisions.npz', b'\x00\x01frozen\xff'),
        ('output/tc/user-dataset.db', b'user database'),
        ('output/user-experiment/report.txt', b'user notes'),
        ('notes/private.txt', b'unrelated'),
    ]:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return root


def snapshot(root):
    result = {}
    for path in root.rglob('*'):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            result[relative] = ('link', os.readlink(path))
        elif path.is_file():
            result[relative] = ('file', path.read_bytes())
        else:
            result[relative] = ('directory',)
    return result


def test_default_dry_run_leaves_entire_tree_unchanged(tmp_path, capsys):
    root = project(tmp_path)
    before = snapshot(root)
    assert module().main(['--project-root', str(root)]) == 0
    assert snapshot(root) == before
    report = json.loads(capsys.readouterr().out)
    assert report['applied'] is False
    assert report['planned_mutations'] == 5


def test_apply_preserves_frozen_bytes_and_relative_compatibility_links(tmp_path):
    root = project(tmp_path)
    module().organize_workspace(root, apply=True)
    first = root / 'output/adaptive-chain-study-20260929'
    second = root / 'output/adaptive-chain-study-20260929-final'
    assert first.is_symlink() and second.is_symlink()
    assert os.readlink(first) == 'research/archive/chain-study-v1-exploratory'
    assert os.readlink(second) == 'research/archive/chain-study-v1-final'
    assert (first / 'case/report.json').read_bytes() == b'{"frozen": 1}\n'
    assert (second / 'case/decisions.npz').read_bytes() == b'\x00\x01frozen\xff'
    assert (root / 'output/research/archive/chain-study-v1-final/case/decisions.npz').read_bytes() == b'\x00\x01frozen\xff'
    for name, expected in [
        ('datasets', '../../output/tc'),
        ('exports', '../../webapp/frontend/retained-chain-data'),
        ('current', '../../output/research/chain-workbench-v2'),
    ]:
        assert os.readlink(root / 'research/local' / name) == expected


def test_repeated_apply_and_dry_run_are_idempotent(tmp_path):
    root = project(tmp_path)
    module().organize_workspace(root, apply=True)
    before = snapshot(root)
    for apply in (False, True):
        report = module().organize_workspace(root, apply=apply)
        assert report['planned_mutations'] == 0
        assert snapshot(root) == before


def test_conflict_in_second_archive_prevents_every_mutation(tmp_path):
    root = project(tmp_path)
    conflict = root / 'output/research/archive/chain-study-v1-final'
    conflict.mkdir(parents=True)
    (conflict / 'user-data').write_bytes(b'keep')
    before = snapshot(root)
    with pytest.raises(ValueError, match='conflict'):
        module().organize_workspace(root, apply=True)
    assert snapshot(root) == before


def test_conflicting_local_link_prevents_archive_moves(tmp_path):
    root = project(tmp_path)
    path = root / 'research/local/current'
    path.parent.mkdir(parents=True)
    path.symlink_to('../../output/user-experiment', target_is_directory=True)
    before = snapshot(root)
    with pytest.raises(ValueError, match='conflict'):
        module().organize_workspace(root, apply=True)
    assert snapshot(root) == before


def test_user_directories_and_datasets_are_not_touched(tmp_path):
    root = project(tmp_path)
    database = root / 'output/tc/user-dataset.db'
    inode = database.stat().st_ino
    module().organize_workspace(root, apply=True)
    assert database.read_bytes() == b'user database'
    assert database.stat().st_ino == inode
    assert (root / 'output/user-experiment/report.txt').read_bytes() == b'user notes'
    assert not (root / 'output/user-experiment').is_symlink()
    assert (root / 'notes/private.txt').read_bytes() == b'unrelated'


def test_missing_experiments_are_skipped_without_creating_fake_archives(tmp_path):
    root = tmp_path / 'empty-project'
    root.mkdir()
    report = module().organize_workspace(root, apply=True)
    assert report['planned_mutations'] == 3
    assert not (root / 'output').exists()
    assert (root / 'research/local/current').is_symlink()
    assert not (root / 'research/local/current').exists()


@pytest.mark.parametrize('link_target', ['elsewhere', 'research/archive/chain-study-v1-exploratory'])
def test_unverified_or_broken_existing_compatibility_link_is_rejected(tmp_path, link_target):
    root = tmp_path / 'project'
    (root / 'output').mkdir(parents=True)
    (root / 'output/adaptive-chain-study-20260929').symlink_to(link_target, target_is_directory=True)
    before = snapshot(root)
    with pytest.raises(ValueError, match='conflict'):
        module().organize_workspace(root, apply=True)
    assert snapshot(root) == before


def test_symlink_parent_cannot_redirect_archive_mutation_outside_project(tmp_path):
    root = project(tmp_path)
    outside = tmp_path / 'outside'
    outside.mkdir()
    (root / 'output/research').symlink_to(outside, target_is_directory=True)
    before = snapshot(root)
    with pytest.raises(ValueError, match='parent'):
        module().organize_workspace(root, apply=True)
    assert snapshot(root) == before
    assert list(outside.iterdir()) == []


def test_optional_inventory_is_copied_exactly_without_printing_contents(tmp_path, capsys):
    root = project(tmp_path)
    inventory = tmp_path / 'inventory.json'
    content = b'{"schema_version":"local-test","local_note":"DO_NOT_PRINT_PAYLOAD"}\n'
    inventory.write_bytes(content)
    assert module().main(['--project-root', str(root), '--apply', '--inventory', str(inventory)]) == 0
    assert 'DO_NOT_PRINT_PAYLOAD' not in capsys.readouterr().out
    assert (root / 'research/local/data-inventory.json').read_bytes() == content
    before = snapshot(root)
    assert module().organize_workspace(root, apply=True, inventory=inventory)['planned_mutations'] == 0
    assert snapshot(root) == before


@pytest.mark.parametrize('bad_inventory', [b'invalid-json', b'[]'])
def test_invalid_inventory_prevents_every_mutation(tmp_path, bad_inventory):
    root = project(tmp_path)
    inventory = tmp_path / 'inventory.json'
    inventory.write_bytes(bad_inventory)
    before = snapshot(root)
    with pytest.raises(ValueError, match='inventory'):
        module().organize_workspace(root, apply=True, inventory=inventory)
    assert snapshot(root) == before


def test_inventory_destination_conflict_prevents_archive_moves(tmp_path):
    root = project(tmp_path)
    source = tmp_path / 'inventory.json'
    source.write_text('{"version":2}')
    destination = root / 'research/local/data-inventory.json'
    destination.parent.mkdir(parents=True)
    destination.write_text('{"version":1}')
    before = snapshot(root)
    with pytest.raises(ValueError, match='conflict'):
        module().organize_workspace(root, apply=True, inventory=source)
    assert snapshot(root) == before
