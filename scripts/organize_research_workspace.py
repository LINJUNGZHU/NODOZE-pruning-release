"""Preview or organize two known experiment directories without changing data.

All destinations, compatibility links, and optional inventory are checked before
any write. Existing conflicts are rejected, never merged or overwritten. This is
an offline maintenance operation: stop concurrent directory writers first. The
preflight is not a crash-atomic filesystem transaction. Dataset contents and
unknown experiment directories are never traversed or moved.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path


ARCHIVES = (
    ('output/adaptive-chain-study-20260929', 'output/research/archive/chain-study-v1-exploratory'),
    ('output/adaptive-chain-study-20260929-final', 'output/research/archive/chain-study-v1-final'),
)
LOCAL_LINKS = (
    ('research/local/datasets', '../../output/tc'),
    ('research/local/exports', '../../webapp/frontend/retained-chain-data'),
    ('research/local/current', '../../output/research/chain-workbench-v2'),
)


def _present(path):
    return path.exists() or path.is_symlink()


def _check_parents(root, path):
    """Do not follow a parent symlink when planning a write within the project."""
    parent = root
    for component in path.relative_to(root).parts[:-1]:
        parent = parent / component
        if parent.is_symlink() or (_present(parent) and not parent.is_dir()):
            raise ValueError(f'parent conflict: {parent.relative_to(root)}')


def organize_workspace(project_root, *, apply=False, inventory=None):
    """Return a metadata-only plan; mutate only when ``apply=True``.

    Absent historical experiments are skipped. Correct relative compatibility
    links and local links are idempotent. Local links may point to a pending data
    directory; existing archive compatibility links must resolve to a real
    archived directory. An inventory must be a JSON object and is copied byte
    for byte into the ignored ``research/local`` directory.
    """
    root = Path(project_root).resolve()
    if not root.is_dir():
        raise ValueError('project root must be an existing directory')
    archives, links = [], []
    for source_name, target_name in ARCHIVES:
        source, target = root / source_name, root / target_name
        _check_parents(root, source)
        _check_parents(root, target)
        relative_link = os.path.relpath(target, source.parent)
        if source.is_symlink():
            if (os.readlink(source) != relative_link or target.is_symlink()
                    or not target.is_dir()):
                raise ValueError(f'archive compatibility conflict: {source_name}')
            status = 'unchanged'
        elif _present(source):
            if not source.is_dir() or _present(target):
                raise ValueError(f'archive destination conflict: {source_name} -> {target_name}')
            status = 'move'
        elif _present(target):
            raise ValueError(f'archive destination conflict without compatibility link: {target_name}')
        else:
            status = 'absent'
        archives.append({'source': source_name, 'target': target_name,
                         'compatibility_link': relative_link, 'status': status})

    for name, relative_target in LOCAL_LINKS:
        path = root / name
        _check_parents(root, path)
        if _present(path):
            if not path.is_symlink() or os.readlink(path) != relative_target:
                raise ValueError(f'local link conflict: {name}')
            status = 'unchanged'
        else:
            status = 'create'
        links.append({'path': name, 'target': relative_target, 'status': status})

    inventory_plan, inventory_bytes = None, None
    if inventory is not None:
        inventory_source = Path(inventory).resolve()
        try:
            inventory_bytes = inventory_source.read_bytes()
            contents = json.loads(inventory_bytes)
        except (OSError, ValueError) as exc:
            raise ValueError('inventory must be a readable JSON object') from exc
        if not isinstance(contents, dict):
            raise ValueError('inventory must be a JSON object')
        name = 'research/local/data-inventory.json'
        target = root / name
        _check_parents(root, target)
        if _present(target):
            if target.is_symlink() or not target.is_file() or target.read_bytes() != inventory_bytes:
                raise ValueError(f'inventory destination conflict: {name}')
            status = 'unchanged'
        else:
            status = 'copy'
        inventory_plan = {'source': str(inventory_source), 'target': name, 'status': status,
                          'bytes': len(inventory_bytes),
                          'sha256': hashlib.sha256(inventory_bytes).hexdigest()}

    planned = sum(item['status'] == 'move' for item in archives)
    planned += sum(item['status'] == 'create' for item in links)
    planned += int(inventory_plan is not None and inventory_plan['status'] == 'copy')
    report = {'schema_version': 'research-workspace-plan-v1', 'project_root': str(root),
              'applied': bool(apply), 'planned_mutations': planned,
              'archives': archives, 'local_links': links, 'inventory': inventory_plan}
    if not apply:
        return report

    # No mutation above this point. These paths are fixed, not caller-provided
    # source globs; no unknown experiment or dataset contents are read.
    for item in archives:
        if item['status'] != 'move':
            continue
        source, target = root / item['source'], root / item['target']
        target.parent.mkdir(parents=True, exist_ok=True)
        if _present(target):
            raise ValueError(f'archive destination changed after preflight: {item["target"]}')
        source.rename(target)
        source.symlink_to(item['compatibility_link'], target_is_directory=True)
    for item in links:
        if item['status'] == 'create':
            path = root / item['path']
            path.parent.mkdir(parents=True, exist_ok=True)
            path.symlink_to(item['target'], target_is_directory=True)
    if inventory_plan is not None and inventory_plan['status'] == 'copy':
        target = root / inventory_plan['target']
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as handle:
            handle.write(inventory_bytes)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project-root', type=Path, required=True)
    parser.add_argument('--apply', action='store_true', help='apply the fully preflighted plan; default is preview only')
    parser.add_argument('--inventory', type=Path, help='optional local JSON inventory to copy into research/local')
    args = parser.parse_args(argv)
    try:
        report = organize_workspace(args.project_root, apply=args.apply, inventory=args.inventory)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
