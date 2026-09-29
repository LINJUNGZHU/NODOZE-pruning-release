"""Prepare local CAPTAIN reference inputs without networking or publication.

Run ``python -m scripts.prepare_chain_references`` after placing the existing
CADETS 06/12/13 annotation files in ``poi/``. Only attack_event_ids and metadata
are copied. Raw references remain local; this helper never invokes Git.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ("06", "12", "13")


def _read_validated(path: Path, scenario: str) -> dict:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ValueError(f"invalid JSON reference file: {path}") from exc
    if not isinstance(document, dict):
        raise ValueError(f"reference must be a JSON object: {path}")
    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError(f"reference metadata must be an object: {path}")
    if metadata.get("groundtruth_family") != "CAPTAIN/human_readable_gt":
        raise ValueError(f"reference groundtruth_family must be CAPTAIN/human_readable_gt: {path}")
    if metadata.get("scenario") != scenario:
        raise ValueError(f"reference scenario does not match case {scenario}: {path}")
    events = document.get("attack_event_ids")
    if not isinstance(events, list) or any(not isinstance(event, str) or not event.strip() for event in events):
        raise ValueError(f"reference attack_event_ids must be a list of nonempty strings: {path}")
    return document


def prepare_references(
    source_directory: str | Path = ROOT / "poi",
    output_directory: str | Path = ROOT / "configs" / "chain_references",
) -> list[dict]:
    """Validate the entire batch before writing; never replace a conflicting file.

    Content equality ignores JSON formatting. Matching destinations remain
    untouched, including their timestamps. Each missing destination is created
    atomically and exclusively, so a concurrent file cannot be overwritten.
    """
    source_directory, output_directory = Path(source_directory), Path(output_directory)
    pending = []
    # First validate every source and construct only the two permitted fields.
    for scenario in SCENARIOS:
        source = source_directory / f"cadets-e3-captain-{scenario}-annotations.json"
        document = _read_validated(source, scenario)
        reference = {"attack_event_ids": document["attack_event_ids"], "metadata": document["metadata"]}
        payload = json.dumps(reference, sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        pending.append((scenario, output_directory / f"cadets-{scenario}.json", reference, payload))
    # A malformed or conflicting final destination must not cause earlier
    # missing destinations to be written as a partial batch.
    existing = set()
    for scenario, destination, reference, _ in pending:
        if destination.exists() or destination.is_symlink():
            actual = _read_validated(destination, scenario)
            if actual != reference:
                raise ValueError(f"conflicting destination; existing reference was not replaced: {destination}")
            existing.add(destination)
    output_directory.mkdir(parents=True, exist_ok=True)
    summary = []
    for scenario, destination, reference, payload in pending:
        status = "unchanged"
        if destination not in existing:
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=output_directory,
                                                 prefix=".reference-", suffix=".tmp", delete=False) as stream:
                    temporary = Path(stream.name)
                    stream.write(payload)
                # link() is atomic and refuses an existing destination; unlike
                # replace(), it cannot overwrite a file created after validation.
                os.link(temporary, destination)
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
            status = "created"
        summary.append({"scenario": scenario, "event_count": len(reference["attack_event_ids"]),
                        "path": str(destination), "status": status})
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-directory", type=Path, default=ROOT / "poi")
    parser.add_argument("--output-directory", type=Path, default=ROOT / "configs" / "chain_references")
    args = parser.parse_args(argv)
    try:
        summary = prepare_references(args.source_directory, args.output_directory)
    except (OSError, ValueError) as exc:
        print(f"Local reference preparation failed: {exc}", file=sys.stderr)
        return 1
    for row in summary:
        print(f'{row["status"]}: {row["event_count"]} events -> {row["path"]}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
