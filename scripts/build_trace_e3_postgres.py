#!/usr/bin/env python3
"""Populate PIDSMaker's TRACE E3 PostgreSQL database from the local SQLite store."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import time

from tc_pruning.trace_postgres import build_database


def _atomic(path: Path, payload: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sqlite", required=True)
    parser.add_argument("--status", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5432)
    parser.add_argument("--user", default="postgres")
    parser.add_argument("--password", default="postgres")
    parser.add_argument("--database", default="trace_e3")
    args = parser.parse_args()
    status_path = Path(args.status)
    status_path.parent.mkdir(parents=True, exist_ok=True)
    state = {"status": "RUNNING", "stage": "schema", "rows": {}, "updated_ns": time.time_ns()}
    _atomic(status_path, state)

    def progress(stage: str, rows: int) -> None:
        state.update({"stage": stage, "updated_ns": time.time_ns()})
        if rows:
            state["rows"][stage] = rows
        _atomic(status_path, state)

    try:
        result = build_database(
            args.sqlite,
            host=args.host,
            port=args.port,
            user=args.user,
            password=args.password,
            database=args.database,
            progress=progress,
        )
    except BaseException as error:
        state.update(
            {"status": "FAILED", "error_type": type(error).__name__, "reason": str(error), "updated_ns": time.time_ns()}
        )
        _atomic(status_path, state)
        raise
    state.update({"status": "COMPLETED", "stage": None, "result": result, "updated_ns": time.time_ns()})
    _atomic(status_path, state)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
