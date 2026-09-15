#!/usr/bin/env python3
"""Run frozen KAIROS inference for additional CADETS days without label logic."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kairos-root", required=True)
    parser.add_argument("--days", nargs="+", type=int, required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    experiment = Path(args.kairos_root) / "DARPA" / "CADETS_E3"
    artifact = experiment / "artifact"
    sys.path.insert(0, str(experiment))
    os.chdir(experiment)

    import torch
    from kairos_utils import gen_nodeid2msg, init_database_connection
    from test import test as reconstruct

    cursor, connection = init_database_connection()
    try:
        nodeid2msg = gen_nodeid2msg(cursor)
    finally:
        cursor.close()
        connection.close()
    model_path = artifact / "models" / "models.pt"
    memory, gnn, link_pred, neighbor_loader = torch.load(model_path, map_location="cuda")
    runs = []
    for day in args.days:
        output = artifact / f"graph_4_{day}"
        if output.exists() and any(output.glob("*.txt")) and not args.force:
            runs.append({"day": day, "status": "EXISTING", "window_count": len(list(output.glob("*.txt")))})
            continue
        output.mkdir(parents=True, exist_ok=True)
        graph_path = artifact / "graphs" / f"graph_4_{day}.TemporalData.simple"
        started = time.perf_counter()
        graph = torch.load(graph_path, map_location="cuda")
        reconstruct(graph, memory, gnn, link_pred, neighbor_loader, nodeid2msg, str(output))
        runs.append({
            "day": day, "status": "RECONSTRUCTED", "seconds": time.perf_counter() - started,
            "window_count": len(list(output.glob("*.txt"))), "graph_sha256": _hash(graph_path),
        })
    manifest = {
        "schema_version": "kairos-frozen-reconstruction-v1",
        "model_sha256": _hash(model_path), "torch_version": torch.__version__,
        "cuda_available": torch.cuda.is_available(), "random_seed": "frozen_model_inference",
        "runs": runs,
    }
    target = Path(args.manifest)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
