#!/usr/bin/env python3
"""Run PIDSMaker KAIROS through training, stopping before label-aware evaluation."""

from __future__ import annotations

import importlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import time


STAGES = ("construction", "transformation", "featurization", "feat_inference", "batching", "training")
LOCAL_SOURCE_DAY = "2018-04-13"
LOCAL_TRAIN_DAY = "2018-04-03"
LOCAL_VAL_DAY = "2018-04-04"


def _atomic(path: Path, payload: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def validate_cfg(cfg) -> None:
    if cfg.dataset.name != "TRACE_E3" or cfg._model != "kairos":
        raise ValueError("this driver admits only KAIROS on TRACE_E3")
    if bool(cfg.training.decoder.use_few_shot):
        raise ValueError("few-shot labels are forbidden in the online detector stage")
    if bool(cfg.training.ocrapt_early_stop.enabled):
        raise ValueError("label-aware early stopping is forbidden")
    if cfg.experiment.used_method != "none":
        raise ValueError("uncertainty/tuning experiments are outside the frozen protocol")


def _set_local_dates(cfg, *, construction: bool) -> None:
    if construction:
        cfg.dataset.train_dates = [LOCAL_SOURCE_DAY]
        cfg.dataset.val_dates = [LOCAL_SOURCE_DAY]
        cfg.dataset.test_dates = [LOCAL_SOURCE_DAY]
    else:
        cfg.dataset.train_dates = [LOCAL_TRAIN_DAY]
        cfg.dataset.val_dates = [LOCAL_VAL_DAY]
        cfg.dataset.test_dates = [LOCAL_SOURCE_DAY]


def _materialize_local_split(cfg, repo_root: Path) -> dict:
    module_path = repo_root / "tc_pruning" / "trace_local_split.py"
    spec = importlib.util.spec_from_file_location("trace_local_split_standalone", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load local split helper: {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    manifest = module.materialize_chronological_split(
        cfg.construction._graphs_dir,
        source_day=LOCAL_SOURCE_DAY,
        train_day=LOCAL_TRAIN_DAY,
        val_day=LOCAL_VAL_DAY,
    )
    _set_local_dates(cfg, construction=False)
    from pidsmaker.preprocessing.build_graph_methods.build_default_graphs import compute_and_save_split2nodes
    compute_and_save_split2nodes(cfg)
    return manifest


def main(argv=None) -> int:
    repo_root = Path(__file__).resolve().parents[1]
    pids_root = Path(os.environ.get("PIDSMaker_ROOT", "/root/PIDSMaker-main")).resolve()
    sys.path.insert(0, str(pids_root))
    from pidsmaker.config import get_runtime_required_args, get_yml_cfg, set_task_to_done, update_task_paths_to_restart
    from pidsmaker.utils.utils import set_seed
    import wandb

    args = get_runtime_required_args(args=list(sys.argv[1:] if argv is None else argv))
    cfg = get_yml_cfg(args)
    local_single_day = os.environ.get("TRACE_E3_LOCAL_SINGLE_DAY") == "1"
    validate_cfg(cfg)
    set_seed(cfg)
    wandb.init(mode="disabled")
    status_path = Path(cfg._artifact_dir) / "trace-e3-kairos-training-status.json"
    status_path.parent.mkdir(parents=True, exist_ok=True)
    status = {
        "status": "RUNNING", "detector": "KAIROS", "dataset": "TRACE_E3",
        "pid": os.getpid(), "stages": {},
        "data_protocol": "local-single-day-chronological-25-10-65" if local_single_day else "official-split",
    }
    _atomic(status_path, status)
    try:
        for stage in STAGES:
            validate_cfg(cfg)
            restart = update_task_paths_to_restart(cfg)
            if local_single_day:
                _set_local_dates(cfg, construction=(stage == "construction"))
            started = time.perf_counter()
            task_path = Path(getattr(cfg, stage)._task_path)
            status.update({"current_stage": stage, "updated_ns": time.time_ns()})
            _atomic(status_path, status)
            if restart[stage]:
                importlib.import_module(f"pidsmaker.tasks.{stage}").main(cfg)
                if stage == "construction" and local_single_day:
                    status["local_split"] = _materialize_local_split(cfg, repo_root)
                set_task_to_done(str(task_path))
            status["stages"][stage] = {
                "seconds": time.perf_counter() - started,
                "task_path": str(task_path), "reused": not restart[stage],
            }
            _atomic(status_path, status)
        status.update({
            "status": "COMPLETED", "current_stage": None, "updated_ns": time.time_ns(),
            "paths": {
                "graphs_dir": str(cfg.transformation._graphs_dir),
                "construction_path": str(cfg.construction._task_path),
                "edge_losses_dir": str(cfg.training._edge_losses_dir),
            },
            "split": {
                "train_dates": list(cfg.dataset.train_dates),
                "val_dates": list(cfg.dataset.val_dates),
                "test_dates": list(cfg.dataset.test_dates),
            },
        })
        _atomic(status_path, status)
    except BaseException as error:
        status.update({
            "status": "FAILED", "error_type": type(error).__name__,
            "reason": str(error), "updated_ns": time.time_ns(),
        })
        _atomic(status_path, status)
        raise
    finally:
        wandb.finish()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
