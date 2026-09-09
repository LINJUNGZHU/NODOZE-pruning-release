# RDP-Guard Implementation Plan

> **Execution note:** This workspace is not a Git repository, so worktree and commit steps are unavailable. Changes are made in place with test checkpoints. The user explicitly requested uninterrupted implementation, so this plan is executed immediately in the current session.

**Goal:** Implement diffusion-gated rarity scoring, raw-event-budget selection, an auditable ordered-POI path certificate, and a Ground-Truth-independent operating-point recommendation; then verify the method on CADETS E3.

**Architecture:** Keep candidate construction, historical frequency modeling, DEPIMPACT grouping, behavior extraction, and temporal diffusion intact. Add an isolated RDP-Guard scoring/recommendation module, opt into it through strict configuration, and extend pruning results with budget/mass/certificate diagnostics. Preserve the legacy additive path for reproducibility.

**Tech Stack:** Python 3, dataclasses, pytest, existing SQLite-backed provenance store and CLI.

---

## Task 1: Specify gated fusion with failing unit tests

**Files:**
- Create: `tc_pruning/rdp_guard.py`
- Create: `tests/test_rdp_guard.py`

1. Write tests showing a remote rare edge cannot outrank a diffusion-supported common bridge.
2. Write tests showing rarity breaks ties among equally diffusion-supported edges.
3. Write tests for zero/empty score normalization and invalid weights.
4. Run `python -m pytest tests/test_rdp_guard.py -q` and confirm RED because the module/API does not exist.
5. Implement the minimum pure scoring API and rerun until GREEN.

## Task 2: Implement guarded raw-event budget and path certificate

**Files:**
- Modify: `tc_pruning/pruning.py`
- Modify: `tests/test_diffusion_pruning.py`

1. Add failing tests for `fusion_mode="rdp_guard"`, certificate fields, and raw-event budget fill with uneven atomic groups.
2. Extend `PruningResult` with scoring mode, score-mass, POI counts, and certificate validity.
3. Delegate score calculation to RDP-Guard only in the new mode; keep additive behavior byte-for-byte equivalent at the API level.
4. Add `rdp_guard` selection mode that scans past oversized groups while never exceeding a feasible raw-event budget.
5. Compute the certificate after pruning and expose all diagnostics.
6. Run focused pruning tests until GREEN.

## Task 3: Wire strict config, CLI, evaluation, and recommendation

**Files:**
- Modify: `tc_pruning/config.py`
- Modify: `tc_pruning/cli.py`
- Modify: `tc_pruning/evaluation.py`
- Modify: `tests/test_evaluation_cli.py`
- Modify: `configs/tc_pruning_poi_alert.json`

1. Add failing config tests for optional `fusion_mode`, allowed values, and optional `score_mass_target`.
2. Thread both options through the CLI and experiment runner.
3. Include score mass and certificate fields in per-budget and per-group report rows.
4. Add a pure recommendation function that uses only score mass, certificate validity, actual ratio, and budget feasibility—not attack labels.
5. Add report-level tests proving Ground Truth metrics do not influence recommendation.
6. Configure the CADETS profile for temporal diffusion, RDP-Guard fusion, RDP-Guard budget selection, and alert/stage protection.
7. Run focused config/evaluation tests until GREEN.

## Task 4: Documentation and operator command

**Files:**
- Modify: `README.md`
- Modify: `docs/EVALUATION_PROTOCOL_V2.md`

1. Document the formula, the structural guarantee, and the Ground-Truth boundary.
2. Document the exact foreground and timestamped `nohup` background commands.
3. Document progress inspection commands (`ps`, `tail`, and result summary).
4. Check all documented paths and CLI flags against `--help`.

## Task 5: Full verification and CADETS experiment

**Files:**
- Runtime outputs under: `output/tc/ubc-cadets-e3/pdf-stage/`
- Runtime logs under: `logs/`

1. Run `python -m pytest tests -q` and preserve the complete pass/fail output.
2. Run the RDP-Guard CADETS command in the background with a `YYYY-MM-DD_HH-MM-SS` log/result name.
3. Monitor candidate construction, scoring, pruning curves, memory, and process exit status.
4. Parse the completed result and compare RDP-Guard against rarity-only, diffusion-only, and legacy additive fusion without using Ground Truth to change the online score.
5. If the 20% target misses the design criterion, diagnose the first failing stage, add a focused regression test, and change only the algorithmic cause.
6. Re-run focused/full tests and the real experiment after any correction.
7. Report the final command, PID/log/result paths, budget fidelity, compression, POI certificate, attack-event recall, and complete-path retention.
