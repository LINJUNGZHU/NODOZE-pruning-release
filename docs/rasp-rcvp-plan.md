# RASP-RCVP Implementation Plan

Goal: implement the opt-in RCVP algorithm and web controls, verify and publish.
Spec: [rasp-rcvp-design.md](rasp-rcvp-design.md), supplemented by the original user requirements.
Architecture: shared array propagation; existing CLI and web adapters; existing certificate and event-group accounting.
Tech stack: Python, NumPy, SQLite, Flask, native JavaScript.

User explicitly authorized direct implementation and GitHub upload; no further approval gates.
Work on `feat/rasp-rcvp` in the requested repository; preserve unrelated dirty files.

- [x] Task 1: `rcvp_config.py`, `rcvp.py`, `tests/test_rcvp.py`: deterministic relation/time/contrast operator, sparse timed roots, audit channels. Test temporal reversal/equal timestamps, family imbalance, background equality, roots, fanout, repeatability before integration.
- [x] Task 2: `progressive_pruning.py`, `pruning.py`, `tests/test_progressive_pruning.py`: reuse atomic/protected/path-cover inputs, lazy group removal and audit; test raw-event accounting, certificate guard and prefix overlap. Independent of propagation implementation.
- [x] Task 3: `optc_investigation.py`, web backend/frontend and web tests: presets, shared propagation adapter, progressive selection, audit display, config-aware API. Uses Task 1 contract described below; preserve old defaults.
- [x] Task 4: `config.py`, `diffusion.py`, `evaluation.py`, `cli.py`, `poi_prefix.py`, `score_ledger.py`: propagate explicit RCVP config and channel evidence through existing score fusion/ledger/hash contracts. Test CLI and ledger tampering and GT isolation.
- [x] Task 5: `scripts/run_rcvp.py`, presets, experiment report: frozen-input A–G and optional H/I at 5/10/20/30%, three completed admitted positive-retention scenarios (CADETS 06/12/13); THEIA excluded from this delivery by user request, runtime/RSS and audits. Labels only after masks freeze. Missing verified paths N/A.
- [x] Task 6: full tests, independent review, smoke, profiling, docs, scoped commit and push; verify remote commit.

Shared propagation interface: `tc_pruning.rcvp.propagate(src, dst, timestamp, relation_names, rarity, poi, process_nodes, config=None)` returns `(diffusion_array, diagnostics)` with `diagnostics['edge_fields']` mapping names to per-event arrays and `diagnostics['roots']` JSON-safe rows. Arrays use existing normalized causal directions, integer nanosecond timestamps, original-event positions; no GT inputs. `tc_pruning.rcvp_config.preset(name)` returns validated algorithm configuration. Names: `conservative`, `relation_aware`, `full`.

Verification commands: `PYTHONPATH=. python -m pytest -q`, targeted new tests, CLI `verify-score-ledger`, `node --check webapp/frontend/app.js`, experiment runner and frozen-output validator. Baseline before algorithm changes: 457 passed in 9.50s.

Final scope update: user requested immediate delivery of completed results and no further THEIA execution. Existing THEIA process is left running; publication does not wait for it.
