# Marginal witness implementation and comparison

Spec: ../specs/2026-09-24-marginal-witness-design.md
Base: deb48b8. Execute inline; user authorizes autonomous implementation/experiments.

1. Write failing tests for union cost, mandatory budget, exact greedy agreement,
   MILP exhaustive optimum and explicit missing-incumbent handling. Implement
   `tc_pruning/marginal_witness.py` without modifying frozen v4 modules.
2. Add v5 config, runner reusing validated v4 decisions, and evaluation adapter
   that explicitly skips missing solver incumbents. Verify suite and freeze.
3. Run all five cases, both tracks, four budgets and POI removal scenarios;
   evaluate afterward. Inspect solver status, budget, routes and convergence.
4. Profile three new selectors in fresh processes; publish full JSON/CSV and
   concise primary/low-budget tables, plots and limits. Preserve failures.
5. Fresh independent whole-change review and required fixes, final tests,
   commit outputs. Leave research branch isolated; no merge or publication.

Shared interface: selectors return raw boolean masks and diagnostics; runner
stores selected IDs; evaluator alone opens the frozen reference. MILP failures
are records, not mandatory-only solutions disguised as optimized results.
