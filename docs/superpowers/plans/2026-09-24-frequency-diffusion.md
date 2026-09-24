# Frequency diffusion implementation and experiment plan

Spec: ../specs/2026-09-24-frequency-diffusion-design.md
User authorized autonomous implementation and experiments. Existing isolated worktree is research/sparse-five-case-study. Do not ask for further approval.

1. Add behavioral tests for host isolation, EXEC direction, bounded episodes, duplicate-invariant frequency and diffusion, relation mass normalization, raw cap and connector admission.
2. Implement tc_pruning/frequency_diffusion.py and a frozen-ledger experiment runner. Reuse RASP temporal fork routes. Keep labels out of selection API. Save sparse selected event IDs and all configuration/source/input hashes.
3. Freeze config, run all five cases and predefined ablations. All decisions saved before separate reference evaluation. Compare same raw caps and existing results; retain negative results.
4. Run whole test suite, obtain final code review, resolve correctness findings, and write Chinese study with exact metrics, limitations and research next steps.

Preflight: selection input is numeric arrays + semantic categories, evaluation consumes frozen event IDs. Cost is raw events, displayed compression also includes episodes. Reference/POI immutability verified by hashes. No hidden parameter fitting after label evaluation; exploratory revisions must get a new named run.

## Execution record

- Implemented and froze three revisions: e1829c2 (v1), 1cb0945 (v2), a42c835 (v3).
- 622 method/budget/case decisions generated over three rounds, including 268 in final v3; all negative results retained.
- Independent review found semantic incidence orientation splitting and legacy helper cross-host matching. Both reproduced by failing tests, fixed, and rerun. Final reviewer reported no important findings.
- Full suite: 592 passed. Final selection audit verifies all candidate/implementation hashes, selected IDs, POI retention and raw caps on all 268 decisions.
- Findings and publication limitations in docs/frequency-diffusion-study.md. No evidence of overall SPARSE superiority; existing production default retained. THEIA1 remains the main unresolved research failure. Occupancy weighting rejected as final recommendation.
