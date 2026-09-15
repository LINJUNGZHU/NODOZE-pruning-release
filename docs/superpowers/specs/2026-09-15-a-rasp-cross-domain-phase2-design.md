# A_rasp Cross-Domain Phase 2 Design

## Goal and frozen baseline

Build an opt-in CADETS E3 research branch on top of A_rasp-R without changing the default algorithm. Phase 1 is frozen by the existing online/offline artifacts: V0 has 41/68 observable candidate GT nodes and 37/68 final GT nodes; V4 has 44/68 candidate and 37/68 final. All Phase 2 variants use the same per-query raw-event budget `floor(r * |C_V0(q)|)` for `r in {0.05, 0.10, 0.20, 0.30}`.

ORTHRUS node labels and the DARPA PDF manifest are evaluator-only inputs. Online construction, propagation, reconstruction, demand generation, and selection must be byte-identical when GT is changed or omitted.

## Failure decomposition

Candidate and selector misses are independent. At V4, 24 observable GT nodes are absent from candidates and seven candidate GT nodes are removed by selection. Scenario 06 is selector-limited (6 candidate, 4 final), Scenario 12 is reconstruction-limited (28/39 at both stages), and Scenario 13 has both problems (10/23 candidate, 5/23 final). Increasing fixed depth, cap, or session timeout is excluded because the measured curves saturate.

`CandidateMissAnalyzer` runs only after online output is frozen. It searches the complete provenance database using the central relation registry and strict temporal verifier, emits minimum witness paths and multi-label failure taxonomy, and has no imports from online modules.

## Three graph views

- `G_full` contains every admitted raw event and is the only source for audit, certificates, motifs, path witnesses, ledgers, and offline evaluation.
- `G_prop` references edges in `G_full` but assigns relation-specific, pre-alert-only temporal/frequency/fanout transition weights. Optional progressive cleaning only reduces weights.
- `G_output` is the selected raw-event subset. It must be a subset of `G_full` and its cost is the count of unique original event IDs.

## Reconstruction pipeline

`TemporalReverseReachability` traverses legal predecessors in strict reverse temporal order. It supports deterministic exhaustive coverage and reproducible weighted sketches. Root scores combine sketch support, relation diversity, path diversity, and anchor support; stochastic instability causes a declared deterministic fallback.

`ForwardCausalSphereBuilder` expands legal successors from root candidates using an indexed frontier. It stops after configured consecutive low `verified_gain / new_raw_event_cost`, an empty valuable frontier, or a resource cap. Forward verification is label-free and uses anchor reachability, normalized A_rasp relevance, rare executable/network behavior, meaningful transfer motifs, verified branches, and coherent descendants. Backward and forward support combine by harmonic mean.

`TemporalCausalMotifBuilder` emits replayable raw witnesses for control-spawn, file-transfer, drop-execute, network-consequence, receive-to-execution, verified common-cause branch, and cross-anchor bridge. Motif cost is its unique raw-event count; rarity only modulates evidence that already has causal support.

## Structural preservation and selection

Online demand pairs are constructed only from verified roots, anchors, meeting points, and terminals. `TemporalReachabilityPreserver` finds minimum non-negative-cost strict temporal paths, unions them, then removes redundant edges only after checking every declared demand remains reachable. The resulting skeleton is mandatory. If its unique-event cost exceeds the budget, the result is explicitly infeasible and no witness is silently removed.

Residual evidence is represented by `EvidenceUnit` (single edge, motif, or small certified bundle). The branch-fair selector maximizes normalized relevance, concave branch/anchor/motif coverage, and verification minus redundancy under the remaining raw-event budget. Lazy greedy uses marginal utility per newly introduced raw event, deterministic tie-breaking, and stale-key recomputation.

## Experiments and gate

Run in order: A miss taxonomy; B ECDF-only selector; C branch-fair selector on frozen V4 candidates; D reverse reachability with legacy selector; E forward sphere; F motifs only when taxonomy supports them; G temporal preserver; H justified full composition. Report aggregate and scenario-specific candidate/final recall, PDF/path/reachability metrics, decomposition counters, timings, peak RSS, feasibility, and 5/10/20/30% sweeps.

The experimental method remains opt-in unless it improves both candidate and final recall, preserves strict evidence, avoids severe low-budget regression and benign-like explosion, benefits multiple scenarios, and passes GT-isolation tests. Modules with no independent value remain optional or are rejected as negative results.
