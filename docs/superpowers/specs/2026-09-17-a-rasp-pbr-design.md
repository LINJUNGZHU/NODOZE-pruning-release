# A_rasp-PBR Design

## Scope and frozen baseline

A_rasp-PBR is a label-free post-selector that starts from the unchanged
A_rasp output and adds only a small number of strict-temporal bridge bundles.
It does not change the detector, POI derivation, common candidate builder,
A_rasp, C_branch_fair, ORTHRUS evaluator, or projection contract.

Frozen baseline SHA-256 values:

- evaluation: `2659c07dbc4df064c846803043244ccb542b1da627690ea938dad2f692f8fd77`
- config: `a9b2e642c2b9c2df25c75227841b522c9e13aee5a5373ce49c4ae61f06088dd2`
- legacy selector source: `3ce99e3c619ae058092333ee268649c63cf25abe5058f50a58f25da94ae213b5`
- baseline focused tests: 42 passed.

## Online architecture

The online PBR input is only the frozen common candidate, POI node set,
mandatory proxies, A_rasp output and label-free candidate metadata. ORTHRUS,
PDF reference paths and audit results are forbidden inputs.

1. Normalize candidate events with the existing CADETS causal orientation.
2. Enumerate ordered POI pairs for which a strict increasing-time candidate
   path exists but the A_rasp output has no such path.
3. Apply a label-free gate. A pair is admitted when it shares a KAIROS proxy
   group, branch/control/common-ancestor provenance, shared resource support,
   or has a bounded short/low-cost candidate path. Gate reasons are audited.
4. Search at most K loop-free strict-temporal paths. Equal timestamps,
   reverse causal edges and witness-free abstract links are invalid.
5. Score edges with normalized non-negative costs based on normality, fanout,
   relation penalty, A_rasp relevance, rarity and pair-conditioned
   compatibility. No learned model and no GT feature is allowed.
6. Convert paths to BridgeBundle objects. Raw cost is the number of unique raw
   event IDs and projected cost uses the frozen EdgeProjection.
7. Compute local counterfactual causal essentiality only for path/bundle edges:
   disconnect gives 1; otherwise `clip((C_without-C*)/(C_without+eps),0,1)`.
8. Select bundles lexicographically: maximize newly satisfied gated demands,
   then essentiality/compatibility, then minimize projected/raw cost and
   redundancy. The total unique added raw events must stay within
   `min(fixed_extra_raw, floor(ratio*A_raw))`.
9. Cleanup only newly added events. An event is removable only when every
   demand rescued by PBR remains strictly reachable and mandatory evidence is
   unchanged.

## Explainable compatibility

`PairConditionedCompatibility` is a deterministic [0,1] score composed of
relation compatibility, process lineage, shared resource semantics, temporal
position, branch support, historical pair interaction and A_rasp relevance.
Components and the final value are emitted per bundle; it is never a global
PPR substitute.

## Evaluation and Pareto protocol

The sweep evaluates A_rasp, A_rasp-PBR allowances 0%, 5%, 10%, 25%, 50%,
100%, and C_branch_fair checkpoints near 100, 250, 500, 1k, 2k, 4k and 8k
projected edges. Actual projected counts are always reported. Metrics include
reference-edge retention, strict path retention, POI-to-POI reachability,
raw/projected graph size, existing POI-local metrics, and non-POI node recall.
The existing 39 one/two-edge paths are described as POI-local connectivity,
not long attack-chain preservation.

## Offline scenario 13 audit

The audit runs after selections are frozen and may use ORTHRUS. It reports C
reference events/paths missing from A, event identity and time, A rarity,
relevance/PPR/lift/path score, C relevance/provenance, POI-to-POI membership,
counterfactual lost demands, alternative count and minimum alternative cost.
The audit module is not imported by PBR and no audit field enters its hash.

## Reproducibility and runtime

Every decision artifact includes config, candidate, baseline and decision
hashes plus counts for demands, gated demands, shortest-path calls,
counterfactual recomputes, bundles, selected bundles, added raw/projected
events, rescued demands, PBR seconds and peak RSS. The production launcher
creates a unique RUN_ID directory with log, PID, process-status, progress and
input hashes. It stops reporting after confirming the process has entered the
first baseline/candidate/scenario stage.

## Required invariants

- Changing GT cannot change demands, bundles, selected events or decision hash.
- PBR disabled reproduces legacy A_rasp exactly.
- Existing reachable pairs add nothing.
- Strict time means every next timestamp is greater, never equal.
- Costs and budgets charge unique raw events.
- PBR never deletes legacy A_rasp or mandatory evidence.
- PBR works only on gated disconnected demands and K paths, never globally
  reselects or sorts the full candidate.
