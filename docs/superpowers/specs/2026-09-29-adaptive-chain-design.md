# Adaptive rarity, diffusion and complete-chain pruning

User request: retain dependency candidates, diagnose phased loss, improve behavioral rarity, preserve complete causal chains, report compression versus whole-chain retention and display on existing HTML. Implement autonomously; push only after measured improvement.

## Design
Preserve current candidate builder and baseline. Add a contextual history model with hierarchical semantic pattern smoothing and support shrinkage. Distinguish novelty, contextual surprise, confidence and investigation relevance; strictly earlier history, no ground truth in fitting/scoring/selection.

Generate bounded, strictly temporal directed root-to-terminal witnesses from observed candidate events. Rank anchored witness bundles using contextual rarity and seeded graph diffusion; keep connecting events atomically under the raw-event budget. High-frequency bridges can survive. Report truncated witnesses and unknown observation boundaries; observable maximal witnesses never claim complete real attacks.

Evaluate frozen decisions after scoring. Independent chain contracts define required event paths, branches and scope/review provenance. Validate direction, timestamps and every required event. Count the whole contract once; stage losses use first-failure attribution with nested sets. Missing source evidence is distinguished from candidate, relevance and budget loss. No chain labels means NA, never 100 percent. Existing CAPTAIN positive labels remain positive-event diagnostics only. Derived reference paths and synthetic full truth are separately named panels.

Export reproducible multi-budget ablations: RASP baseline, contextual-score-only, whole-chain-only, combined. Compare actual raw-event compression; include counts, conditional and end-to-end retention, failure locations, elapsed runtime and input hashes. Do not optimize parameters against current reference labels.

HTML dashboard links from research page, displays the requested curve, strict chain counts, loss funnel, ordered per-chain events/branches and removal reasons, plus provenance and explicit NA for missing independent complete-chain truth. Keep existing APIs compatible.

## Validation
Baseline 555 tests pass. New behavioral tests cover cold history/semantic variation, future isolation, broken bridges, branch loss, missing source, equal timestamps, budget insufficiency and label-independent selection. Replay current CADETS 06/12/13 (THEIA excluded by existing project scope) and a fully labeled synthetic multi-stage benchmark. New defaults require evidence; otherwise expose experiment separately.

## Workspace
Work on feature branch; preserve all prior dirty changes with /tmp/nodoze-adaptive-baseline. Only stage task-owned new files and isolated edits; no credentials, raw data, environments or unrelated work uploaded.
