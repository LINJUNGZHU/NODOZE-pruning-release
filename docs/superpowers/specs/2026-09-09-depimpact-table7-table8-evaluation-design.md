# DEPIMPACT Table 7/8 Evaluation Design

## Goal

Add an auditable evaluation protocol matching the metrics used by Tables 7 and
8 of *Back-Propagating System Dependency Impact for Attack Investigation*.
The existing pruning and path-retention results remain available, but no
POI-derived path count is presented as a count of independent attacks.

## Table 7: runtime decomposition

Every DEPIMPACT analysis records wall-clock seconds for edge merge, dependency
feature/weight computation, backward impact propagation, and total time. The
experiment also reports causal candidate construction and NoDoze frequency
model/scoring time. A fixed projection `(0.334, 0.333, 0.333)` runs on the same
candidate graph and POIs for a direct comparison.

## Table 8: average attack-entry rank

Candidate entry nodes follow Section 4.3.2 of the paper: non-library files
without incoming edges, processes with no parents or only system-library
parents, and network-flow nodes. The last rule is an explicit CADETS adapter:
CADETS reuses a network UUID in both directions, so a later send can create an
apparent incoming edge for an earlier external receive. They are ranked
separately inside network, file, and process categories.

Evaluation-only attack entries are manually annotated UBC attack nodes that
satisfy the same online entry predicate. Online algorithms never receive the
attack-node set. Labels are intersected only after scores are frozen.

Five methods are reported: temporal only, temporal plus data size, fixed
projection `(0.334, 0.333, 0.333)`, deterministic uniform random, and learned
DEPIMPACT. Ranks descend by impact and use midranks for ties. Uniform random
uses a stable SHA-256-derived value and a declared seed. Reports include truth
coverage, candidate counts by category, per-entry ranks, average rank, and MRR.
Unavailable categories remain explicit rather than becoming rank zero.

Multiple POI node-impact maps are combined with noisy-OR, giving monotone
prefix semantics without overwriting earlier evidence.

## Audit and leakage controls

- Ground truth is used only in the offline rank evaluator.
- Candidate construction, normalization, projection and propagation do not use
  truth labels.
- Reports declare entry definitions, category mapping, ties, random seed and
  projections and persist all candidate-entry scores/ranks.
- Prefix summaries produce paper-style Table 7 and Table 8 CSV/Markdown files.
