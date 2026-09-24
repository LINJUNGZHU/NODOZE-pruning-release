# Marginal witness experiment (frozen before evaluation)

## Objective and scope
Preserve frequency statistics and diffusion as the scoring engine. Replace the
fixed half-global/half-type quota by marginal evidence utility per additional raw
event in a temporal witness. Compare with the existing v4 outputs and a new
independently formulated binary optimization baseline. These five cases remain
development data; this round is not a held-out test or a SPARSE reproduction.

## Frozen protocol
- Same five ledgers, report-grounded POIs, reference, scenarios, two tracks,
  budgets 64/256/1024/4096 and primary budget 1024 as v4. Budget 256 is an
  explicitly secondary low-budget regression check. Removed-POI runs use 1024.
- Main score: v4 frequency diffusion times 300-second temporal affinity.
- For each budget B, candidate anchors are the union of the top max(4096, 2B)
  reachable positive-score events globally and the top ceil(max(4096,2B)/R)
  per observed relation. R counts relations among eligible events. Order is
  score descending, then existing event tie ID. No reference labels are read.
- Each anchor expands to the existing fixed backward/fork witness; union cost
  counts each raw event once. Mandatory events count toward B. No free closure.
- Normalize raw values by the maximum over reachable positive-score events.
  Utility F(S) = sum(value[e], e in S) + lambda * sum_r sqrt(sum(value[e],
  e in S of relation r)). Main lambda=1; linear control=0; sensitivity=4.
  Recompute exact marginal gain / newly introduced raw-event count each step.
  No lazy upper-bound assumption for decreasing union costs. Ties use anchor ID.
- Static-score ablation uses the same selection rule and lambda=1, constructing
  its pool from static scores. A no-frequency ablation sets frequency=False
  in the existing diffusion scorer, retaining temporal rerank and lambda=1.
  Both are ablations, not identical-pool optimizer comparisons.
- MILP baseline at all-POI budgets 256 and 1024 on both tracks uses the identical
  rerank pool and lambda=0 objective. Binary anchor y and raw event x enforce
  y_j <= x_e for every witness member and x_e <= sum(y_j containing e) for each
  nonmandatory e. Mandatory x=1; sum(x)<=B. SciPy 1.14.1 HiGHS, 20-second solver
  limit, relative gap .01, presolve enabled. Record solver status, gap, bound,
  and wall time; validate incumbent integrality, closure and cap independently.
  With no valid incumbent, report no_incumbent and no performance metrics.
  Never claim exactness unless supported by solver bounds/tolerance.
- Previous decisions/times are reused with source/input hashes. New times
  distinguish scoring, routes, pool build and selection/solver. Fresh process
  profiling for the main method and linear/MILP controls at budget 1024.
- Evaluate only after a code/config freeze commit. Preserve unsuccessful runs.
  Official-equivalent metrics stay NA; report all local proxy metrics explicitly.

## Sources and differences
Khuller, Moss, Naor (1999), budgeted maximum coverage:
https://thibaut.horel.org/submodularity/papers/khuller1999.pdf
Their sum of set costs differs from our union of raw witness events; no imported
approximation guarantee is claimed. Our MILP is a new task formulation, not their
algorithm or a paper-system reproduction.

D'Angelo and Delfaraz, AAMAS 2025, connected maximum coverage:
https://www.ifaamas.org/Proceedings/aamas2025/pdfs/p538.pdf
Supports studying connectivity and budget jointly; their bicriteria algorithms
and theoretical guarantees are not implemented or attributed to our selector.

SciPy 1.14.1 solver API:
https://docs.scipy.org/doc/scipy-1.14.1/reference/generated/scipy.optimize.milp.html

## Acceptance
Tests against slow greedy and exhaustive tiny optimization, all five case runs,
honest complete tables including regressions, raw caps and route audits, and an
independent final review. No required positive performance outcome.
