# Matched kernel supplement — frozen before reading v5 labels/results

Original v5 selector/config freeze: 1447a39. The main runs are in progress.
Add degree-normalized PPR and heat kernel (existing full sparse-matvec formula
adapters), each multiplied by the same 300-second POI time affinity. Both use
v5 lambda=1, same score-derived pool rule, same routes, mandatory sets, raw caps,
tracks and removal scenarios. Save augmented decisions separately from v5.
No parameter change, new labels, or case-specific rule. This supplement tests
whether frequency/lift scoring helps under matched downstream selection;
original top-K kernel baselines do not control for witness costs.

Not a reproduction of conductance sweeps, hk-relax, or a full published system.
Score-dependent pools are different; the common pool *rule* is matched.

Primary source for heat and degree normalization:
https://www.cs.purdue.edu/homes/dgleich/publications/Kloster%202014%20-%20hkrelax.pdf
