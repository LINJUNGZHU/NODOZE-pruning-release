# Reference subgraph completeness

The user asks to consider attack-chain completeness from subgraphs, and has authorized autonomous implementation. Extend the current research workflow with a separate offline evaluation and HTML view. Existing frozen selections and their v2 evaluation remain byte-for-byte unchanged.

Each source-resolved reference event is a vertex in an event DAG. A feasible transition requires matching causal endpoints, strictly increasing positive integer timestamps, and no conflicting explicit hosts. EXECUTE uses the existing causal reversal. Equal-time events do not connect; unknown-time events remain required singleton events and are disclosed. Unknown-host links are counted, not silently certified.

Fix weak components of this event DAG once per case. Multi-event components are reference dependency subgraphs; singleton events are reported separately. These disjoint units avoid counting many overlapping paths as independent attacks, but are not independently annotated attacks themselves. Unresolved reference events remain an explicit source-coverage deficit.

Evaluate exact all-member preservation, required-event coverage, feasible-transition retention, and fixed reference-root/reference-sink reachability. Roots and sinks are topological endpoints, not inferred intrusion/exfiltration stages. A surviving alternate route must not make a partially retained branch complete. Reachability uses the full feasible-transition DAG after deleting missing events; a frozen transitive reduction is unsuitable because reduction and vertex deletion do not commute. Optional fork/join neighborhoods may be defined on the fixed cover DAG and named separately.

Publish two separately fixed scopes: native excludes synthetic LINEAGE entries; augmented includes them. Their component denominators differ, so they are sensitivity views rather than comparable samples of the same attacks. No-reference and zero-denominator metrics are null. Independent complete-attack counts and semantic attack-stage completeness stay unavailable.

The evaluator validates all registered frozen variants before reference access, binds to the original v2 report/reference/source snapshot hashes, and compares all 2520 decisions without rescoring or retuning. Aggregate JSON/CSV/figures contain no event identities. Detailed reference subgraphs are local-only sidecars for the 15 existing representative exports, bound to each manifest and exact decision.

HTML adds the subgraph curve and local inspection beside current path metrics. Any aggregate entity diagram is explicitly only a display projection; temporal completeness comes from the offline event DAG. Missing members remain visible, and display filtering never changes the denominator.
