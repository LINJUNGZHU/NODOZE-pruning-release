# Paper-inspired multi-view investigation

The current learned detector mixes attributes and behavior and misses the eight publicly labeled attack processes. The rule detector recovers those processes but covers only 9/44 TAPAS-listed processes in the default window. This change tests complementary learned signals without changing either reference label set.

Implement an explicitly adapted multi-view detector, not a reproduction of PROVFUSION. Attribute novelty uses image/command trigram KNN. A masked relational process-graph encoder learns normalized action profiles and neighborhood context without text. A separate MLP predicts event relations from the actor's strictly earlier action history and current endpoint metadata; the target action is excluded from its input. Resource interactions contribute behavior features, but resources do not automatically become malicious nodes.

Use the existing 09:10–10:00 training interval, 10:00–10:10 validation interval, and 10:10–10:40 calibration interval. Train no classifier on malicious labels. Freeze seven fusion dimensions and majority voting before attack evaluation. Calibration is empirical, not an FPR guarantee. Constant calibration dimensions cannot cast votes. Export all raw scores, reference percentiles, thresholds and votes. Retain rules and the previous neural detector as separate baselines; only promote a new default if measurements justify it.

Borrow OCR-APT's evidence-first stage reconstruction as a deterministic local report: each stage has event references, observed facts, and explicit limits. Do not invent initial compromise, escalation, persistence or exfiltration from ordinary events. No external LLM is required or silently called. Slot's supervised similarity/Bandit optimization is deferred because current overlapping attack windows do not provide a sound independent labeled training split; bounded real temporal paths remain the evidence contract.

Evaluate four existing windows with both public and TAPAS labels, individual views, prior neural baseline and rules; include runtime and background false positives. The windows overlap and are development examples, not independent generalization tests. Tests must reject future leakage, target leakage, label dependence, tampered evidence and invalid model artifacts. Browser verification covers detector switching, readable view scores, stage evidence and report download.

Work autonomously under the standing user instruction; preserve unrelated dirty files. Commit and push the concrete reviewed implementation and measured limitations.
