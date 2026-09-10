# PS-RDP Web Demo

This remote-friendly Flask application displays the pre-pruning and
post-pruning THEIA Case 3 graph with ground-truth-derived reference paths. The browser uses a
small representative subgraph; headline metrics always come from the complete
1,132,218-edge score ledger.

The current research method is [RASP](../docs/rasp-method.md). When its cache
is present, the UI defaults to RASP's fixed 20% budget preset, with 1%, 5%, 10%
and the original baseline also selectable. It updates scores, decisions, metrics
and graph labels together; the new scorer does not use DEPIMPACT. The three-day
CADETS table uses the same frozen configuration and implementation as THEIA,
checked by `publish_rasp_validation.py`. These are development-set results,
not held-out validation. Legacy T-MASS results are collapsed as history.

The reference paths contain 2, 4 and 1 events. Their preservation does not
establish complete attack reconstruction; a singleton is only a retained
event. The default view focuses on the four-event reference. The path context
is sampled by a deterministic event-ID hash, independently of score and
retention. Global metrics, complete one-hop context counts and displayed
sample counts are labeled separately. Both graphs share positions and edge
curves; the post-pruning view draws only retained endpoints. Parallel events
are grouped visually with count/score ranges, while every displayed raw
event has an individual searchable score-table row and full decision details.

Prepare the fast visualization cache once:

```bash
cd /root/NODOZE-pruning-release
PYTHONPATH=. python webapp/scripts/prepare_demo.py
PYTHONPATH=. python webapp/scripts/resolve_entities.py \
  --cache webapp/runtime/theia-case3-demo.json \
  --source-dir /root/TAPAS-artifact/data/theia/logs
```

Run label enrichment after regenerating the cache. It matches exact UUIDs to
original CDM entity declarations and records source file/line evidence; it never
changes experiment scores, retained decisions, or truth labels. Missing entity
declarations remain explicitly unresolved instead of inventing names.

The flat SVG comparison uses shared coordinates. Large context views aggregate
peripheral entities by type for readability; reference nodes remain individual.
The score table retains individual events, and clicking a grouped edge filters
its underlying events. Reference steps show readable entity names and Chinese
event descriptions. Raw UUIDs and entity-source evidence remain in details.

DEPIMPACT is not a separate result in the main score table. Its existing 0.05
auxiliary weight remains in the experiment algorithm, documented in expandable
event details. Components describe the winning POI, not additive contributions
to the final multi-POI score. Small nonzero scores use scientific notation.

The algorithm comparison panel can load T-MASS offline experiment results via
`scripts/run_adaptive_mass.py --cache ...` (see
[method and reproduction](../docs/t-mass-research.md)). Without a RASP cache the
baseline remains the default. Switching methods updates full-graph metrics,
individual edge decisions, path cards, local counts and both graph views using
exactly the same display sample. Negative results remain visible. Uploading
new data does not automatically execute this research experiment.

Run the service on the remote server:

```bash
cd /root/NODOZE-pruning-release
PYTHONPATH=. python webapp/backend/app.py
```

Forward it from a local computer:

```bash
ssh -N -L 8000:127.0.0.1:8000 root@SERVER_IP
```

Then open `http://127.0.0.1:8000`. Do not expose the Flask development server
directly to the public Internet; use Gunicorn and Nginx for a public deployment.
