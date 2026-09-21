# TRACE E3 KAIROS-POI Experiment Design

## Goal

Train KAIROS on TRACE E3, turn its native anomalous queues into immutable POIs, and compare A_rasp, A_rasp-PBR, and C_branch_fair only on attack nodes and strict-time attack paths that are relevant to detected POIs.

## Data and isolation boundary

- Detector input is the already parsed local TRACE E3 SQLite store. A bounded-memory importer projects only PIDSMaker/KAIROS's process, file, socket and ten relation types into PostgreSQL. It preserves UUIDs, timestamps, and the PIDSMaker-compatible normalized edge direction.
- The remote PostgreSQL dump is not downloaded. The local import is fingerprinted and reused only after a `COMPLETED` metadata record; partial imports are rebuilt.
- The available local corpus covers only 2018-04-13 09:56–17:09, not the official multi-day detector-training split. It is therefore reported as `local-single-day-chronological-25-10-65`: graph windows are sorted chronologically, the first 25% are training, the next 10% validation, and the remaining 65% test. This partition is fixed without consulting ORTHRUS. No result from it may be described as an official-split KAIROS result.
- KAIROS runs through construction, transformation, featurization, feature inference, batching, and training. It does not run PIDSMaker's label-aware evaluation stage.
- The final generated epoch is selected without incident labels. Native anomalous edges use the KAIROS window rule `loss > mean + 1.5 * population_std`; queues use the KAIROS IDF linkage and fixed queue threshold 20.
- Selected-queue anomalous endpoints are mapped from PIDSMaker integer node IDs to TRACE UUIDs through the PostgreSQL node tables. The anomalous `(source index, destination index, timestamp)` tuples are independently mapped to raw event UUIDs. Both node POIs and exact event anchors, together with native KAIROS window bounds, are sealed before evaluation.
- Alerts, queues, POIs, candidate envelopes, and selector decisions are hashed and sealed before any ORTHRUS CSV is opened.
- After sealing, the three official TRACE E3 ORTHRUS CSVs are loaded only for evaluation.

## Online experiment

Each available test day is an independent query. Detector POIs from that day seed one shared candidate envelope. Node-valued POIs receive one incident causal witness fairly before deep expansion, so a lexicographically early high-fanout branch cannot consume the entire cap. All three methods operate on exactly that envelope and share the same mandatory incident proxy events, projection, and maximum budget.

The methods are:

- `A_rasp`: unchanged baseline selector.
- `A_rasp-PBR`: a 10,000-event A_rasp base plus at most 2,000 detector-event-local strict-temporal bridge events; it never reads ORTHRUS online.
- `C_branch_fair`: branch-fair trajectory sampled at fixed projected-edge targets.

The online artifacts include detector counts, mapping coverage, candidate size/time/RSS, method selection size/time, decisions, and content hashes.

## Offline evaluation

For each ORTHRUS attack scenario, evaluation POIs are `KAIROS POIs ∩ ORTHRUS positive nodes`. Detector false-positive POIs remain part of online query cost but are not invented as attack nodes. If the intersection is empty, the scenario is reported as `NO_ATTACK_POI_HIT` and no path-reconstruction score is claimed.

For a hit scenario, reference paths are deterministic, strictly time-increasing paths in the frozen shared candidate envelope. Only reference paths with a KAIROS-hit POI as source or target are eligible. Results include attack-node retention and Backward Path, Forward Path, POI-to-POI Path, Anomaly Path, Time, Path Length, and Time × Path Length breakdowns.

## Operational behavior

One background pipeline imports/reuses the local TRACE store, trains KAIROS, freezes native POIs, runs pruning, and performs offline evaluation. Atomic `process-status.json`, `postgres-import-status.json`, and `progress.json` files expose the current stage; logs are append-only. Failed stages write a terminal failure record instead of appearing to continue running.
