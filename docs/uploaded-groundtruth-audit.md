# Archive audit interpretation and reproduction

The uploaded archive SHA-256 is `a967a224c6f02a6045892137e11919eea5fb3bdc8fa2e711ce086fd39b6fa16a`. Its 12 CSVs contain 482 rows, representing 476 distinct (dataset, UUID) pairs. All 12 files are byte-identical to existing local DARPA labels. This is a re-evaluation of existing development labels, not independent held-out validation.

Five scenarios have matching local databases: CADETS E3 days 06, 12, 13 and THEIA E3 Cases 1, 3. All 194 scenario-label UUIDs match, including process, file, and network entities. Four scenarios have completed saved output under the selected three-POI protocol; later corrected THEIA Case 1 is incomplete. No matching CLEARSCOPE or E5 database appears in the inspected `output/tc` database inventory. The ZIP has no OPTC or TRACE labels.

See `uploaded-groundtruth-report.md` and `uploaded-groundtruth-evaluation.json` for the full table and exact inputs. Under the saved RASP-D 20% cap, retained CSV nodes are 8/8, 35/43, 14/24, and 61/61 for CADETS 06/12/13 and THEIA 3. Their CSV-core derived-event retention is 268/268, 4958/5000, 419/497, and 870/870. Candidate graphs contain all corresponding CSV nodes and all protocol-derived internal events, so the remaining losses occur in pruning. These are coverage/retention metrics, not classifier accuracy. Unlisted nodes are unlabeled, not verified benign nodes.

## CADETS 13 protocol difference

The saved comparison reports **420/498**, whereas re-deriving events from uploaded CSV endpoints within the original annotation window gives **419/497**. The reference used by the saved comparison adds the report-confirmed sshd C2 event `B5BA7AC4-2A51-5E4F-A287-895AA4BD30D2`, at 09:16:26.684642175 America/New_York, approximately 27 seconds after the original 09:16:00 boundary. Its destination UUID is not in the CSV. This is a documented report-augmented label, not an internal CSV-core event. Both counts are valid under their stated scopes; they must not be silently interchanged. `uploaded-groundtruth-verification.json` records the exact reference file, hash, event endpoints, timestamp, and the independently replayed report-augmented count. Other saved comparison counts match directly.

## THEIA Case 1 historical output

`uploaded-groundtruth-availability.json` records the later corrected run's `candidate_construction_truncated` status and `candidate_event_limit` at 250,000 candidates. It has no completed pruning result. The older one-POI causal run has exactly one candidate event and retains that event: **2/58 labeled nodes and 1/25,217 derived internal events**. This is recorded separately in `uploaded-groundtruth-theia1-historical.json`; it is not substituted for a completed corrected window-context run. Its nominal 20% cap retains one event because of minimum-one rounding, so its actual keep ratio is 100%.

## Reproduce

Run from any directory; the script uses only the Python standard library and opens SQLite with `mode=ro` and `query_only=ON`:

```bash
python /root/NODOZE-paper-fusion/webapp/scripts/evaluate_uploaded_groundtruth.py \
  --archive /root/ground-truth-012f321f46137650496e639b0ad7e0a66db07a73.zip \
  --config /root/NODOZE-pruning-release/webapp/runtime/research/groundtruth-study/archive/inputs.json \
  --output-dir /root/NODOZE-pruning-release/webapp/runtime/research/groundtruth-study/archive \
  --local-label-root /root/NODOZE-pruning-release/darpa

python -m pytest -q /root/NODOZE-paper-fusion/tests/test_uploaded_groundtruth.py
```

For historical THEIA Case 1, substitute `inputs-historical-theia1.json` and output directory `archive/historical`.

The 3 contract tests verify case-insensitive node identity, the full CSV denominator including unavailable nodes, false retention decisions, separation of all-time and window event sets, and N/A for absent predictions. Real replay verified all four candidate-ledger hashes against saved manifests and all four report-reference event counts against saved comparisons, with the CADETS 13 augmentation explicitly accounted for. Large databases are not fully hashed; their size/mtime and a digest of matched nodes/internal-event IDs are recorded. These observations are retrospective saved-output audits and do not benchmark the newer paper-fusion model or establish end-to-end detector accuracy.
