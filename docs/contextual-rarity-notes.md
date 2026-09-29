# Contextual rarity: novelty is not maliciousness

`tc_pruning.contextual_rarity.ContextualRarityModel` separates three different
pieces of evidence:

- `novelty`: `1 / (1 + exact_count)`, describing whether the exact structural
  event/resource has appeared in the fitted history.
- `contextual_surprise`: normalized negative log probability of a semantic
  behavior pattern under a host/program baseline, with smoothing toward the
  same program's baseline across hosts.
- `confidence`: historical context support `N / (N + 20)`. Falling back to
  another host's peer-program baseline discounts this by 0.75.

`anomaly_score = contextual_surprise * confidence` is bounded ranking evidence.
It is **not a maliciousness probability**, an attack label, or a guarantee that
a rare event is suspicious. A new program with no historical context has zero
confidence and zero anomaly score, while its novelty can remain one. The graph
pipeline should retain its diffusion and path safeguards; a low anomaly score
alone must not certify that an edge is safe to remove.

## Baseline and smoothing

The program context selects a process endpoint, regardless of whether that
endpoint is stored as source or destination. The full directional behavior
pattern `(src_type, dst_type, src_semantic, dst_semantic, relation)` is never
reversed. When both endpoints are processes, source supplies the context.
Program basename supplies the peer family; the full executable path remains in
the pattern, so a binary in `/tmp` does not become equivalent to a system binary
with the same basename. Non-process events fall back to their source identity.

For a peer context containing `N` events and `K` observed patterns, its smoothed
pattern probability is `(pattern_count + alpha) / (N + alpha * (K + 1))`.
The extra bucket represents unseen patterns, and `alpha = 0.5` by default.
Where a host context exists, its probability is smoothed with five pseudo-events
from that peer distribution. The normalized surprisal divides `-log(p)` by the
same context's `-log(p_unseen)`, keeping the value in `[0, 1]` without fitting a
candidate-specific vocabulary or scale. A new host falls back to the peer
baseline; a wholly unseen program receives no contextual surprise claim.

`raw_rarity` remains available separately: half exact-event surprisal and half
an equally weighted combination of source-node-type, destination-node-type,
relation, and type-transition surprisal. Their historical counts are included
in every score for audit. Empty history has no raw frequency evidence and gives
raw rarity zero, while exact novelty still distinguishes an unobserved event.

## Conservative semantic normalization

- `/home/<name>/...` and `/Users/<name>/...` pool user-directory names.
- Under `/tmp`, `/var/tmp`, and `/dev/shm`, isolated long hexadecimal, numeric,
  or UUID tokens in a filename are pooled. The surrounding filename stem and
  extension remain. Other arbitrary filenames are not generalized.
- Process semantics, executable operations, and common executable suffixes
  bypass random-token pooling, preserving potentially suspicious binary names.
- IPv4/IPv6 addresses retain their identity. IPv6 notation is canonicalized.
  Ports 49152–65535 form an ephemeral-port bucket; lower service ports remain
  distinct. This conservative default does not infer a host's configured
  ephemeral-port range.

The model does not claim to recognize every legitimate resource variation;
this intentionally narrow normalization avoids erasing security-relevant names
or unrelated remote addresses.

## Temporal and data contracts

```python
model = ContextualRarityModel().fit(history_rows, cutoff_ns=poi_timestamp_ns)
evidence = model.score_rows(candidate_rows)
```

Fitting accepts only rows whose integer `timestamp_ns` is **strictly less** than
the cutoff. Ties and future events are excluded. The optional history `count`
must be a positive integer; fractional, boolean, negative, nonfinite and string
weights are rejected. Expanding a weighted row into repeated unit rows gives
identical scores. For database aggregates, **apply the temporal filter before
GROUP BY**. A representative/minimum timestamp on an already aggregated row
cannot prove the aggregate contains no events at or after the cutoff.

Scoring reads only structural fields; it never learns from candidate rows,
uses their `count`, reads labels/ground truth, or consumes precomputed scores.
Repeated scoring and input reordering do not change the baseline. Each result
includes support counts, context level, semantic pattern, cutoff and a reason
code, making new-resource matches distinguishable from unseen patterns.
