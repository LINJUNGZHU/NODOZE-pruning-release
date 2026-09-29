"""Historical resource novelty and contextual surprise, without attack labels.

The model is deliberately an evidence model, not a maliciousness probability.
Only ``fit`` changes its baseline, and only events strictly before ``cutoff_ns``
are admitted. Aggregated history must be grouped *after* applying that cutoff:
a row's timestamp cannot certify that an aggregate contains no future events.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
import ipaddress
import math
import re
from typing import Any


_PROCESS_TYPES = frozenset({"process", "proc", "subject", "subject_process"})
_EXECUTABLE_SUFFIXES = (".exe", ".dll", ".so", ".sh", ".py", ".pl", ".elf", ".bin")
_USER_DIRECTORY = re.compile(r"^(/(?:home|Users)/)[^/]+(?=/|$)")
_RANDOM_TOKEN = re.compile(
    r"(?<![A-Za-z0-9])(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{8,}|[0-9]{6,})(?![A-Za-z0-9])"
)
_FIELDS = ("src_type", "dst_type", "src_semantic", "dst_semantic", "relation", "host")
_Pattern = tuple[str, str, str, str, str]
_Context = tuple[str, str]


def _nonnegative_integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field} must be a nonnegative integer")
    return value


def _row_fields(row: Mapping[str, object]) -> tuple[str, ...]:
    values = []
    for key in _FIELDS:
        value = row.get(key, "")
        if value is None:
            value = ""
        if not isinstance(value, str):
            raise ValueError(f"{key} must be a string or null")
        values.append(value)
    return tuple(values)


def _socket_semantic(value: str) -> str:
    """Preserve IP identities and service ports; only pool ephemeral ports."""
    if value.startswith("[") and "]:" in value:
        host, port = value[1:].rsplit("]:", 1)
    elif value.count(":") == 1:
        host, port = value.rsplit(":", 1)
    else:
        return value
    if not port.isdigit() or not 0 <= int(port) <= 65535:
        return value
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return value
    canonical = f"[{address.compressed}]" if address.version == 6 else str(address)
    suffix = "<ephemeral>" if int(port) >= 49152 else str(int(port))
    return f"{canonical}:{suffix}"


def _semantic(node_type: str, value: str, relation: str) -> str:
    prefix, separator, payload = value.partition(":")
    recognized = prefix.lower() in {"file", "process", "proc", "socket", "netflow", "subject"}
    if not (separator and recognized):
        prefix, payload = node_type, value
    kind = node_type.lower()
    if kind in {"socket", "netflow", "network"}:
        return f"{prefix}:{_socket_semantic(payload)}"
    payload = payload.replace("\\", "/")
    payload = _USER_DIRECTORY.sub(r"\1<user>", payload)
    # Keep executable names intact, including randomly named binaries in /tmp.
    operation = relation.upper().removeprefix("EVENT_")
    executable = (
        kind in _PROCESS_TYPES
        or "EXEC" in operation
        or payload.lower().endswith(_EXECUTABLE_SUFFIXES)
    )
    if kind == "file" and not executable and payload.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
        parent, slash, filename = payload.rpartition("/")
        filename = _RANDOM_TOKEN.sub("<random>", filename)
        payload = parent + slash + filename
    return f"{prefix}:{payload}"


def _features(fields: tuple[str, ...]) -> tuple[_Pattern, _Pattern, _Context, str]:
    src_type, dst_type, src, dst, relation, host = fields
    exact = (src_type, dst_type, src, dst, relation)
    pattern = (src_type, dst_type, _semantic(src_type, src, relation), _semantic(dst_type, dst, relation), relation)
    if src_type.lower() in _PROCESS_TYPES:
        program = src
    elif dst_type.lower() in _PROCESS_TYPES:
        program = dst
    else:
        # Non-process events use the source identity; there is no invented
        # program baseline obtained from an unrelated common node type.
        return exact, pattern, (f"source:{src_type}", pattern[2]), host
    program = program.removeprefix("process:").removeprefix("proc:").removeprefix("subject:")
    # Program basename is the peer family; full paths stay in the pattern so
    # a /tmp/sshd masquerade is not made equivalent to /usr/sbin/sshd.
    family = program.replace("\\", "/").rsplit("/", 1)[-1]
    return exact, pattern, ("program", family), host


def _surprisal(probability: float, unseen_probability: float) -> float:
    if unseen_probability >= 1.0:
        return 0.0
    return min(1.0, max(0.0, -math.log(probability) / -math.log(unseen_probability)))


class ContextualRarityModel:
    """Smoothed program/host baselines with history-support shrinkage.

    Exact resource novelty remains separate from semantic behavior surprise.
    Host/program distributions are smoothed toward the same program's peers.
    A completely unseen program receives zero confidence, including when
    global node types are frequent. Candidate rows never extend the vocabulary.
    All output scores are bounded heuristic evidence, not attack probabilities.
    """

    def __init__(self, *, smoothing: float = 0.5, prior_strength: float = 5.0,
                 confidence_support: float = 20.0) -> None:
        for key, value in (("smoothing", smoothing), ("prior_strength", prior_strength),
                           ("confidence_support", confidence_support)):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                raise ValueError(f"{key} must be finite and positive")
        self.smoothing = float(smoothing)
        self.prior_strength = float(prior_strength)
        self.confidence_support = float(confidence_support)
        self.cutoff_ns: int | None = None
        self.history_count = 0
        self._exact: Counter[_Pattern] = Counter()
        self._src_types: Counter[str] = Counter()
        self._dst_types: Counter[str] = Counter()
        self._relations: Counter[str] = Counter()
        self._type_relations: Counter[tuple[str, str, str]] = Counter()
        self._peers: dict[_Context, Counter[_Pattern]] = {}
        self._hosts: dict[tuple[str, _Context], Counter[_Pattern]] = {}
        self._peer_totals: Counter[_Context] = Counter()
        self._host_totals: Counter[tuple[str, _Context]] = Counter()

    def fit(self, history_rows: Iterable[Mapping[str, object]], cutoff_ns: int) -> "ContextualRarityModel":
        """Replace the baseline from strict-past rows with positive integer counts.

        The default count is one. Invalid weights are rejected, never rounded;
        future rows are skipped before their other fields are inspected. Fitting
        is transactional, so an invalid historical row leaves an existing model
        intact. No field beyond the six structural fields, timestamp and count
        is read, including any ground-truth or precomputed score metadata.
        """
        cutoff = _nonnegative_integer(cutoff_ns, "cutoff_ns")
        exact: Counter[_Pattern] = Counter()
        src_types: Counter[str] = Counter()
        dst_types: Counter[str] = Counter()
        relations: Counter[str] = Counter()
        type_relations: Counter[tuple[str, str, str]] = Counter()
        peers: defaultdict[_Context, Counter[_Pattern]] = defaultdict(Counter)
        hosts: defaultdict[tuple[str, _Context], Counter[_Pattern]] = defaultdict(Counter)
        peer_totals: Counter[_Context] = Counter()
        host_totals: Counter[tuple[str, _Context]] = Counter()
        total = 0
        for row in history_rows:
            timestamp = _nonnegative_integer(row.get("timestamp_ns"), "timestamp_ns")
            if timestamp >= cutoff:
                continue
            count = row.get("count", 1)
            if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
                raise ValueError("count must be a positive integer")
            fields = _row_fields(row)
            raw, pattern, context, host = _features(fields)
            exact[raw] += count
            src_types[fields[0]] += count
            dst_types[fields[1]] += count
            relations[fields[4]] += count
            type_relations[(fields[0], fields[1], fields[4])] += count
            peers[context][pattern] += count
            hosts[(host, context)][pattern] += count
            peer_totals[context] += count
            host_totals[(host, context)] += count
            total += count
        self._exact, self._src_types, self._dst_types = exact, src_types, dst_types
        self._relations, self._type_relations = relations, type_relations
        self._peers, self._hosts = dict(peers), dict(hosts)
        self._peer_totals, self._host_totals = peer_totals, host_totals
        self.cutoff_ns, self.history_count = cutoff, total
        return self

    def _frequency_surprise(self, counts: Counter, key: object) -> float:
        denominator = self.history_count + self.smoothing * (len(counts) + 1)
        return _surprisal((counts[key] + self.smoothing) / denominator, self.smoothing / denominator)

    def score_rows(self, candidate_rows: Iterable[Mapping[str, object]]) -> list[dict[str, Any]]:
        """Score against frozen history, preserving input order and edge direction."""
        if self.cutoff_ns is None:
            raise ValueError("fit must be called before score_rows")
        results: list[dict[str, Any]] = []
        for row in candidate_rows:
            fields = _row_fields(row)
            raw, pattern, context, host = _features(fields)
            type_key = (fields[0], fields[1], fields[4])
            raw_rarity = 0.5 * self._frequency_surprise(self._exact, raw) + 0.125 * sum((
                self._frequency_surprise(self._src_types, fields[0]),
                self._frequency_surprise(self._dst_types, fields[1]),
                self._frequency_surprise(self._relations, fields[4]),
                self._frequency_surprise(self._type_relations, type_key),
            ))
            peer_count = self._peer_totals[context]
            host_count = self._host_totals[(host, context)]
            count = host_count or peer_count
            surprise = confidence = 0.0
            pattern_count = 0
            level = "unseen"
            if peer_count:
                peer_patterns = self._peers[context]
                denominator = peer_count + self.smoothing * (len(peer_patterns) + 1)
                probability = (peer_patterns[pattern] + self.smoothing) / denominator
                unseen_probability = self.smoothing / denominator
                pattern_count = peer_patterns[pattern]
                level = "peer_program"
                if host_count:
                    pattern_count = self._hosts[(host, context)][pattern]
                    probability = (pattern_count + self.prior_strength * probability) / (host_count + self.prior_strength)
                    unseen_probability = self.prior_strength * unseen_probability / (host_count + self.prior_strength)
                    level = "host_program"
                surprise = _surprisal(probability, unseen_probability)
                confidence = count / (count + self.confidence_support)
                if level == "peer_program":
                    confidence *= 0.75  # A new host has weaker contextual evidence.
            if not count:
                reason = "unseen_context_no_historical_support"
            elif not pattern_count:
                reason = "unseen_pattern_in_supported_context"
            elif not self._exact[raw]:
                reason = "new_resource_matches_historical_semantic_pattern"
            else:
                reason = "observed_pattern_scored_against_historical_context"
            results.append({
                "raw_rarity": raw_rarity,
                "novelty": 1.0 / (1 + self._exact[raw]),
                "contextual_surprise": surprise,
                "confidence": confidence,
                "anomaly_score": surprise * confidence,
                "context_count": count,
                "pattern_count": pattern_count,
                "context_level": level,
                "exact_count": self._exact[raw],
                "src_type_count": self._src_types[fields[0]],
                "dst_type_count": self._dst_types[fields[1]],
                "relation_count": self._relations[fields[4]],
                "type_relation_count": self._type_relations[type_key],
                "semantic_pattern": list(pattern),
                "reason": reason,
                "history_count": self.history_count,
                "history_cutoff_ns": self.cutoff_ns,
                "score_semantics": "historical_context_evidence_not_maliciousness_probability",
            })
        return results


__all__ = ["ContextualRarityModel"]
