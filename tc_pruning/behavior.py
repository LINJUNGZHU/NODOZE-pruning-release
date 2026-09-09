from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import hashlib
import ipaddress
import math
import re
from typing import Iterable

from .models import Neighborhood, StoredEdge


_TOKEN_RE = re.compile(r"[A-Za-z0-9_.-]+")
_RELATED_OPERATIONS = frozenset(
    {
        ("READ", "WRITE"),
        ("WRITE", "EXECUTE"),
        ("WRITE", "EXEC"),
        ("WRITE", "DELETE"),
        ("WRITE", "UNLINK"),
        ("CREATE", "WRITE"),
        ("RECV", "WRITE"),
        ("READ", "SEND"),
    }
)


def _tokens(value: str) -> tuple[str, ...]:
    return tuple(token.lower() for token in _TOKEN_RE.findall(value or ""))


def _unit(vector: Iterable[float]) -> tuple[float, ...]:
    values = tuple(float(value) for value in vector)
    norm = math.sqrt(sum(value * value for value in values))
    if norm <= 0.0:
        return values
    return tuple(value / norm for value in values)


class OOVEmbeddingCache:
    """Small deterministic cache with token composition for unseen entities.

    A complete label seen during ``fit`` reuses its cached vector. An unseen
    label is composed only from tokens present in the fitted vocabulary;
    tokens outside that vocabulary contribute the zero vector.
    """

    def __init__(self, *, dimensions: int = 32, minimum_token_frequency: int = 1):
        if dimensions <= 0:
            raise ValueError("dimensions must be positive")
        if minimum_token_frequency <= 0:
            raise ValueError("minimum_token_frequency must be positive")
        self.dimensions = dimensions
        self.minimum_token_frequency = minimum_token_frequency
        self.vocabulary: set[str] = set()
        self._label_vectors: dict[str, tuple[float, ...]] = {}
        self._token_vectors: dict[str, tuple[float, ...]] = {}

    def _token_vector(self, token: str) -> tuple[float, ...]:
        cached = self._token_vectors.get(token)
        if cached is not None:
            return cached
        vector = [0.0] * self.dimensions
        padded = f"^{token}$"
        grams = {padded[index : index + 3] for index in range(max(1, len(padded) - 2))}
        for gram in grams:
            digest = hashlib.blake2b(gram.encode("utf-8"), digest_size=8).digest()
            bucket = int.from_bytes(digest[:4], "big") % self.dimensions
            vector[bucket] += 1.0 if digest[4] & 1 else -1.0
        result = _unit(vector)
        self._token_vectors[token] = result
        return result

    def fit(self, labels: Iterable[str]) -> "OOVEmbeddingCache":
        materialized = [str(label) for label in labels]
        counts = Counter(token for label in materialized for token in _tokens(label))
        self.vocabulary = {
            token
            for token, count in counts.items()
            if count >= self.minimum_token_frequency
        }
        self._label_vectors.clear()
        for label in materialized:
            self._label_vectors.setdefault(label, self._compose(label))
        return self

    def _compose(self, label: str) -> tuple[float, ...]:
        known = [self._token_vector(token) for token in _tokens(label) if token in self.vocabulary]
        if not known:
            return (0.0,) * self.dimensions
        return _unit(
            sum(vector[index] for vector in known) / len(known)
            for index in range(self.dimensions)
        )

    def embed(self, label: str) -> tuple[float, ...]:
        cached = self._label_vectors.get(label)
        return cached if cached is not None else self._compose(label)


def _strip_socket_label(label: str) -> str:
    value = (label or "").removeprefix("socket:")
    if value.startswith("[") and "]" in value:
        return value[1 : value.index("]")]
    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        if port.isdigit():
            return host
    return value


def _ip_prefix_similarity(left: str, right: str) -> float:
    try:
        first = ipaddress.ip_address(_strip_socket_label(left))
        second = ipaddress.ip_address(_strip_socket_label(right))
    except ValueError:
        return 0.0
    if first.version != second.version:
        return 0.0
    xor = int(first) ^ int(second)
    common = first.max_prefixlen if xor == 0 else first.max_prefixlen - xor.bit_length()
    return common / first.max_prefixlen


def _path_prefix_similarity(left: str, right: str) -> float:
    def parts(value: str) -> tuple[str, ...]:
        return tuple(part.lower() for part in re.split(r"[/\\]+", value) if part)

    first, second = parts(left), parts(right)
    if not first or not second:
        return 0.0
    common = 0
    for lhs, rhs in zip(first, second):
        if lhs != rhs:
            break
        common += 1
    denominator = max(len(first), len(second))
    if common and common < denominator:
        denominator = max(1, denominator - 1)
    return min(1.0, common / denominator)


def entity_similarity(
    node_type: str,
    left: str,
    right: str,
    embeddings: OOVEmbeddingCache,
) -> float:
    if node_type == "file":
        return _path_prefix_similarity(left, right)
    if node_type == "socket":
        return _ip_prefix_similarity(left, right)
    first, second = embeddings.embed(left), embeddings.embed(right)
    return max(0.0, min(1.0, sum(a * b for a, b in zip(first, second))))


def _operation_name(relation: str) -> str:
    return (relation or "").upper().removeprefix("EVENT_").replace("FROM", "")


def operation_transition_similarity(left: str, right: str) -> float:
    first, second = _operation_name(left), _operation_name(right)
    if (first, second) in _RELATED_OPERATIONS:
        return 1.0
    if first == second and first:
        return 0.5
    return 0.0


@dataclass(slots=True)
class BehaviorAnalysis:
    edge_importance: dict[int, float]
    edge_clusters: dict[int, int]
    cluster_count: int
    backend: str


def _fallback_labels(edges: list[StoredEdge], gap_seconds: float) -> list[int]:
    labels: list[int] = []
    cluster = 0
    previous_time: int | None = None
    for edge in edges:
        if previous_time is not None:
            gap = max(0.0, (edge.timestamp_ns - previous_time) / 1_000_000_000)
            if gap > gap_seconds:
                cluster += 1
        labels.append(cluster)
        previous_time = edge.timestamp_ns
    return labels


def _hdbscan_labels(features: list[list[float]], min_cluster_size: int) -> list[int] | None:
    if len(features) < max(2, min_cluster_size):
        return None
    try:
        import hdbscan  # type: ignore
    except ImportError:
        return None
    labels = hdbscan.HDBSCAN(
        min_cluster_size=min_cluster_size,
        min_samples=1,
        allow_single_cluster=True,
    ).fit_predict(features)
    if all(int(label) < 0 for label in labels):
        return None
    return [int(label) for label in labels]


def analyze_behaviors(
    graph: Neighborhood,
    *,
    poi_edge_ids: set[int],
    min_cluster_size: int = 3,
    fallback_gap_seconds: float = 30.0,
    embedding_dimensions: int = 32,
    minimum_token_frequency: int = 1,
) -> BehaviorAnalysis:
    if min_cluster_size < 2:
        raise ValueError("min_cluster_size must be at least 2")
    if fallback_gap_seconds <= 0.0:
        raise ValueError("fallback_gap_seconds must be positive")
    embeddings = OOVEmbeddingCache(
        dimensions=embedding_dimensions,
        minimum_token_frequency=minimum_token_frequency,
    ).fit(node.label for node in graph.nodes.values())
    process_edges: dict[str, list[StoredEdge]] = defaultdict(list)
    for edge in graph.edges:
        if graph.nodes.get(edge.src) and graph.nodes[edge.src].node_type == "process":
            process_edges[edge.src].append(edge)
        if graph.nodes.get(edge.dst) and graph.nodes[edge.dst].node_type == "process":
            process_edges[edge.dst].append(edge)

    edge_memberships: dict[int, set[int]] = defaultdict(set)
    poi_clusters: set[int] = set()
    next_cluster = 0
    used_hdbscan = False
    for process_id, edges in sorted(process_edges.items()):
        ordered = sorted(edges, key=lambda edge: (edge.timestamp_ns, edge.edge_id))
        features: list[list[float]] = []
        previous: StoredEdge | None = None
        first_time = ordered[0].timestamp_ns if ordered else 0
        for edge in ordered:
            other_id = edge.dst if edge.src == process_id else edge.src
            other = graph.nodes.get(other_id)
            previous_other = None
            if previous is not None:
                previous_id = previous.dst if previous.src == process_id else previous.src
                previous_other = graph.nodes.get(previous_id)
            interval = max(0, edge.timestamp_ns - first_time) / (
                1_000_000_000 * fallback_gap_seconds
            )
            similarity = (
                1.0
                if previous_other is None or other is None
                else entity_similarity(
                    other.node_type,
                    previous_other.label,
                    other.label,
                    embeddings,
                )
            )
            operation = (
                1.0
                if previous is None
                else operation_transition_similarity(previous.relation, edge.relation)
            )
            features.append([interval, 1.0 - similarity, 1.0 - operation])
            previous = edge

        local_labels = _hdbscan_labels(features, min_cluster_size)
        if local_labels is None:
            local_labels = _fallback_labels(ordered, fallback_gap_seconds)
        else:
            used_hdbscan = True
        local_to_global: dict[int, int] = {}
        for edge, local in zip(ordered, local_labels):
            if local < 0:
                global_label = next_cluster
                next_cluster += 1
            else:
                if local not in local_to_global:
                    local_to_global[local] = next_cluster
                    next_cluster += 1
                global_label = local_to_global[local]
            edge_memberships[edge.edge_id].add(global_label)
            if edge.edge_id in poi_edge_ids:
                poi_clusters.add(global_label)

    importance = {
        edge.edge_id: (
            1.0
            if edge.edge_id in poi_edge_ids
            or bool(edge_memberships.get(edge.edge_id, set()) & poi_clusters)
            else 0.0
        )
        for edge in graph.edges
    }
    clusters = {
        edge_id: min(labels) for edge_id, labels in edge_memberships.items() if labels
    }
    return BehaviorAnalysis(
        edge_importance=importance,
        edge_clusters=clusters,
        cluster_count=next_cluster,
        backend="hdbscan" if used_hdbscan else "density-gap-fallback",
    )


__all__ = [
    "BehaviorAnalysis",
    "OOVEmbeddingCache",
    "analyze_behaviors",
    "entity_similarity",
    "operation_transition_similarity",
]
