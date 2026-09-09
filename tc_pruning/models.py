from __future__ import annotations

from dataclasses import dataclass, field
import re


def normalize_entity_label(node_type: str, label: str) -> str:
    value = (label or "").strip()
    if node_type == "file":
        value = re.sub(r"(?i)(/home/)[^/]+", r"\1*", value)
        value = re.sub(r"(?i)(/users/)[^/]+", r"\1*", value)
        value = re.sub(r"(?i)([a-z]:\\users\\)[^\\]+", r"\1*", value)
    return f"{node_type}:{value}"


@dataclass(frozen=True, slots=True)
class NodeRecord:
    uuid: str
    node_type: str
    label: str
    host: str = ""
    semantic_key: str = ""
    properties: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.semantic_key:
            object.__setattr__(
                self, "semantic_key", normalize_entity_label(self.node_type, self.label)
            )


@dataclass(frozen=True, slots=True)
class EdgeRecord:
    event_id: str
    src: str
    dst: str
    relation: str
    timestamp_ns: int = 0
    host: str = ""
    data_size: int | None = None


Observation = NodeRecord | EdgeRecord


@dataclass(frozen=True, slots=True)
class StoredEdge:
    edge_id: int
    event_id: str
    src: str
    dst: str
    relation: str
    timestamp_ns: int
    host: str
    src_type: str
    dst_type: str
    src_semantic: str = ""
    dst_semantic: str = ""
    data_size: int | None = None


@dataclass(slots=True)
class Neighborhood:
    nodes: dict[str, NodeRecord] = field(default_factory=dict)
    edges: list[StoredEdge] = field(default_factory=list)
