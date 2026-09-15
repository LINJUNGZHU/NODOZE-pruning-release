from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TargetContext:
    relations: frozenset[str] = frozenset()
    process_lineage: frozenset[str] = frozenset()
    resources: frozenset[str] = frozenset()
    remote_endpoints: frozenset[str] = frozenset()
    commands: frozenset[str] = frozenset()
    neighborhood: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class TargetMatchFeatures:
    relation: float
    lineage: float
    resource: float
    remote: float
    command: float
    neighborhood: float
    total: float


class TargetConditionedCompatibility:
    @staticmethod
    def _hit(value: str | None, values: frozenset[str]) -> float:
        if value is None or not values:
            return 0.0
        lowered = value.lower()
        return float(any(item.lower() in lowered or lowered in item.lower() for item in values))

    def score(self, context: TargetContext, *, relation: str, process: str | None,
              resource: str | None, remote: str | None, command: str | None,
              nodes: set[str]) -> TargetMatchFeatures:
        values = (
            float(relation.upper() in {item.upper() for item in context.relations}),
            self._hit(process, context.process_lineage), self._hit(resource, context.resources),
            self._hit(remote, context.remote_endpoints), self._hit(command, context.commands),
            len(nodes & set(context.neighborhood)) / max(1, len(nodes)),
        )
        return TargetMatchFeatures(*values, sum(values) / len(values))


__all__ = ["TargetConditionedCompatibility", "TargetContext", "TargetMatchFeatures"]
