from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class InvestigationState:
    version: int
    component_ids: tuple[str, ...]
    selected_event_ids: tuple[str, ...]
    added_event_ids: tuple[str, ...]
    removed_event_ids: tuple[str, ...]

    @classmethod
    def empty(cls):
        return cls(0, (), (), (), ())

    def update(self, *, component_ids, selected_event_ids):
        current = set(self.selected_event_ids)
        future = set(selected_event_ids)
        return InvestigationState(
            self.version + 1, tuple(sorted(component_ids)), tuple(sorted(future)),
            tuple(sorted(future - current)), tuple(sorted(current - future)),
        )


__all__ = ["InvestigationState"]
