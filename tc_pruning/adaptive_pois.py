"""Reliability-calibrated rarity and label-free investigation-anchor suggestions.

R_new = (1 - weight * confidence) * raw + weight * confidence * surprise.
Confidence zero is an exact legacy fallback, not evidence that a novel event is
benign. No value here is a maliciousness probability.

POI marginal gain is evidence times *new cohort mass*. Each observed
(host, program family) has mass one: 0.45 for the family, 0.25 shared equally
among its distinct processes, 0.20 among its relations, and 0.10 among distinct
(process, relation, UTC-aligned time-bin) episodes. A candidate covers its four
facets; gain counts only facets not already covered by protected/suggested
anchors. The default 0.05 threshold means 5% of one cohort's mass, not 5% of all
candidate events. Repeating resource UUIDs/records does not create new mass.

Only the strongest event per episode is considered (event-ID ties are stable).
The candidate pool first reserves one representative per best-scoring cohort,
then adds further representatives round-robin, capped at 4096 total and
min(max_pois, 32) per cohort. These approximation limits are disclosed. This
avoids quadratic event-pair scans: O(N + U log K + K * max_pois), apart from
bounded cohort heaps, with O(N) identity/episode bookkeeping; K <= 4096.
Recommendations are investigation anchors, never detector-confirmed alerts.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
import heapq
import math

import numpy as np


_MAX_CANDIDATES = 4096
_MAX_PER_COHORT = 32
_PROCESS_TYPES = frozenset({'process', 'proc', 'subject', 'subject_process'})


def _unit_vector(values, name):
    if isinstance(values, (list, tuple)) and any(isinstance(x, (bool, np.bool_)) for x in values):
        raise ValueError(f'{name} must contain numeric evidence, not booleans')
    array = np.asarray(values)
    if array.ndim != 1 or array.dtype.kind not in 'fiu':
        raise ValueError(f'{name} must be a one-dimensional numeric vector')
    array = array.astype(float, copy=False)
    if not np.all(np.isfinite(array)) or np.any((array < 0) | (array > 1)):
        raise ValueError(f'{name} must be finite in [0, 1]')
    return array


def _unit_scalar(value, name):
    if (isinstance(value, (bool, np.bool_)) or not isinstance(value, (int, float, np.integer, np.floating))
            or not math.isfinite(value) or not 0 <= value <= 1):
        raise ValueError(f'{name} must be finite in [0, 1]')
    return float(value)


def reliability_rarity(raw, context, weight=.75):
    """Fuse vectors using confidence/surprise from frozen contextual evidence.

    Only those two context fields are consumed; novelty, anomaly_score, labels
    and any other input metadata do not affect this formula.
    """
    raw = _unit_vector(raw, 'raw rarity')
    weight = _unit_scalar(weight, 'weight')
    if not isinstance(context, Sequence) or len(context) != len(raw):
        raise ValueError('context must contain exactly one evidence object per raw score')
    confidences, surprises = [], []
    for row in context:
        if not isinstance(row, Mapping):
            raise ValueError('context entries must be mappings')
        confidences.append(_unit_scalar(row.get('confidence'), 'confidence'))
        surprises.append(_unit_scalar(row.get('contextual_surprise'), 'contextual_surprise'))
    reliability = weight * np.asarray(confidences, dtype=float)
    return (1. - reliability) * raw + reliability * np.asarray(surprises, dtype=float)


def _text(row, key, default=''):
    value = row.get(key, default)
    if value is None:
        return default
    if not isinstance(value, str):
        raise ValueError(f'{key} must be a string')
    return value


def _episode(row, episode_ns):
    src, dst = _text(row, 'src'), _text(row, 'dst')
    relation, host = _text(row, 'relation'), _text(row, 'host')
    if not src or not dst or not relation:
        raise ValueError('src, dst and relation must be nonempty')
    src_type, dst_type = _text(row, 'src_type').lower(), _text(row, 'dst_type').lower()
    if src_type in _PROCESS_TYPES:
        actor, semantic = src, _text(row, 'src_semantic')
    elif dst_type in _PROCESS_TYPES:
        actor, semantic = dst, _text(row, 'dst_semantic')
    else:
        actor, semantic = src, _text(row, 'src_semantic')
    # The family groups installation paths by executable basename, while the
    # process identity remains a separate facet. No src/dst edge is reversed.
    program = semantic
    if ':' in program and program.split(':', 1)[0].lower() in _PROCESS_TYPES:
        program = program.split(':', 1)[1]
    program = program.replace('\\', '/').rsplit('/', 1)[-1] if program else actor
    timestamp = row.get('timestamp_ns')
    if (isinstance(timestamp, (bool, np.bool_)) or not isinstance(timestamp, (int, np.integer))
            or timestamp < 0 or timestamp > np.iinfo(np.int64).max):
        raise ValueError('timestamp_ns must be a nonnegative int64 integer')
    return (host, program), actor, relation, int(timestamp) // episode_ns


@dataclass(slots=True)
class _Cohort:
    processes: set = field(default_factory=set)
    relations: set = field(default_factory=set)
    episodes: int = 0
    best: tuple | None = None


def select_adaptive_pois(rows, values, *, max_pois=8, episode_seconds=60, gain_threshold=.05):
    """Preserve declared seeds and suggest a variable number of new anchors.

    The returned bool mask follows input row order. Diagnostics use only stable
    event identities and deterministic selection order, so row permutations and
    label-field changes cannot alter the selected identity set or explanations.
    No suggestions are made from zero evidence. Mandatory seeds over the hard
    cap are an explicit infeasible configuration, never silently discarded.
    """
    if isinstance(max_pois, (bool, np.bool_)) or not isinstance(max_pois, (int, np.integer)) or max_pois < 1:
        raise ValueError('max_pois must be a positive integer')
    if (isinstance(episode_seconds, (bool, np.bool_))
            or not isinstance(episode_seconds, (int, float, np.integer, np.floating))
            or not math.isfinite(episode_seconds) or episode_seconds <= 0
            or episode_seconds > np.iinfo(np.int64).max / 1e9):
        raise ValueError('episode_seconds must be finite and positive')
    episode_ns = int(episode_seconds * 1e9)
    if episode_ns < 1:
        raise ValueError('episode_seconds must be at least one nanosecond')
    threshold = _unit_scalar(gain_threshold, 'gain_threshold')
    scores = _unit_vector(values, 'anchor evidence')
    if len(scores) != len(rows):
        raise ValueError('one evidence value is required per event')
    ids, seen, cohorts, representatives, declared = [], set(), {}, {}, {}
    kept = np.zeros(len(rows), dtype=bool)
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            raise ValueError('candidate rows must be mappings')
        event = _text(row, 'event_id')
        if not event.strip() or event in seen:
            raise ValueError('event IDs must be unique nonempty strings')
        seen.add(event); ids.append(event)
        is_declared = row.get('is_declared_poi', False)
        if type(is_declared) is not bool:
            raise ValueError('is_declared_poi must be boolean')
        episode = _episode(row, episode_ns)
        family, process, relation, _ = episode
        cohort = cohorts.setdefault(family, _Cohort())
        cohort.processes.add(process); cohort.relations.add(relation)
        prior = representatives.get(episode)
        if prior is None:
            representatives[episode] = index
            cohort.episodes += 1
        elif scores[index] > scores[prior] or (scores[index] == scores[prior] and event < ids[prior]):
            representatives[episode] = index
        if is_declared:
            declared[index] = episode; kept[index] = True
    if len(declared) > max_pois:
        raise ValueError('declared seeds exceed max_pois; configuration is infeasible')

    def facets(episode):
        family, process, relation, _ = episode
        cohort = cohorts[family]
        return (
            (('cohort', family), .45),
            (('process', family, process), .25 / len(cohort.processes)),
            (('relation', family, relation), .20 / len(cohort.relations)),
            (('episode', episode), .10 / cohort.episodes),
        )

    covered = {token for episode in declared.values() for token, _ in facets(episode)}

    def initial_rank(item):
        episode, index = item
        gain = float(scores[index]) * sum(mass for token, mass in facets(episode) if token not in covered)
        return -gain, ids[index]

    positive_episodes, eligible_episodes = 0, 0
    for episode, index in representatives.items():
        if scores[index] <= 0:
            continue
        positive_episodes += 1
        rank = initial_rank((episode, index))
        if kept[index] or rank[0] >= 0:
            continue
        eligible_episodes += 1
        cohort = cohorts[episode[0]]
        if cohort.best is None or rank < cohort.best[0]:
            cohort.best = rank, episode, index
    primary = heapq.nsmallest(_MAX_CANDIDATES,
                              (cohort.best for cohort in cohorts.values() if cohort.best is not None),
                              key=lambda item: item[0])
    groups = {item[1][0]: [] for item in primary}
    for episode, index in representatives.items():
        if episode[0] in groups and scores[index] > 0 and not kept[index]:
            rank = initial_rank((episode, index))
            if rank[0] < 0:
                groups[episode[0]].append((episode, index))
    quota = min(int(max_pois), _MAX_PER_COHORT)
    groups = {family: heapq.nsmallest(quota, members, key=initial_rank) for family, members in groups.items()}
    pool = []
    for position in range(quota):
        for _, episode, _ in primary:
            members = groups[episode[0]]
            if position < len(members):
                item_episode, index = members[position]
                pool.append((item_episode, index, facets(item_episode)))
            if len(pool) >= _MAX_CANDIDATES:
                break
        if len(pool) >= _MAX_CANDIDATES:
            break
    suggestions, selected_count = [], len(declared)
    stop_reason = 'no_positive_evidence' if positive_episodes == 0 else 'no_new_cohort_coverage'
    while selected_count < max_pois:
        best = None
        for episode, index, evidence_facets in pool:
            if kept[index]:
                continue
            added = [(token, mass) for token, mass in evidence_facets if token not in covered]
            gain = float(scores[index]) * sum(mass for _, mass in added)
            rank = -gain, ids[index]
            if best is None or rank < best[0]:
                best = rank, index, added
        if best is None or best[0][0] == 0:
            break
        rank, index, added = best
        gain = -rank[0]
        if gain < threshold:
            stop_reason = 'gain_below_threshold'
            break
        kept[index] = True; selected_count += 1
        covered.update(token for token, _ in added)
        suggestions.append({'event_id': ids[index], 'evidence': float(scores[index]),
                            'marginal_gain': gain, 'new_facets': [token[0] for token, _ in added],
                            'reason': 'algorithm_suggested_new_cohort_evidence',
                            'detector_confirmed': False})
    if selected_count >= max_pois:
        stop_reason = 'max_pois_reached'
    elif selected_count == 0:
        stop_reason = 'no_anchor'
    elif pool and all(kept[index] or not any(token not in covered for token, _ in entries)
                      for _, index, entries in pool):
        stop_reason = 'no_new_cohort_coverage'
    return kept, {
        'declared_event_ids': sorted(ids[index] for index in declared),
        'suggested_event_ids': sorted(item['event_id'] for item in suggestions),
        'selected_event_ids': sorted(ids[index] for index in np.flatnonzero(kept)),
        'suggestions': suggestions, 'suggested_are_detector_confirmed': False,
        'ground_truth_used': False, 'selected_count': int(kept.sum()), 'declared_count': len(declared),
        'suggested_count': len(suggestions), 'cohort_count': len(cohorts),
        'episode_representative_count': len(representatives), 'positive_episode_count': positive_episodes,
        'candidate_pool_count': len(pool), 'candidate_pool_truncated': eligible_episodes > len(pool),
        'max_candidate_representatives': _MAX_CANDIDATES, 'max_representatives_per_cohort': quota,
        'max_pois': int(max_pois), 'episode_seconds': float(episode_seconds), 'gain_threshold': threshold,
        'gain_semantics': 'evidence_times_new_cohort_mass_not_global_event_fraction',
        'stop_reason': stop_reason,
    }


__all__ = ['reliability_rarity', 'select_adaptive_pois']
