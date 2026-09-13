"""Central, label-free RCVP experiment parameters and relation families.

Families classify already-normalized events; they never reverse endpoints.
"""
from copy import deepcopy
import math

import numpy as np

from .causal import CausalSearchConfig


FAMILIES = {
    'process_control': ['EVENT_FORK', 'EVENT_CLONE', 'EVENT_EXIT', 'EVENT_CHANGE_PRINCIPAL',
                        'PROCESS_CREATE', 'PROCESS_TERMINATE'],
    'file_read': ['EVENT_READ', 'EVENT_MMAP', 'EVENT_LOADLIBRARY', 'FILE_READ'],
    'file_write': ['EVENT_WRITE', 'EVENT_CREATE_OBJECT', 'EVENT_UNLINK', 'EVENT_RENAME',
                   'FILE_WRITE', 'FILE_CREATE', 'FILE_DELETE', 'FILE_MODIFY', 'FILE_RENAME'],
    'network_receive': ['EVENT_RECVFROM', 'EVENT_RECVMSG', 'EVENT_ACCEPT',
                        'EVENT_READ_SOCKET_PARAMS', 'FLOW_RECEIVE', 'FLOW_READ', 'FLOW_INBOUND'],
    'network_send': ['EVENT_SENDTO', 'EVENT_SENDMSG', 'EVENT_CONNECT',
                     'FLOW_SEND', 'FLOW_WRITE', 'FLOW_OUTBOUND'],
    'execution': ['EVENT_EXECUTE', 'PROCESS_EXECUTE'],
    'other': [],
}

_SEARCH = CausalSearchConfig()
DEFAULT = dict(
    schema_version=1, mixing='weighted', relation_families=FAMILIES,
    directional_relation_aliases={r: {'inbound': 'FLOW_INBOUND', 'outbound': 'FLOW_OUTBOUND'}
                                  for r in ('FLOW_MESSAGE', 'FLOW_START', 'FLOW_OPEN')},
    relation_weights={name: 1. for name in FAMILIES}, rarity_floor=.2,
    damping=.85, temporal_tau_seconds=900., temporal_tau_overrides={},
    fanout_gamma=.5, high_frequency_degree=_SEARCH.high_frequency_degree,
    high_frequency_partition_seconds=_SEARCH.high_frequency_partition_seconds,
    backward_enabled=True, verification_enabled=True, background_contrast=True,
    root_quantile=.5, max_root_candidates=32, root_min_score=0.,
    channel_weights=dict(backward=.35, forward=.35, verification=.75),
    epsilon=1e-300, include_legacy=True, legacy_restart=.15,
    legacy_iterations=200, legacy_tolerance=1e-10,
)


def validate_config(config=None):
    if config is not None and not isinstance(config, dict):
        raise ValueError('rcvp config must be an object')
    unknown = set(config or {}) - set(DEFAULT)
    if unknown:
        raise ValueError(f'unknown rcvp fields: {sorted(unknown)}')
    cfg = deepcopy(DEFAULT)
    cfg.update(deepcopy(config or {}))
    if type(cfg['schema_version']) is not int or cfg['schema_version'] != 1:
        raise ValueError('unsupported rcvp config schema')
    if cfg['mixing'] not in ('legacy', 'uniform', 'weighted'):
        raise ValueError('invalid rcvp mixing')
    for name in ('backward_enabled', 'verification_enabled', 'background_contrast', 'include_legacy'):
        if type(cfg[name]) is not bool:
            raise ValueError(f'{name} must be boolean')
    for name in ('max_root_candidates', 'high_frequency_degree', 'legacy_iterations'):
        if type(cfg[name]) is not int or cfg[name] < 1:
            raise ValueError(f'{name} must be a positive integer')
    def number(value, name, lo=0., hi=float('inf'), strict=False):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ValueError(f'{name} must be finite numeric')
        if value < lo or value > hi or (strict and value == lo):
            raise ValueError(f'{name} outside range')
    for name in ('root_quantile', 'root_min_score'):
        number(cfg[name], name, hi=1.)
    for name in ('rarity_floor', 'legacy_restart'):
        number(cfg[name], name, hi=1., strict=True)
    number(cfg['damping'], 'damping', hi=1.)
    if cfg['damping'] == 1:
        raise ValueError('damping must be < 1')
    number(cfg['fanout_gamma'], 'fanout_gamma')
    for name in ('high_frequency_partition_seconds', 'epsilon', 'legacy_tolerance'):
        number(cfg[name], name, strict=True)
    if cfg['epsilon'] >= 1:
        raise ValueError('epsilon must be < 1')
    if cfg['temporal_tau_seconds'] is not None:
        number(cfg['temporal_tau_seconds'], 'temporal_tau_seconds', strict=True)
    mapping, weights, overrides = (cfg[k] for k in ('relation_families', 'relation_weights', 'temporal_tau_overrides'))
    if not all(isinstance(v, dict) for v in (mapping, weights, overrides)) or 'other' not in mapping:
        raise ValueError('relation maps must be objects with other fallback')
    seen = set()
    for family, relations in mapping.items():
        if not isinstance(family, str) or not family or not isinstance(relations, list):
            raise ValueError('invalid relation family')
        for relation in relations:
            if not isinstance(relation, str) or not relation or relation.upper() in seen:
                raise ValueError('empty or duplicate relation mapping')
            seen.add(relation.upper())
    if set(weights) != set(mapping) or set(overrides) - set(mapping):
        raise ValueError('family weights/overrides must match mapping')
    aliases = cfg['directional_relation_aliases']
    if not isinstance(aliases, dict):
        raise ValueError('directional_relation_aliases must be an object')
    for relation, directions in aliases.items():
        if not isinstance(relation, str) or not isinstance(directions, dict) or set(directions) - {'inbound', 'outbound'}:
            raise ValueError('invalid directional relation alias')
        if any(not isinstance(alias, str) or alias.upper() not in seen for alias in directions.values()):
            raise ValueError('directional relation alias must reference a mapped relation')
    for family, weight in weights.items():
        number(weight, f'weight {family}', strict=True)
    for family, tau in overrides.items():
        if tau is not None:
            number(tau, f'tau {family}', strict=True)
    if not isinstance(cfg['channel_weights'], dict) or set(cfg['channel_weights']) != {'backward', 'forward', 'verification'}:
        raise ValueError('invalid channel_weights')
    for name, value in cfg['channel_weights'].items():
        number(value, f'channel {name}', hi=1.)
    return cfg


def preset(name):
    cfg = deepcopy(DEFAULT)
    if name == 'conservative':
        cfg.update(mixing='legacy', temporal_tau_seconds=None, fanout_gamma=0., verification_enabled=False)
    elif name == 'relation_aware':
        cfg.update(mixing='uniform', temporal_tau_seconds=None, fanout_gamma=0., verification_enabled=False)
    elif name != 'full':
        raise ValueError('unknown RCVP preset')
    return validate_config(cfg)


def relation_families(relations, config):
    lookup = {r.upper(): family for family, members in config['relation_families'].items() for r in members}
    return np.array([lookup.get(str(r).upper(), 'other') for r in relations])


def optc_relation_names(edges, config):
    """Family-only aliases from the direction already used by optc.parse_event.

    Leaves original relation, source, target and event identity untouched.
    Missing/unknown direction remains the original relation and falls back.
    """
    aliases = config['directional_relation_aliases']
    return [aliases.get(e['relation'].upper(), {}).get(
        str(e.get('raw', {}).get('properties', {}).get('direction', '')).lower(), e['relation']) for e in edges]
