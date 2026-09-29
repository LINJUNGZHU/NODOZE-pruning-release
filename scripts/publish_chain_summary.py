"""Publish only registered case identities and aggregate numeric chain metrics.

Usage: python -m scripts.publish_chain_summary --input LOCAL_REPORT.json \
    --output webapp/frontend/chain-study-summary.json

This module does not import the experiment runner or copy nested input objects.
New public cases, methods or stages require an explicit source-code registration
and review; arbitrary labels and identifiers are never accepted as output text.
Detailed local reports, event identities, resource semantics, paths, provenance,
per-event scores and source/history descriptors have no publication fields.
"""
from __future__ import annotations

import argparse
from collections.abc import Mapping
import json
import math
from pathlib import Path


PUBLIC_CASES = {
    'cadets06': ('CADETS-06', 'real'),
    'cadets12': ('CADETS-12', 'real'),
    'cadets13': ('CADETS-13', 'real'),
    'synthetic101': ('Synthetic-101', 'synthetic'),
    'synthetic202': ('Synthetic-202', 'synthetic'),
    'synthetic303': ('Synthetic-303', 'synthetic'),
}
METHOD_LABELS = {
    'rarity_only': '仅原始稀有度', 'diffusion_only': '仅图扩散', 'rasp': '原 RASP',
    'contextual': '上下文稀有度 + 扩散', 'chain_only': 'RASP + 整链选择',
    'adaptive': '上下文稀有度 + 扩散 + 整链选择',
}
STAGES = ('source', 'candidate', 'temporal_eligible', 'bundle_eligible', 'retained')
LOSS_STAGES = STAGES + ('invalid_reference', 'surviving')
POINT_RATIOS = ('complete_reference_retention', 'verified_attack_chain_retention',
                'candidate_chain_coverage', 'conditional_reference_retention',
                'positive_event_retention')
CHAIN_COUNTS = ('reference_chain_count', 'admitted_complete_chain_count',
                'valid_complete_chain_count', 'derived_reference_chain_count',
                'synthetic_chain_count', 'unreviewed_reference_chain_count',
                'unverifiable_chain_count', 'invalid_chain_count')
STAGE_COUNTS = ('complete_chain_count', 'derived_chain_count',
                'synthetic_chain_count', 'reference_chain_count')
STAGE_RATIOS = ('complete_chain_retention', 'conditional_complete_chain_retention',
                'derived_chain_retention', 'synthetic_chain_retention',
                'reference_chain_retention')


def _mapping(value):
    if not isinstance(value, Mapping):
        raise ValueError('expected an aggregate metric object')
    return value


def _count(value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError('aggregate counts must be nonnegative integers')
    return value


def _unit(value):
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or not 0 <= value <= 1):
        raise ValueError('ratios must be finite numbers in [0, 1]')
    return float(value)


def _ratio(value):
    value = _mapping(value)
    numerator, denominator = _count(value.get('numerator')), _count(value.get('denominator'))
    if numerator > denominator:
        raise ValueError('ratio numerator cannot exceed denominator')
    if denominator == 0:
        if value.get('value') is not None:
            raise ValueError('zero-denominator ratios must remain unavailable')
        result = None
    else:
        result = numerator / denominator
        if not math.isclose(_unit(value.get('value')), result, rel_tol=1e-12, abs_tol=1e-15):
            raise ValueError('ratio value does not match its counts')
    return {'numerator': numerator, 'denominator': denominator, 'value': result}


def _copy_fields(source, count_keys=(), ratio_keys=()):
    source = _mapping(source)
    result = {}
    for key in count_keys:
        if key in source:
            result[key] = _count(source[key])
    for key in ratio_keys:
        if key in source:
            result[key] = _ratio(source[key])
    return result


def _stage_order(value):
    if (not isinstance(value, list) or any(not isinstance(stage, str) or stage not in STAGES for stage in value)
            or len(value) != len(set(value))):
        raise ValueError('stage order must contain unique registered stage names')
    positions = [STAGES.index(stage) for stage in value]
    if positions != sorted(positions):
        raise ValueError('stage order must follow the registered evaluation sequence')
    return list(value)


def _loss_counts(value):
    value = _mapping(value)
    return {stage: _count(value[stage]) for stage in LOSS_STAGES if stage in value}


def _event_funnel(value):
    value = _mapping(value)
    order = _stage_order(value.get('stage_order'))
    stages = _mapping(value.get('stages'))
    result = _copy_fields(value, ('reference_event_count',))
    result['stage_order'] = order
    result['stages'] = {
        stage: _copy_fields(stages.get(stage), ('retained_event_count',),
                            ('total_retention', 'conditional_retention')) for stage in order
    }
    result['first_loss_counts'] = _loss_counts(value.get('first_loss_counts'))
    return result


def _chain_evaluation(value):
    value = _mapping(value)
    order = _stage_order(value.get('stage_order'))
    stages = _mapping(value.get('stages'))
    result = _copy_fields(value, CHAIN_COUNTS)
    result['schema_version'] = 'chain-evaluation-v1'
    result['stage_order'] = order
    result['stages'] = {stage: _copy_fields(stages.get(stage), STAGE_COUNTS, STAGE_RATIOS) for stage in order}
    result['first_loss_counts'] = _loss_counts(value.get('first_loss_counts'))
    if 'event_funnel' in value:
        result['event_funnel'] = _event_funnel(value['event_funnel'])
    # Boolean declarations are optional and strictly typed. Their field names
    # are registered; no arbitrary string metadata can enter through them.
    for key in ('evaluation_only', 'ground_truth_used_for_selection'):
        if key in value:
            if type(value[key]) is not bool:
                raise ValueError('evaluation declarations must be booleans')
            result[key] = value[key]
    return result


def _point(value, candidate_edges):
    value = _mapping(value)
    method = value.get('method')
    if not isinstance(method, str) or method not in METHOD_LABELS:
        raise ValueError('method must be explicitly registered for publication')
    budget_ratio = _unit(value.get('budget_ratio'))
    compression = _unit(value.get('actual_compression'))
    budget, retained = _count(value.get('budget_edges')), _count(value.get('retained_edges'))
    if (candidate_edges <= 0 or budget_ratio <= 0 or budget != int(candidate_edges * budget_ratio)
            or retained > budget or budget > candidate_edges):
        raise ValueError('retained events must fit the original candidate budget')
    if not math.isclose(compression, 1 - retained / candidate_edges, rel_tol=1e-12, abs_tol=1e-15):
        raise ValueError('compression does not match retained and candidate counts')
    result = {
        'method': method, 'method_label': METHOD_LABELS[method],
        'budget_ratio': budget_ratio, 'budget_edges': budget, 'retained_edges': retained,
        'actual_compression': 1 - retained / candidate_edges,
    }
    result.update(_copy_fields(value, ratio_keys=POINT_RATIOS))
    if 'chain_evaluation' in value:
        result['chain_evaluation'] = _chain_evaluation(value['chain_evaluation'])
    if 'positive_event_funnel' in value:
        result['positive_event_funnel'] = _event_funnel(value['positive_event_funnel'])
    return result


def make_public_summary(report):
    """Build aggregate output from an explicit field allowlist without mutation.

    Only PUBLIC_CASES, METHOD_LABELS and STAGES provide text values. All other
    leaves are validated counts, bounded ratios, booleans, or unavailable nulls.
    Additional keys at every input level are discarded, never recursively copied.
    """
    report = _mapping(report)
    if report.get('schema_version') != 'adaptive-chain-study-v1':
        raise ValueError('unsupported study schema')
    cases = report.get('cases')
    if not isinstance(cases, list):
        raise ValueError('study cases must be a list')
    public_cases, seen = [], set()
    for case in cases:
        case = _mapping(case)
        case_id = case.get('id')
        if not isinstance(case_id, str) or case_id not in PUBLIC_CASES or case_id in seen:
            raise ValueError('case identity must be unique and explicitly registered for publication')
        seen.add(case_id)
        label, kind = PUBLIC_CASES[case_id]
        if case.get('kind') != kind:
            raise ValueError('case kind does not match its public registration')
        candidate_edges = _count(case.get('candidate_edges'))
        chains = case.get('reference_chains', [])
        if not isinstance(chains, list):
            raise ValueError('reference_chains must be a list')
        chain_count = _count(case.get('reference_chain_count', len(chains)))
        points = case.get('results')
        if not isinstance(points, list):
            raise ValueError('case results must be a list')
        public_cases.append({
            'id': case_id, 'label': label, 'kind': kind, 'candidate_edges': candidate_edges,
            'reference_chains': [], 'reference_chain_count': chain_count,
            'results': [_point(point, candidate_edges) for point in points],
        })
    return {'schema_version': 'adaptive-chain-study-v1', 'data_visibility': 'aggregate_only', 'cases': public_cases}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.input.resolve() == args.output.resolve():
        raise ValueError('summary output must differ from the detailed source report')
    summary = make_public_summary(json.loads(args.input.read_text(encoding='utf-8')))
    payload = json.dumps(summary, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + '.tmp')
    temporary.write_text(payload, encoding='utf-8')
    temporary.replace(args.output)
    print(json.dumps({'data_visibility': 'aggregate_only', 'cases': len(summary['cases']),
                      'points': sum(len(case['results']) for case in summary['cases'])}))


if __name__ == '__main__':
    main()
