"""Find observed compression points satisfying offline reference-retention floors.

This is a posthoc operating-point analysis of a previously evaluated report.
Reference labels select budgets here; this is not an online guarantee or a new
pruning algorithm. No interpolation or monotonicity assumption is used.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import re

METRICS = {
    'event_retention': ('retained_reference_events', 'reference_events'),
    'dependency_retention': ('retained_dependencies', 'reference_dependencies'),
    'terminal_reachability': ('reachable_terminal_pairs', 'terminal_pairs'),
}
POINT_FIELDS = ('budget', 'retained_events', 'compression', 'fixed_scope_compression')


def _fraction(value):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 1


def _point(row, scope):
    metrics = row['scopes'][scope]
    result = {key: row[key] for key in POINT_FIELDS}
    for ratio, counts in METRICS.items():
        result.update({key: metrics[key] for key in (ratio, *counts)})
    return result


def select_budget(points, target, *, scope='native', require_terminals=False):
    """Return highest compression satisfying every requested floor in ONE point."""
    if not _fraction(target) or target == 0 or type(require_terminals) is not bool:
        raise ValueError('target must be in (0,1] and require_terminals boolean')
    if scope not in ('native', 'augmented') or not points:
        raise ValueError('known reference scope and nonempty observed points required')
    fields = list(METRICS) if require_terminals else list(METRICS)[:2]
    budgets, methods, denominators, stages = set(), set(), None, None
    for row in points:
        if (type(row['budget']) is not int or row['budget'] < 1 or row['budget'] in budgets
                or type(row['retained_events']) is not int
                or not 0 <= row['retained_events'] <= row['budget']
                or not all(_fraction(row[key]) for key in POINT_FIELDS[2:])):
            raise ValueError('invalid observed budget or compression')
        budgets.add(row['budget']); methods.add(row['method'])
        m = row['scopes'][scope]
        current = []
        for ratio, (numerator, denominator) in METRICS.items():
            a, b, rate = m[numerator], m[denominator], m[ratio]
            if a is None and b is None:
                if rate is not None: raise ValueError('unknown reference has a ratio')
            elif type(a) is not int or type(b) is not int or not 0 <= a <= b:
                raise ValueError('invalid reference counts')
            elif b == 0:
                if rate is not None: raise ValueError('zero denominator must be unavailable')
            elif not _fraction(rate) or abs(rate-a/b) > 1e-12:
                raise ValueError('reference ratio differs from counts')
            current.append(b)
        if denominators is not None and current != denominators:
            raise ValueError('reference denominators change between budgets')
        denominators = current
        counts = m['event_stage_counts']
        if counts is None:
            if m['reference_events'] is not None: raise ValueError('missing event stages')
            fixed = None
        else:
            values = [counts[key] for key in ('source', 'candidate', 'temporal_eligible', 'retained')]
            if (any(type(value) is not int or value < 0 for value in values)
                    or values != sorted(values, reverse=True)
                    or values[0] != m['reference_events']
                    or values[-1] != m['retained_reference_events']):
                raise ValueError('event stages are inconsistent')
            fixed = values[:3]
        if stages is not None and stages != fixed:
            raise ValueError('preselection coverage changes between budgets')
        stages = fixed
    if len(methods) != 1:
        raise ValueError('budget selection must hold method fixed')
    result = dict(status='unmet', reason='no_tested_budget_meets_target', selected=None,
                  closest=None, best_joint_retention=None,
                  event_ceilings=None if not stages or not stages[0] else
                  dict(source=1., candidate=stages[1]/stages[0], temporal_eligible=stages[2]/stages[0]))
    if any(row['scopes'][scope][key] is None for row in points for key in fields):
        return dict(result, status='unavailable', reason='required_reference_metric_unavailable')
    valid = [row for row in points if all(row['scopes'][scope][key] >= target for key in fields)]
    if valid:
        chosen = min(valid, key=lambda row: (-row['compression'], row['budget']))
        return dict(result, status='met', reason=None, selected=_point(chosen, scope))
    closest = min(points, key=lambda row: (-min(row['scopes'][scope][key] for key in fields),
                                          -row['compression'], row['budget']))
    result.update(closest=_point(closest, scope),
                  best_joint_retention=min(closest['scopes'][scope][key] for key in fields))
    for key, reason in [('candidate', 'candidate_event_ceiling'), ('temporal_eligible', 'temporal_event_ceiling')]:
        if result['event_ceilings'] and result['event_ceilings'][key] < target:
            result['reason'] = reason
            break
    return result


def analyze_report(report, *, input_sha256, targets=(.9, .95, .99, 1.)):
    if (report.get('schema_version') != 'chain-subgraph-report-v1'
            or report.get('data_visibility') != 'aggregate_only'
            or not re.fullmatch('[a-f0-9]{64}', input_sha256)
            or not targets or len(set(targets)) != len(targets)):
        raise ValueError('validated public subgraph report and unique targets required')
    records, cases = [], set()
    for case in report['cases']:
        if case['id'] in cases: raise ValueError('duplicate case')
        cases.add(case['id']); variants = set()
        for variant in case['variants']:
            key = (variant['track'], variant['poi_policy'])
            if key in variants: raise ValueError('duplicate variant')
            variants.add(key)
            n, total = variant['candidate_events'], variant['source_scope_events']
            if type(n) is not int or type(total) is not int or not 0 < n <= total:
                raise ValueError('invalid candidate denominators')
            for row in variant['rows']:
                if (row['retained_events'] > n or row['budget'] > n
                        or abs(row['compression']-(1-row['retained_events']/n)) > 1e-12
                        or abs(row['fixed_scope_compression']-(1-row['retained_events']/total)) > 1e-12):
                    raise ValueError('compression differs from actual retained count')
            for method in dict.fromkeys(row['method'] for row in variant['rows']):
                points = [row for row in variant['rows'] if row['method'] == method]
                for scope in ('native', 'augmented'):
                    for target in targets:
                        for terminals in (False, True):
                            result = select_budget(points, target, scope=scope, require_terminals=terminals)
                            records.append(dict(case_id=case['id'], track=key[0], poi_policy=key[1],
                                method=method, scope=scope, target=target, require_terminals=terminals,
                                source_missing_positive_events=case['source_missing_positive_events'], **result))
    return dict(schema_version='retention-target-analysis-v1', source_report_sha256=input_sha256,
                base_report_sha256=report['base_report_sha256'], targets=list(targets),
                methodology=dict(reference_used_for_budget_selection=True, unseen_data_guarantee=False,
                    split='posthoc_development', pruning_recomputed=False, search='observed_budget_grid_only',
                    objective='maximum_actual_compression_subject_to_joint_retention_floors',
                    method_track_poi_held_fixed=True, event_retention_includes_singletons=True), rows=records)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.with_suffix('.csv').exists():
        raise FileExistsError('target analysis output must be new')
    blob = args.input.read_bytes()
    report = analyze_report(json.loads(blob), input_sha256=hashlib.sha256(blob).hexdigest())
    flat = []
    for row in report['rows']:
        record = {key:value for key,value in row.items() if key not in ('selected','closest','event_ceilings')}
        for field in ('selected','closest','event_ceilings'):
            for key,value in (row[field] or {}).items(): record[field+'_'+key] = value
        flat.append(record)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.with_suffix('.csv').open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(dict.fromkeys(key for row in flat for key in row)), lineterminator='\n')
        writer.writeheader(); writer.writerows(flat)
    with args.output.open('x') as stream:
        json.dump(report, stream, ensure_ascii=False, sort_keys=True, separators=(',',':'), allow_nan=False)
        stream.write('\n')
    print(json.dumps({'profiles':len(flat),'output':str(args.output)}))


if __name__ == '__main__':
    main()
