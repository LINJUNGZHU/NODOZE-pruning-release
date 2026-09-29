"""Plot public, fixed reference-subgraph metrics without reading event identities.

python -m scripts.plot_reference_subgraphs --input REPORT.json --output FIGUREDIR
Native and LINEAGE-augmented scopes have separate fixed denominators. Neither
component counts nor terminal reachability establish independent attack counts.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import re

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter

from scripts.plot_chain_workbench import _METHOD_LABELS, _POLICY_LABELS, _write_figure


_SCOPES = ('native', 'augmented')
_POLICIES = ('single', 'declared', 'adaptive')


def _coverage(case, scope):
    summary = case['reference_summaries'][scope]
    if summary['reference_subgraph_count'] is None:
        return 'Reference unavailable'
    return (f"{summary['reference_subgraph_count']} subgraphs / "
            f"{summary['reference_events']} reference events / "
            f"{summary['singleton_event_count']} singleton events")


def _axes_style(ax, *, fixed_scope=False):
    ax.set_xlim(-.025, 1.025)
    ax.set_ylim(-.025, 1.025)
    ax.xaxis.set_major_formatter(PercentFormatter(1))
    ax.yaxis.set_major_formatter(PercentFormatter(1))
    ax.set_xlabel('Compression in fixed candidate scope' if fixed_scope
                  else 'Compression in base candidates', fontsize=9)
    ax.set_ylabel('Whole reference-subgraph retention', fontsize=9)
    ax.grid(alpha=.25)


def _plot_variant(ax, variant, scope, xfield):
    handles = {}
    colors = plt.rcParams['axes.prop_cycle'].by_key()['color']
    if variant is not None:
        for index, (method, label) in enumerate(_METHOD_LABELS.items()):
            points = [row for row in variant['rows'] if row['method'] == method
                      and row['scopes'][scope]['reference_subgraph_count']
                      and row['scopes'][scope]['subgraph_retention'] is not None]
            points.sort(key=lambda row: row[xfield])
            if not points:
                continue
            line, = ax.plot([row[xfield] for row in points],
                            [row['scopes'][scope]['subgraph_retention'] for row in points],
                            color=colors[index % len(colors)], label=label,
                            linewidth=1.4, marker='o', markersize=3)
            handles[method] = line
    if not handles:
        ax.text(.5, .5, 'N/A: no applicable reference-subgraph denominator',
                transform=ax.transAxes, ha='center', va='center', fontsize=9, wrap=True)
    return handles


def _legend(figure, handles):
    order = [method for method in _METHOD_LABELS if method in handles]
    if order:
        figure.legend([handles[method] for method in order], [_METHOD_LABELS[method] for method in order],
                      loc='lower center', ncol=min(4, len(order)), fontsize=8, frameon=False)


def overview_figure(report, *, scope='native'):
    """One base/declared panel per case; never choose a case's best policy."""
    if scope not in _SCOPES:
        raise ValueError('unknown reference scope')
    cases = report['cases']
    columns = min(3, max(1, len(cases)))
    rows = max(1, math.ceil(len(cases) / columns))
    figure, axes = plt.subplots(rows, columns, squeeze=False, sharex=True, sharey=True,
                               figsize=(5.2 * columns, 3.7 * rows + 1.0))
    handles = {}
    for index, ax in enumerate(axes.flat):
        if index >= len(cases):
            ax.set_visible(False)
            continue
        case = cases[index]
        variant = next((value for value in case['variants']
                        if (value['track'], value['poi_policy']) == ('base', 'declared')), None)
        _axes_style(ax)
        if index // columns != rows - 1:
            ax.set_xlabel('')
        if index % columns:
            ax.set_ylabel('')
        ax.set_title(f"{case['id'].upper()}\n{_coverage(case, scope)}", fontsize=9)
        handles.update(_plot_variant(ax, variant, scope, 'compression'))
    title = ('Native reference-subgraph completeness' if scope == 'native'
             else 'Augmented reference-subgraph completeness: LINEAGE sensitivity')
    figure.suptitle(title, fontsize=13)
    note = ('Native scope excludes synthetic LINEAGE.' if scope == 'native'
            else 'Augmented scope includes synthetic LINEAGE; denominators differ from native.')
    figure.text(.5, .945, 'Fixed base candidates and declared POIs; seven methods; no case averaging.',
                ha='center', fontsize=9)
    figure.text(.5, .922, note + ' Reference subgraphs are not independent attacks.',
                ha='center', fontsize=8)
    _legend(figure, handles)
    figure.tight_layout(rect=(0, .075, 1, .90))
    return figure


def case_figure(case):
    """Native scope, one panel per track/policy and a common fixed-scope x axis."""
    tracks = [track for track in ('base', 'expanded')
              if any(value['track'] == track for value in case['variants'])]
    figure, axes = plt.subplots(max(1, len(tracks)), len(_POLICIES), squeeze=False,
                               sharex=True, sharey=True,
                               figsize=(15.6, 3.7 * max(1, len(tracks)) + 1.0))
    variants = {(value['track'], value['poi_policy']): value for value in case['variants']}
    handles = {}
    for row, track in enumerate(tracks):
        for column, policy in enumerate(_POLICIES):
            ax = axes[row, column]
            _axes_style(ax, fixed_scope=True)
            if column:
                ax.set_ylabel('')
            ax.set_title(f'{track.capitalize()} | {_POLICY_LABELS[policy]}', fontsize=10)
            handles.update(_plot_variant(ax, variants.get((track, policy)), 'native', 'fixed_scope_compression'))
    figure.suptitle(f"{case['id'].upper()} — Native reference-subgraph completeness\n"
                   f"{_coverage(case, 'native')}\n"
                   'All required events must survive; reference subgraphs are not independent attacks.',
                   fontsize=10)
    _legend(figure, handles)
    figure.tight_layout(rect=(0, .12, 1, .82))
    return figure


def _validate_report(report):
    if (report.get('schema_version') != 'chain-subgraph-report-v1'
            or report.get('data_visibility', 'aggregate_only') != 'aggregate_only'):
        raise ValueError('plotter requires a public aggregate reference-subgraph report')
    cases = report.get('cases')
    if not isinstance(cases, list) or not cases:
        raise ValueError('report must contain cases')
    seen = set()
    for case in cases:
        case_id = case.get('id')
        if not isinstance(case_id, str) or not re.fullmatch(r'[a-z][a-z0-9-]{1,63}', case_id) or case_id in seen:
            raise ValueError('case IDs must be unique safe public plot names')
        seen.add(case_id)
        for scope in _SCOPES:
            summary = case['reference_summaries'][scope]
            for key in ('reference_subgraph_count', 'reference_events', 'singleton_event_count'):
                value = summary[key]
                if value is not None and (type(value) is not int or value < 0):
                    raise ValueError('reference summary counts must be nonnegative integers or null')
        variants = case['variants']
        if not variants:
            raise ValueError('case requires frozen variants')
        variant_keys = set()
        for variant in variants:
            key = (variant['track'], variant['poi_policy'])
            if key in variant_keys or key[0] not in ('base', 'expanded') or key[1] not in _POLICIES:
                raise ValueError('unknown or duplicate track/policy')
            variant_keys.add(key)
            for point in variant['rows']:
                if point['method'] not in _METHOD_LABELS:
                    raise ValueError('unregistered method')
                for value in (point['compression'], point['fixed_scope_compression']):
                    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 1:
                        raise ValueError('compression must be a finite fraction')
                for scope in _SCOPES:
                    metric = point['scopes'][scope]
                    denominator = metric['reference_subgraph_count']
                    if denominator != case['reference_summaries'][scope]['reference_subgraph_count']:
                        raise ValueError('reference denominator changed across variants')
                    value = metric['subgraph_retention']
                    if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float))
                                               or not math.isfinite(value) or not 0 <= value <= 1 or not denominator):
                        raise ValueError('subgraph retention requires a positive fixed denominator and finite fraction')


def plot_report(report, output):
    _validate_report(report)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    files = []
    with plt.rc_context({'font.family': 'DejaVu Sans', 'svg.fonttype': 'none', 'pdf.fonttype': 42}):
        for scope in _SCOPES:
            files.extend(_write_figure(overview_figure(report, scope=scope), output,
                                       f'overview-{scope}-subgraphs'))
        for case in report['cases']:
            files.extend(_write_figure(case_figure(case), output,
                                       f"{case['id']}-native-subgraphs-fixed-scope"))
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    report = json.loads(args.input.read_text())
    files = plot_report(report, args.output)
    print(json.dumps({'artifacts': len(files), 'output': str(args.output)}))


if __name__ == '__main__':
    main()
