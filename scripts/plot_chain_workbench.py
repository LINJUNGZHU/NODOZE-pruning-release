"""Publication plots from aggregate-only workbench reports.

python -m scripts.plot_chain_workbench --input REPORT.json --output FIGUREDIR
Each case exports candidate-relative and fixed-scope compression/reference-chain
curves plus equal-absolute-budget incremental-positive-retention facets. Every
figure is written as PDF, PNG, and SVG; missing metrics remain explicitly N/A.
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

_METHOD_LABELS = {
    'rarity_only': 'Frequency rarity', 'diffusion_only': 'Diffusion',
    'rasp': 'RASP', 'context_v1': 'Previous context fusion',
    'reliability': 'Confidence-calibrated fusion',
    'adaptive_v1': 'Previous fusion + chain bundles',
    'reliability_chain': 'Calibrated fusion + chain bundles',
}
_POLICY_LABELS = {'single': 'Single original POI', 'declared': 'All original POIs', 'adaptive': 'Adaptive investigation anchors'}


def _write_figure(figure, folder, stem):
    files = []
    for suffix in ('.pdf', '.png', '.svg'):
        path = folder / (stem + suffix)
        figure.savefig(path, dpi=180, bbox_inches='tight')
        files.append(path)
    plt.close(figure)
    return files


def _coverage_note(case):
    summary = case.get('fixed_reference_summary') or {}
    count = summary.get('chain_count')
    if count is None:
        return 'Reference coverage unavailable'
    note = (f'{count} reference paths; {summary.get("covered_positive_events")} covered positives; '
            f'{summary.get("singleton_positive_events")} singleton positives')
    synthetic = summary.get('paths_containing_synthetic_lineage')
    if count and synthetic == count:
        note += '\nAll reference paths depend on synthetic LINEAGE; not independent raw-log evidence'
    elif synthetic:
        note += f'; {synthetic}/{count} paths include synthetic LINEAGE'
    return note


def _case_figure(case, *, metric, xfield, equal_budget=False):
    tracks = [track for track in ('base', 'expanded') if any(v['track'] == track for v in case['variants'])]
    policies = [policy for policy in ('single', 'declared', 'adaptive') if any(v['poi_policy'] == policy for v in case['variants'])]
    fig, axes = plt.subplots(len(tracks), len(policies), squeeze=False,
                             figsize=(5 * len(policies), 3.7 * len(tracks) + .6), sharey=True)
    by_variant = {(v['track'], v['poi_policy']): v for v in case['variants']}
    budget_sets = [{row['budget'] for row in variant['rows']} for variant in case['variants']]
    common_budgets = set.intersection(*budget_sets) if budget_sets else set()
    handles, labels = {}, {}
    for row_number, track in enumerate(tracks):
        for col_number, policy in enumerate(policies):
            ax = axes[row_number, col_number]
            variant = by_variant.get((track, policy))
            ax.set_title(f'{track.capitalize()} | {_POLICY_LABELS[policy]}', fontsize=10)
            ax.set_ylim(-.025, 1.025)
            ax.yaxis.set_major_formatter(PercentFormatter(1))
            ax.grid(alpha=.25)
            if equal_budget:
                ax.set_xscale('log')
                ax.set_xlabel('Absolute retained-edge budget (common across variants)')
            else:
                ax.set_xlim(-.025, 1.025)
                ax.xaxis.set_major_formatter(PercentFormatter(1))
                ax.set_xlabel('Compression in fixed candidate scope' if xfield == 'fixed_scope_compression' else 'Compression in this candidate graph')
            if col_number == 0:
                ax.set_ylabel('Incremental known-positive retention' if equal_budget else 'Whole reference-chain retention')
            displayed = False
            if variant:
                for method, label in _METHOD_LABELS.items():
                    points = [point for point in variant['rows'] if point['method'] == method
                              and point.get(metric) is not None
                              and (not equal_budget or point['budget'] in common_budgets)]
                    points.sort(key=lambda point: point[xfield])
                    if not points:
                        continue
                    line, = ax.plot([point[xfield] for point in points], [point[metric] for point in points],
                                    marker='o', markersize=3, linewidth=1.4, label=label)
                    handles[method], labels[method] = line, label
                    displayed = True
            if not displayed:
                ax.text(.5, .5, 'N/A: no applicable reference denominator' if not equal_budget or common_budgets
                        else 'N/A: no common absolute budgets', transform=ax.transAxes,
                        ha='center', va='center', fontsize=9, wrap=True)
    headline = ('Equal absolute budgets: original POIs excluded from the fixed positive denominator'
                if equal_budget else 'Source-positive-subgraph reference chains; complete attack truth unavailable')
    fig.suptitle(f'{case["id"].upper()} — {headline}\n{_coverage_note(case)}', fontsize=10)
    if handles:
        order = [method for method in _METHOD_LABELS if method in handles]
        fig.legend([handles[method] for method in order], [labels[method] for method in order],
                   loc='lower center', ncol=min(4, len(order)), fontsize=8, frameon=False)
    fig.tight_layout(rect=(0, .11, 1, .85))
    return fig


def _overview_figure(report):
    """One independent base/declared panel per case; never average case ratios."""
    cases = report['cases']
    columns = min(3, max(1, len(cases)))
    rows = max(1, math.ceil(len(cases) / columns))
    figure, axes = plt.subplots(rows, columns, squeeze=False, sharex=True, sharey=True,
                               figsize=(5 * columns, 3.6 * rows + 1.0))
    handles = {}
    colors = plt.rcParams['axes.prop_cycle'].by_key()['color']
    for index, ax in enumerate(axes.flat):
        if index >= len(cases):
            ax.set_visible(False)
            continue
        case = cases[index]
        variant = next((value for value in case['variants']
                        if (value['track'], value['poi_policy']) == ('base', 'declared')), None)
        summary = case.get('fixed_reference_summary') or {}
        count = summary.get('chain_count')
        coverage = ('Reference unavailable' if count is None else
                    f'{count} paths / {summary.get("covered_positive_events")} covered positives / '
                    f'{summary.get("singleton_positive_events")} singleton positives')
        ax.set_title(f'{case["id"].upper()}\n{coverage}', fontsize=9)
        ax.set_xlim(-.025, 1.025); ax.set_ylim(-.025, 1.025)
        ax.xaxis.set_major_formatter(PercentFormatter(1))
        ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.grid(alpha=.25)
        if index // columns == rows - 1:
            ax.set_xlabel('Compression in fixed base candidates', fontsize=9)
        if index % columns == 0:
            ax.set_ylabel('Whole reference-path retention', fontsize=9)
        shown = False
        if variant:
            for method_index, (method, label) in enumerate(_METHOD_LABELS.items()):
                points = [point for point in variant['rows']
                          if point['method'] == method and point.get('reference_chain_count', 0)
                          and point.get('reference_chain_retention') is not None]
                points.sort(key=lambda point: point['compression'])
                if not points:
                    continue
                line, = ax.plot([point['compression'] for point in points],
                                [point['reference_chain_retention'] for point in points],
                                label=label, color=colors[method_index % len(colors)],
                                linewidth=1.4, marker='o', markersize=2.8)
                handles[method] = line
                shown = True
        if not shown:
            ax.text(.5, .5, 'N/A: no applicable fixed reference', transform=ax.transAxes,
                    ha='center', va='center', fontsize=9)
        synthetic = summary.get('paths_containing_synthetic_lineage')
        if count and synthetic:
            warning = ('All reference paths depend on synthetic LINEAGE' if synthetic == count
                       else f'{synthetic}/{count} reference paths contain synthetic LINEAGE')
            ax.text(.03, .03, warning + '\nNot independent raw-log attack-chain evidence',
                    transform=ax.transAxes, fontsize=7.2, color='#8a2d22', va='bottom',
                    bbox={'facecolor': 'white', 'alpha': .9, 'edgecolor': 'none', 'pad': 2})
    figure.suptitle('Compression–whole reference-path retention: registered development cases', fontsize=13)
    figure.text(.5, .945,
                'Same base candidates and declared POIs within each case; seven project methods; no case averaging.',
                ha='center', fontsize=9)
    if handles:
        ordered = [method for method in _METHOD_LABELS if method in handles]
        figure.legend([handles[method] for method in ordered], [_METHOD_LABELS[method] for method in ordered],
                      loc='lower center', ncol=min(4, len(ordered)), fontsize=8, frameon=False)
    figure.tight_layout(rect=(0, .085, 1, .91))
    return figure


def plot_report(report, output):
    if report.get('schema_version') != 'chain-workbench-v2-report' or report.get('data_visibility') != 'aggregate_only':
        raise ValueError('plotter requires an aggregate workbench report')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    files = []
    with plt.rc_context({'font.family': 'DejaVu Sans', 'svg.fonttype': 'none', 'pdf.fonttype': 42}):
        if report['cases']:
            files.extend(_write_figure(_overview_figure(report), output, 'overview-reference-chain'))
        for case in report['cases']:
            if not re.fullmatch(r'[a-z][a-z0-9-]{1,63}', case['id']):
                raise ValueError('case ID is not a safe registered plot filename')
            if not case['variants']:
                continue
            for suffix, metric, xfield, equal in (
                ('reference-chain', 'reference_chain_retention', 'compression', False),
                ('reference-chain-fixed-scope', 'reference_chain_retention', 'fixed_scope_compression', False),
                ('equal-budget', 'incremental_retention', 'budget', True),
            ):
                figure = _case_figure(case, metric=metric, xfield=xfield, equal_budget=equal)
                files.extend(_write_figure(figure, output, f'{case["id"]}-{suffix}'))
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
