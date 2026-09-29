"""Reference-subgraph figures preserve fixed denominators and missing metrics."""
from copy import deepcopy
import json

import pytest


METHODS = ('rarity_only', 'diffusion_only', 'rasp', 'context_v1',
           'reliability', 'adaptive_v1', 'reliability_chain')
CASES = ('cadets06', 'cadets12', 'cadets13', 'theia-case1', 'theia-case3',
         'theia-case5', 'trace-case5-paper', 'fivedirections-case1', 'fivedirections-case3')


def api():
    from scripts import plot_reference_subgraphs
    return plot_reference_subgraphs


@pytest.fixture
def report():
    cases = []
    for case_id in CASES:
        missing = case_id == 'theia-case5'
        native_count = None if missing else 0 if case_id == 'trace-case5-paper' else 2
        summaries = {
            'native': {'reference_subgraph_count': native_count,
                       'singleton_event_count': None if missing else 3 if native_count == 0 else 1,
                       'reference_events': None if missing else 3 if native_count == 0 else 7},
            'augmented': {'reference_subgraph_count': None if missing else 3,
                          'singleton_event_count': None if missing else 1,
                          'reference_events': None if missing else 9},
        }
        variants = []
        for track in ('base', 'expanded') if case_id.startswith('cadets') else ('base',):
            for policy in ('single', 'declared', 'adaptive'):
                rows = []
                for method in METHODS:
                    for budget in (10, 20):
                        scopes = {}
                        for scope, summary in summaries.items():
                            count = summary['reference_subgraph_count']
                            complete = None if count is None else min(count, budget // 10)
                            scopes[scope] = {
                                'reference_subgraph_count': count, 'complete_subgraphs': complete,
                                'subgraph_retention': complete / count if count else None,
                                'event_retention': None if missing else .8,
                                'terminal_reachability': None if not count else 1.,
                            }
                        rows.append({'method': method, 'budget': budget, 'compression': 1 - budget / 100,
                                     'fixed_scope_compression': 1 - budget / 200, 'scopes': scopes})
                variants.append({'track': track, 'poi_policy': policy, 'rows': rows})
        cases.append({'id': case_id, 'reference_summaries': summaries, 'variants': variants})
    return {'schema_version': 'chain-subgraph-report-v1', 'data_visibility': 'aggregate_only', 'cases': cases}


def test_native_zero_denominator_and_absent_reference_have_no_perfect_curve(report):
    module = api()
    figure = module.overview_figure(report, scope='native')
    try:
        for index in (5, 6):
            ax = figure.axes[index]
            assert not ax.lines
            assert any('N/A' in text.get_text() for text in ax.texts)
        trace_title = figure.axes[6].get_title()
        assert '0 subgraphs' in trace_title and '3 singleton' in trace_title
        assert len(figure.axes[0].lines) == 7
        assert not any('100%' in text.get_text() for text in figure.axes[6].texts)
    finally:
        module.plt.close(figure)


def test_augmented_scope_is_separate_and_method_colors_do_not_shift(report):
    module = api()
    first = report['cases'][0]['variants'][1]
    for point in first['rows']:
        if point['method'] == 'rarity_only':
            point['scopes']['augmented']['subgraph_retention'] = None
    figure = module.overview_figure(report, scope='augmented')
    try:
        colors = [{line.get_label(): line.get_color() for line in ax.lines} for ax in figure.axes]
        assert len(figure.axes[6].lines) == 7
        assert colors[0]['Diffusion'] == colors[1]['Diffusion']
        assert 'augmented' in figure._suptitle.get_text().lower()
        assert 'sensitivity' in figure._suptitle.get_text().lower()
    finally:
        module.plt.close(figure)


def test_case_facets_use_fixed_scope_compression_and_all_policies(report):
    module = api()
    for case, expected in ((report['cases'][0], 6), (report['cases'][3], 3)):
        figure = module.case_figure(case)
        try:
            assert len(figure.axes) == expected
            assert all('fixed candidate scope' in ax.get_xlabel() for ax in figure.axes)
            assert all(list(line.get_xdata()) == [.9, .95] for ax in figure.axes for line in ax.lines)
            assert '7 reference events' in figure._suptitle.get_text()
            assert '1 singleton' in figure._suptitle.get_text()
        finally:
            module.plt.close(figure)


def test_all_nine_cases_export_33_publication_files_and_cli(report, tmp_path, capsys):
    module = api()
    source = tmp_path / 'aggregate.json'
    source.write_text(json.dumps(report))
    output = tmp_path / 'figures'
    module.main(['--input', str(source), '--output', str(output)])
    files = sorted(output.iterdir())
    assert len(files) == 33
    assert {path.suffix for path in files} == {'.pdf', '.png', '.svg'}
    assert all(path.stat().st_size > 100 for path in files)
    expected = {'overview-native-subgraphs', 'overview-augmented-subgraphs'}
    expected |= {case + '-native-subgraphs-fixed-scope' for case in CASES}
    assert {path.stem for path in files} == expected
    assert json.loads(capsys.readouterr().out)['artifacts'] == 33
    svg = (output / 'overview-native-subgraphs.svg').read_text()
    assert 'N/A' in svg and 'independent attacks' in svg


@pytest.mark.parametrize('change', ['schema', 'unsafe_case', 'invalid_ratio'])
def test_invalid_public_input_is_rejected_before_writing(report, tmp_path, change):
    value = deepcopy(report)
    if change == 'schema':
        value['schema_version'] = 'retained-chain-export-v1'
    elif change == 'unsafe_case':
        value['cases'][0]['id'] = '../private-event'
    else:
        value['cases'][0]['variants'][0]['rows'][0]['scopes']['native']['subgraph_retention'] = 1.5
    with pytest.raises(ValueError):
        api().plot_report(value, tmp_path / 'figures')
    assert not (tmp_path / 'figures').exists()
