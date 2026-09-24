import csv

from scripts.export_sparse_local_reference_csv import export_table


def test_csv_export_preserves_proxy_and_unavailable_official_metrics(tmp_path):
    metrics = {
        'candidate_edges': 5, 'output_edges': 2,
        'proxy_tp': 1, 'proxy_fp': 1, 'proxy_fn': 1, 'proxy_tn': 2,
        'proxy_precision': 0.5, 'proxy_recall': 0.5, 'proxy_f1': 0.5,
        'proxy_fpr': 1 / 3, 'proxy_fnr': 0.5,
        'critical_groups_hit': 1, 'critical_groups_total': 2,
        'attack_stages_hit': 1, 'attack_stages_total': 2,
        'official_equivalent_metrics': {
            'fp': None, 'fn': None, 'precision': None, 'recall': None, 'f1': None,
        },
    }
    output = tmp_path / 'table.csv'
    export_table({'cases': [{'name': 'case', 'baseline': metrics,
                             'optimized': metrics}]}, output)
    with output.open(newline='') as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == 2
    assert rows[0]['proxy_fpr_pct'] == '33.333333'
    assert rows[0]['sparse_equivalent_fp'] == 'NA'
    assert rows[1]['method'] == 'optimized'
