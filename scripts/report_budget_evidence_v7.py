"""Build immutable first-stage provenance, registry, descriptive profile and figures.

Only reads completed decisions and post-selection evaluation. It never runs a selector.
"""
import argparse
import csv
import gzip
import hashlib
import json
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


PAPERS = [
    ('DEPIMPACT', 'USENIX Security 2022', 'https://www.usenix.org/system/files/sec22summer_fang.pdf'),
    ('SPARSE', 'arXiv v1 2024', 'https://arxiv.org/pdf/2405.02629v1'),
    ('NODLINK', 'NDSS 2024', 'https://www.ndss-symposium.org/wp-content/uploads/2024-204-paper.pdf'),
    ('ORTHRUS', 'USENIX Security 2025', 'https://www.usenix.org/system/files/usenixsecurity25-jiang-baoxiang.pdf'),
    ('PIDSMaker/Bilot', 'USENIX Security 2025', 'https://www.usenix.org/system/files/usenixsecurity25-bilot.pdf'),
    ('ProvX', 'USENIX Security 2026', 'https://www.usenix.org/system/files/usenixsecurity26-wu-weiheng.pdf'),
    ('KnowHow', 'NDSS 2026', 'https://www.ndss-symposium.org/wp-content/uploads/2026-s199-paper.pdf'),
    ('G-Retriever', 'NeurIPS 2024', 'https://proceedings.neurips.cc/paper_files/paper/2024/file/efaf1c9726648c8ba363a5c927440529-Paper-Conference.pdf'),
    ('RRF', 'SIGIR 2009', 'https://cormack.uwaterloo.ca/cormacksigir09-rrf.pdf'),
    ('Submodular summarization', 'ACL 2011', 'https://aclanthology.org/P11-1052.pdf'),
    ('Graph sparsification audit', 'PVLDB 17', 'https://www.vldb.org/pvldb/vol17/p427-chen.pdf'),
    ('DeepTest', 'ICSE 2018', 'https://arxiv.org/pdf/1708.08559v2'),
    ('Elastic Sketch', 'SIGCOMM 2018', 'https://yangzhou1997.github.io/paper/elastic-sigcomm18.pdf'),
]


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def gz(path):
    with gzip.open(path, 'rt') as f:
        return json.load(f)


def write_new(path, content):
    path = Path(path)
    with path.open('x') as f:
        if isinstance(content, str):
            f.write(content)
        else:
            json.dump(content, f, ensure_ascii=False, indent=2)
            f.write('\n')


def csv_new(path, rows):
    rows = list(rows)
    with Path(path).open('x', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator='\n')
        w.writeheader()
        w.writerows(rows)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input-dir', type=Path, required=True)
    p.add_argument('--output-dir', type=Path, required=True)
    a = p.parse_args()
    output = a.output_dir
    result_path = output / 'results.json'
    results = json.loads(result_path.read_text())
    audit = json.loads((output / 'input_audit.json').read_text())
    manifests = [gz(a.input_dir / f'case{i}' / 'manifest.json.gz') for i in range(5)]
    assert len(results['results']) == 120
    assert all(len(m['runs']) == 24 and m['labels_used_for_selection'] is False for m in manifests)
    assert all(m['source_sha256'] == manifests[0]['source_sha256'] and m['config_sha256'] == manifests[0]['config_sha256'] for m in manifests)
    assert all(m.get('execution_git_commit') == manifests[0].get('execution_git_commit') for m in manifests)
    for i, m in enumerate(manifests):
        assert m['ledger_sha256'] == audit['cases'][i]['inputs']['ledger']['sha256']
        for run in m['runs']:
            assert digest(run['path']) == run['sha256']
        for pool in m['pools']:
            assert digest(pool['path']) == pool['sha256']
    for path, expected in manifests[0]['source_sha256'].items():
        assert digest(path) == expected, f'executed source changed: {path}'
    postselection = ['scripts/evaluate_budget_evidence_v7.py', 'scripts/diagnose_budget_evidence_v7.py',
                     'scripts/diagnose_group_rank_v7.py', 'scripts/report_budget_evidence_v7.py']
    frozen_v6 = gz(audit['cases'][0]['inputs']['frozen_v6_decisions']['path'])
    source = {
        'protocol': 'budget-evidence-v7',
        'execution_commit': manifests[0].get('execution_git_commit','207690f'),
        'execution_commit_role': 'HEAD observed by runner when decisions were generated; per-file hashes are authoritative',
        'source_sha256': manifests[0]['source_sha256'],
        'validated_inherited_v6_source_sha256': frozen_v6['source_sha256'],
        'postselection_sha256': {path: digest(path) for path in postselection},
        'config_sha256': manifests[0]['config_sha256'],
        'reference_sha256': results['reference_sha256'],
        'result_sha256': digest(result_path),
        'case_manifests': [dict(case_index=i, path=str(a.input_dir / f'case{i}' / 'manifest.json.gz'), sha256=digest(a.input_dir / f'case{i}' / 'manifest.json.gz')) for i in range(5)],
        'label_boundary': 'reference read only by evaluator and diagnosis, after decisions were persisted',
    }
    write_new(output / 'source_manifest.json', source)
    baseline = {
        'protocol': 'budget-evidence-v7',
        'local_methods': [
            dict(name=name, status='native_reproduced' if name in ('witness_rerank', 'history_channel_portfolio') else 'historical_result_only',
                 code_entry=entry, training='cached local history where applicable; no new training',
                 prior='same report-derived oracle POIs; no external alerts', event_mapping='frozen local ledger ID',
                 parameter_selection='frozen v4/v6 configuration', executed_in_v7=name in ('witness_rerank', 'history_channel_portfolio'))
            for name, entry in audit['methods'].items()
        ],
        'paper_methods': [
            dict(name=name, version=version, paper_url=url, status='paper_reference_only',
                 author_code_url=None, author_commit=None, author_implementation_executed=False,
                 adapter=None, event_mapping=None, training=None, prior=None,
                 parameter_selection=None, reason='No validated author-system execution or event mapping in this first stage')
            for name, version, url in PAPERS
        ],
        'component_borrowing': [
            dict(component='RRF rank fusion', source='RRF', status='component_adapter', detail='c=60 fixed initial value; no claim of author system reproduction'),
            dict(component='group evidence coverage', source='Submodular summarization', status='conceptual_inspiration_only', detail='OR-of-AND evidence and union cost violate a plain submodular guarantee'),
            dict(component='matched-budget graph retrieval', source='G-Retriever', status='experimental_design_only', detail='No LLM or full-system baseline executed'),
        ],
    }
    write_new(output / 'baseline_manifest.json', baseline)
    registry = {
        'protocol': 'budget-evidence-v7',
        'registered_cases': [x['name'] for x in audit['cases']],
        'split': 'previously-used-development',
        'budgets': [256, 1024],
        'track': 'poi_only',
        'rows': [dict(run_id=x['run_id'], case_index=x['case_id'], budget=x['budget'], family=x['run_id'].split('-')[0].upper(),
                      method=x['method'], objective=x['objective'], pool_sha256=x['pool_hash'], status=x['status'],
                      decision_path=next(run['path'] for run in manifests[x['case_id']]['runs'] if run['run_id'] == x['run_id']))
                 for x in results['results']],
        'not_executed': [
            dict(experiment='E1_four_budget_and_shared_context', reason='first-stage H1/H2 results negative; predeclared stop rule'),
            dict(experiment='E2_cap_and_rrf_sensitivity', reason='first-stage H1 result negative; not used for case-specific post hoc tuning'),
            dict(experiment='E4_context_frequency_state_diffusion', reason='second-stage separate design'),
            dict(experiment='E5_independent_reference_witnesses', reason='two-reviewer independent evidence reference absent'),
            dict(experiment='E6_robustness', reason='no promoted first-stage method; requires distinct run design'),
            dict(experiment='E7_five_independent_process_repetitions', reason='not run; only one descriptive case process each'),
            dict(experiment='E8_unseen_attacks', reason='no frozen unseen attack with independent event reference'),
        ],
    }
    write_new(output / 'experiment_registry.json', registry)
    profile_rows = []
    for i, m in enumerate(manifests):
        profile_rows.append(dict(case_index=i, case_name=audit['cases'][i]['name'], process_repetitions=1,
                                 scope='cold_case_process_24_reused_decisions', cold_seconds=m['elapsed_seconds'],
                                 warm_seconds=None, peak_rss_mib=m['peak_rss_mib'],
                                 candidate_build_seconds=sum(pool['diagnostics'].get('build_seconds', 0) for pool in m['pools']),
                                 alternative_build_seconds=sum(pool['diagnostics'].get('seconds', 0) for pool in m['pools']),
                                 historical_build_seconds=None, status='descriptive_only_not_E7',
                                 reason='one process per case; history cache reused; no five-repeat median/IQR'))
    csv_new(output / 'profiles.csv', profile_rows)
    csv_new(output / 'robustness.csv', [dict(experiment='E6', status='not_run', case_index=None, seed=None,
                                            perturbation=None, strength=None, recall_original=None,
                                            recall_observable=None, reason='first-stage stop rule; no fixed method promoted')])
    rows = results['results']
    def get(case, budget, token):
        return next(x for x in rows if x['run_id'] == token.format(c=case, b=budget))
    cases = [x['name'] for x in audit['cases']]
    lines = [
        ('v4 portfolio', 'e0-c{c}-b{b}-witness_rerank'),
        ('v6 composite', 'e0-c{c}-b{b}-history_channel_portfolio'),
        ('E2 group RRF', 'e2-c{c}-group-rrf-b{b}'),
        ('E3 k3 edge', 'e3-c{c}-k3-edge_score-b{b}'),
        ('E3 k3 witness+detail', 'e3-c{c}-k3-witness_plus_detail-b{b}'),
    ]
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.2), sharey=True)
    for ax, budget in zip(axes, (256, 1024)):
        for label, token in lines:
            ax.plot(range(5), [get(i, budget, token)['recall_known'] for i in range(5)], marker='o', label=label)
        ax.set_xticks(range(5), ['FD1', 'FD3', 'THEIA1', 'THEIA3', 'CASE5*'])
        ax.set_title(f'Raw ledger budget {budget}; development cases')
        ax.set_ylabel('Recall of local partial positives')
        ax.set_ylim(0, 1.05)
        ax.grid(alpha=.25)
    axes[1].legend(loc='center left', bbox_to_anchor=(1, .5))
    fig.tight_layout()
    fig.savefig(output / 'observed_two_budget_recall.png', dpi=170, bbox_inches='tight')
    plt.close(fig)
    print('SAVED first-stage manifests, registry, descriptive profile, status and figure')


if __name__ == '__main__':
    main()
