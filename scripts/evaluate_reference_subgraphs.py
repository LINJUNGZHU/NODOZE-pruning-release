"""Add fixed reference-subgraph metrics to immutable v2 decisions, without rescoring.

Public JSON/CSV contain aggregates only. Optional catalog-bound inspection files
contain private source events and must remain local. All variants are validated
before reference access; existing v2 report and experiment bytes are preserved.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import re

import numpy as np

from scripts import evaluate_chain_workbench as base
from scripts.adaptive_chain_inputs import derive_reference_chains, load_source_events
from tc_pruning.chain_workbench import METHODS, canonical, digest, read_gzip, write_json
from tc_pruning.subgraph_evaluation import derive_reference_subgraphs, evaluate_subgraphs

STAGES = ('source', 'candidate', 'temporal_eligible', 'retained')
SCOPES = {'native': False, 'augmented': True}
SUMMARY_COUNTS = ('reference_subgraph_count', 'singleton_event_count', 'reference_events',
    'reference_dependencies', 'terminal_pairs', 'fork_count', 'join_count', 'input_events',
    'excluded_synthetic_events', 'synthetic_events', 'inferred_host_dependencies', 'unverifiable_time_events')
METRIC_COUNTS = ('reference_subgraph_count', 'complete_subgraphs', 'singleton_event_count',
    'retained_singleton_events', 'reference_events', 'retained_reference_events',
    'reference_dependencies', 'retained_dependencies', 'terminal_pairs', 'reachable_terminal_pairs',
    'fork_count', 'complete_forks', 'join_count', 'complete_joins')
METRIC_RATIOS = ('subgraph_retention', 'event_retention', 'dependency_retention',
                 'terminal_reachability', 'fork_retention', 'join_retention')


def _counts(value, keys):
    output = {}
    for key in keys:
        item = value[key]
        if type(item) is not int or item < 0:
            raise ValueError(f'invalid public count {key}')
        output[key] = item
    return output


def _summary(value):
    output = _counts(value, SUMMARY_COUNTS)
    if type(value['include_synthetic']) is not bool:
        raise ValueError('invalid synthetic scope flag')
    output.update(include_synthetic=value['include_synthetic'],
                  independent_attack_count=None, attack_stage_completeness=None,
                  scope='fixed_observed_positive_subgraphs_not_complete_attacks')
    return output


def _read(path):
    contents = Path(path).read_bytes()
    return json.loads(contents), hashlib.sha256(contents).hexdigest()


def _unique(values, key, label):
    result = {}
    for value in values:
        identity = key(value)
        if identity in result:
            raise ValueError(f'duplicate {label} in base report')
        result[identity] = value
    return result


def _unchanged(files):
    if any(not path.is_file() or digest(path) != expected for path, expected in files.items()):
        raise ValueError('frozen input or bound report/reference changed during evaluation')


def _catalog_requests(catalog, local_output, watched, run_root):
    if catalog is None:
        if local_output is not None:
            raise ValueError('local output requires a catalog of exact frozen exports')
        return {}
    if local_output is None:
        raise ValueError('catalog inspection requires a new local output directory')
    output = Path(local_output)
    if output.exists():
        raise FileExistsError('local inspection output must be new')
    catalog = Path(catalog).resolve()
    value, watched[catalog] = _read(catalog)
    asset_root = catalog.parent
    allowed = [(asset_root/'retained-chain-data').resolve(), (Path(run_root)/'exports').resolve()]
    requests, seen = {}, set()
    for entry in value['entries']:
        if entry.get('study_version') != 'chain-workbench-v2':
            continue
        name = entry.get('id', '')
        url = entry.get('artifact_url', '')
        if (not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]*', name)
                or name in seen or not url.startswith('/assets/retained-chain-data/')):
            raise ValueError('invalid or duplicate local export catalog identity')
        path = (asset_root/url.removeprefix('/assets/')).resolve()
        if '..' in Path(url).parts or not any(path.is_relative_to(root) for root in allowed):
            raise ValueError('local export path escapes retained-chain-data')
        artifact, watched[path] = _read(path)
        fields = ('case_id', 'track', 'poi_policy', 'method', 'budget_edges')
        if any(entry.get(k) != artifact.get(k) for k in fields):
            raise ValueError('catalog and artifact decision mismatch')
        if type(artifact['budget_edges']) is not int:
            raise ValueError('local export budget must be an integer')
        key = tuple(artifact[k] for k in fields)
        seen.add(name)
        requests.setdefault(key, []).append({'id': name, 'artifact': artifact})
    return requests


def _metrics(evaluation):
    retained = evaluation['stages']['retained']
    output = _counts(retained, METRIC_COUNTS)
    for key in METRIC_RATIOS:
        value = retained[key]
        if value is not None and (type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1):
            raise ValueError(f'invalid public ratio {key}')
        output[key] = value
    output.update(independent_attack_count=None, attack_stage_completeness=None,
        first_loss_counts=_counts(evaluation['first_loss_counts'], (*STAGES, 'surviving')),
        subgraph_stage_counts={s: _counts(evaluation['stages'][s], ('complete_subgraphs',))['complete_subgraphs'] for s in STAGES},
        event_stage_counts={s: _counts(evaluation['stages'][s], ('retained_reference_events',))['retained_reference_events'] for s in STAGES})
    return output


def _unavailable(value):
    return {key: None if isinstance(item, (int, float)) and not isinstance(item, bool)
            else item for key, item in value.items()}


def _check_export_event(event, frozen):
    """IDs alone cannot bind the causal graph shown by a local export."""
    fields = ('src', 'dst', 'relation')
    if any(base._identity(event.get(key)) != base._identity(frozen[key]) for key in fields):
        raise ValueError('local export event structure differs from frozen candidate')
    timestamp = event.get('timestamp_ns')
    if (not isinstance(timestamp, str) or not re.fullmatch(r'-?\d+', timestamp)
            or int(timestamp) != int(frozen['timestamp_ns'])):
        raise ValueError('local export event structure has a different or inexact timestamp')
    if str(event.get('host') or '').strip().upper() != str(frozen.get('host') or '').strip().upper():
        raise ValueError('local export event structure has a different host')
    a, b = (frozen['dst'], frozen['src']) if str(frozen['relation']).upper() == 'EVENT_EXECUTE' else (frozen['src'], frozen['dst'])
    if (base._identity(event.get('causal_src')) != base._identity(a)
            or base._identity(event.get('causal_dst')) != base._identity(b)):
        raise ValueError('local export event structure has different causal endpoints')


def evaluate_run(run_root, base_report, *, catalog=None, local_output=None, allow_partial=False):
    if type(allow_partial) is not bool:
        raise ValueError('allow_partial must be boolean')
    prior_hash = digest(base_report)
    watched = {Path(base_report).resolve(): prior_hash}
    for path in (Path(__file__), Path(derive_reference_subgraphs.__code__.co_filename),
                 Path(base.__file__), Path(derive_reference_chains.__code__.co_filename),
                 Path(base.evaluate_chains.__code__.co_filename),
                 base.ROOT/'configs/chain_workbench_v2.json'):
        watched[path.resolve()] = digest(path)
    watched.update({path: digest(path) for path in Path(run_root).glob('*/case.json')})
    requests = _catalog_requests(catalog, local_output, watched, run_root)
    validated = base._validate_all(run_root)
    prior, actual_prior_hash = _read(base_report)
    if actual_prior_hash != prior_hash:
        raise ValueError('base report changed during global validation')
    if prior.get('schema_version') != 'chain-workbench-v2-report':
        raise ValueError('a completed v2 base report is required')
    config = base._json(base.ROOT/'configs/chain_workbench_v2.json')
    expected_cases = {c['id'] for c in config['cases']}
    completed = {c['id'] for _, c, *_ in validated}
    missing = sorted(expected_cases-completed)
    if completed-expected_cases or (missing and not allow_partial):
        raise ValueError('registered cases are missing or unregistered; complete the full matrix')
    cases = _unique(prior['cases'], lambda c: c['id'], 'case')
    if (set(cases) != completed or prior.get('completed_cases') != len(completed)
            or prior.get('partial_evaluation') is not bool(missing)):
        raise ValueError('base report case matrix differs from frozen run')
    expected_provenance = {
        'evaluator_sha256': digest(base.__file__),
        'chain_evaluation_sha256': digest(base.evaluate_chains.__code__.co_filename),
        'reference_derivation_sha256': digest(derive_reference_chains.__code__.co_filename),
        'registration_config_sha256': digest(base.ROOT/'configs/chain_workbench_v2.json'),
    }
    if any(prior.get('evaluation_provenance', {}).get(k) != v for k, v in expected_provenance.items()):
        raise ValueError('base report evaluation provenance differs from current frozen implementation')
    # The expected manifest hashes come from the already validated case records,
    # never from rereading a potentially changed manifest after validation.
    manifest_hashes = {}
    for folder, case, registration, variants, _ in validated:
        watched[folder/'registration.json'] = case['registration_sha256']
        watched[Path(registration['data_root'])/registration['case']['ledger']] = registration['ledger_sha256']
        for item in case['variants']:
            manifest_hashes[(folder/item['path']).resolve()] = item['manifest_sha256']
        for directory, manifest in variants:
            watched[directory/'manifest.json'] = manifest_hashes[directory.resolve()]
            watched.update({directory/name: sha for name, sha in manifest['artifacts'].items()})
    _unchanged(watched)
    report = {'schema_version': 'chain-subgraph-report-v1', 'data_visibility': 'aggregate_only',
              'base_report_sha256': prior_hash, 'registered_cases': len(expected_cases),
              'completed_cases': len(completed), 'missing_case_ids': missing,
              'partial_evaluation': bool(missing), 'methods': dict(METHODS),
              'data_readiness': base._public_readiness(config),
              'evaluation_provenance': {'adapter_sha256': digest(__file__),
                  'subgraph_core_sha256': digest(derive_reference_subgraphs.__code__.co_filename),
                  **expected_provenance},
              'methodology': {'selection_recomputed': False, 'split': 'development',
                  'all_frozen_artifacts_validated_before_references': True,
                  'component_scope': 'fixed_observed_positive_subgraphs_not_complete_attacks',
                  'terminal_scope': 'fixed_reference_topology_not_semantic_attack_stages',
                  'reachability_graph': 'full_feasible_transition_dag_after_vertex_deletion',
                  'native_excludes_synthetic_lineage': True,
                  'verified_attack_subgraph_count': None}, 'cases': []}
    audits, matched, source_snapshots = {}, set(), []
    for folder, case, registration, variants, _ in validated:
        old = cases[case['id']]
        if old.get('registration_sha256') != case['registration_sha256']:
            raise ValueError('base report registration mismatch')
        positives, status, metadata = base._load_reference(registration)
        if old.get('reference_sha256') != metadata['reference_sha256'] or old.get('annotation_status') != status:
            raise ValueError('base report reference differs from current reference')
        if metadata['reference_sha256'] is not None:
            path = base._inside(base.ROOT, registration['case']['reference']['path'])
            watched[path] = metadata['reference_sha256']
        database = Path(registration['data_root'])/registration['case']['database']
        rows = [] if positives is None else load_source_events(database, positives)
        chains, diagnostics = derive_reference_chains(rows, 'registered_positive_subgraph')
        snapshot = None if positives is None else diagnostics['source_positive_graph_sha256']
        if snapshot != old.get('source_positive_snapshot_sha256'):
            raise ValueError('base report source reference snapshot differs')
        source_snapshots.append((database, positives, snapshot))
        source_ids = {r['event_id'] for r in rows}
        source_rows_by_id = {r['event_id']: r for r in rows}
        source_display = {r['event_id']: {k: r[k] for k in
                          ('src_semantic', 'dst_semantic', 'src_type', 'dst_type') if k in r}
                          for r in rows}
        models = {scope: derive_reference_subgraphs(rows, include_synthetic=include)
                  for scope, include in SCOPES.items()}
        summaries = {scope: _summary(model['summary']) if positives is not None else _unavailable(_summary(model['summary']))
                     for scope, model in models.items()}
        public = {'id': case['id'], 'label': case['id'].upper(), 'provider': case['provider'],
                  'annotation_status': status, 'split': 'development',
                  'reference_sha256': metadata['reference_sha256'],
                  'source_positive_snapshot_sha256': snapshot,
                  'registration_sha256': case['registration_sha256'],
                  'positive_count': None if positives is None else len(positives),
                  'source_missing_positive_events': None if positives is None else len(positives-source_ids),
                  'reference_summaries': summaries, 'variants': []}
        old_variants = _unique(old['variants'], lambda v: (v['track'], v['poi_policy']), 'variant')
        if set(old_variants) != {(m['track'], m['poi_policy']) for _, m in variants}:
            raise ValueError('base report variant matrix mismatch')
        for directory, manifest in variants:
            track, policy = manifest['track'], manifest['poi_policy']
            previous = old_variants[(track, policy)]
            old_points = _unique(previous['rows'], lambda p: (p['method'], p['budget']), 'point')
            if set(old_points) != {(m, b) for m in METHODS for b in manifest['budgets']}:
                raise ValueError('base report decision matrix mismatch')
            variant = {'track': track, 'poi_policy': policy, 'candidate_events': manifest['candidate_events'],
                       'source_scope_events': case['source_scope_events'], 'poi_count': manifest['poi_count'], 'rows': []}
            candidates = read_gzip(directory/'candidates.json.gz')
            positions = {base._identity(row['event_id']): i for i, row in enumerate(candidates)
                         if positives is not None and base._identity(row['event_id']) in positives}
            candidate_ids = source_ids & positions.keys()
            for event_id in candidate_ids:
                source_row, candidate_row = source_rows_by_id[event_id], candidates[positions[event_id]]
                if (any(base._identity(source_row[k]) != base._identity(candidate_row[k])
                        for k in ('src', 'dst', 'relation'))
                        or int(source_row['timestamp_ns']) != int(candidate_row['timestamp_ns'])
                        or str(source_row.get('host') or '').strip().upper() != str(candidate_row.get('host') or '').strip().upper()):
                    raise ValueError('source and candidate event structure differ for a reference identity')
            with np.load(directory/'decisions.npz', allow_pickle=False) as decisions, np.load(directory/'eligibility.npz', allow_pickle=False) as eligibility:
                for method in METHODS:
                    eligible = eligibility[method]
                    temporal = {event for event in candidate_ids if eligible[positions[event]]}
                    for budget in manifest['budgets']:
                        mask = decisions[f'{method}@{budget}']
                        retained = {event for event in temporal if mask[positions[event]]}
                        retained_count = int(mask.sum())
                        compression = 1-retained_count/manifest['candidate_events']
                        fixed_compression = 1-retained_count/case['source_scope_events']
                        old_point = old_points[(method, budget)]
                        if (old_point['retained_events'] != retained_count
                                or old_point['compression'] != compression
                                or old_point['fixed_scope_compression'] != fixed_compression):
                            raise ValueError('base report point differs from actual frozen decision')
                        if positives is not None:
                            chain_count = sum(set(c['event_ids']) <= retained for c in chains)
                            if (old_point['reference_chain_count'] != len(chains)
                                    or old_point['retained_reference_chains'] != chain_count):
                                raise ValueError('base report reference path metrics differ from actual frozen decision')
                        stages = dict(zip(STAGES, (source_ids, candidate_ids, temporal, retained)))
                        key = (case['id'], track, policy, method, budget)
                        detailed = key in requests
                        evaluations = {scope: evaluate_subgraphs(model, stages, detail=detailed)
                                       for scope, model in models.items()}
                        metrics = {scope: _metrics(ev) for scope, ev in evaluations.items()}
                        if positives is None:
                            metrics = {scope: {k: None for k in values} for scope, values in metrics.items()}
                        variant['rows'].append({'method': method, 'budget': budget,
                            'retained_events': retained_count, 'compression': compression,
                            'fixed_scope_compression': fixed_compression, 'scopes': metrics})
                        if detailed:
                            expected_rows = {base._identity(candidates[i]['event_id']): candidates[i]
                                             for i in np.flatnonzero(mask)}
                            expected_ids = set(expected_rows)
                            for request in requests[key]:
                                artifact = request['artifact']
                                if artifact.get('source_manifest_sha256') != manifest_hashes[directory.resolve()]:
                                    raise ValueError('local export source manifest mismatch')
                                actual_ids = [base._identity(e['event_id']) for e in artifact['events']]
                                if len(actual_ids) != len(set(actual_ids)) or set(actual_ids) != expected_ids:
                                    raise ValueError('local export events differ from exact frozen mask')
                                for event in artifact['events']:
                                    _check_export_event(event, expected_rows[base._identity(event['event_id'])])
                                audit = {'schema_version': 'chain-subgraph-audit-v1',
                                    **dict(zip(('case_id', 'track', 'poi_policy', 'method', 'budget_edges'), key)),
                                    'source_manifest_sha256': manifest_hashes[directory.resolve()],
                                    'reference_sha256': metadata['reference_sha256'],
                                    'source_positive_snapshot_sha256': snapshot,
                                    'base_report_sha256': prior_hash, 'annotation_status': status,
                                    'source_missing_positive_events': public['source_missing_positive_events'],
                                    'independent_attack_count': None, 'selection_recomputed': False,
                                    'offline_annotation_overlay': True, 'scopes': {}}
                                for scope, ev in evaluations.items():
                                    detail = dict(ev)
                                    detail['summary'] = summaries[scope]
                                    if positives is None:
                                        detail['stages'] = {s: {k: None for k in values} for s, values in ev['stages'].items()}
                                        detail['first_loss_counts'] = None
                                    detail['events'] = [{**r, **source_display[r['event_id']],
                                        'timestamp_ns': str(r['timestamp_ns']),
                                        'retained': r['event_id'] in retained,
                                        'candidate_present': r['event_id'] in candidate_ids,
                                        'temporal_eligible': r['event_id'] in temporal}
                                        for r in models[scope]['events']]
                                    audit['scopes'][scope] = detail
                                audits[request['id']] = audit
                            matched.add(key)
            del candidates
            public['variants'].append(variant)
        report['cases'].append(public)
        print(f"Subgraph metrics ready: {case['id']}", flush=True)
    if matched != set(requests):
        raise ValueError('catalog contains decisions outside this frozen run')
    # Check bound bytes again, including references and the optional local exports.
    _unchanged(watched)
    for database, positives, snapshot in source_snapshots:
        if positives is not None:
            _, current = derive_reference_chains(load_source_events(database, positives), 'registered_positive_subgraph')
            if current['source_positive_graph_sha256'] != snapshot:
                raise ValueError('source reference snapshot changed during evaluation')
    canonical(report)
    if local_output is not None:
        destination = Path(local_output)
        destination.mkdir(parents=True, exist_ok=False)
        for name, audit in audits.items():
            write_json(destination/(name+'.json'), audit)
    return report


def write_flat_csv(report, path):
    records = []
    for case in report['cases']:
        for variant in case['variants']:
            for point in variant['rows']:
                for scope, metrics in point['scopes'].items():
                    record = {k: case[k] for k in ('id', 'provider', 'annotation_status')}
                    record.update({k: variant[k] for k in ('track', 'poi_policy', 'candidate_events', 'source_scope_events')})
                    record.update({k: v for k, v in point.items() if k != 'scopes'})
                    record.update(scope=scope)
                    for key, value in metrics.items():
                        if isinstance(value, dict):
                            record.update({f'{key}_{stage}': number for stage, number in value.items()})
                        else:
                            record[key] = value
                    records.append(record)
    fields = list(dict.fromkeys(k for record in records for k in record))
    with Path(path).open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator='\n')
        writer.writeheader(); writer.writerows(records)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('input', 'base-report', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--catalog', type=Path)
    parser.add_argument('--local-output', type=Path)
    parser.add_argument('--allow-partial', action='store_true')
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.with_suffix('.csv').exists():
        raise FileExistsError('subgraph aggregate output must be new')
    report = evaluate_run(args.input, args.base_report, catalog=args.catalog,
                          local_output=args.local_output, allow_partial=args.allow_partial)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_flat_csv(report, args.output.with_suffix('.csv'))
    write_json(args.output, report)
    print(json.dumps({'completed_cases': report['completed_cases'], 'output': str(args.output)}))


if __name__ == '__main__':
    main()
