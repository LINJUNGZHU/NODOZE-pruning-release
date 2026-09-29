"""Validate every frozen variant before loading references; publish aggregates only.

Usage: python -m scripts.evaluate_chain_workbench --input RUNROOT --output REPORT.json
The companion CSV contains the same scalar aggregates. References are fixed
source-positive-subgraph witnesses, never independently complete attack truth.
Local critical subsets contain positives only; unlabelled events are not negatives.
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

from scripts.adaptive_chain_inputs import derive_reference_chains, load_source_events
from tc_pruning.chain_evaluation import evaluate_chains, evaluate_event_funnel
from tc_pruning.chain_workbench import ROOT, METHODS, canonical, digest, read_gzip, validate_variant, write_json

_STAGES = ('source', 'candidate', 'temporal_eligible', 'retained')
_PROVIDERS = {'CADETS', 'THEIA', 'TRACE', 'FIVEDIRECTIONS'}
_POLICIES = {'single', 'declared', 'adaptive'}
_TRACKS = {'base', 'expanded'}
_POINT_RESOURCES = {'unused_budget': 'count', 'anchor_limit_reached': 'bool',
                    'truncated_bundles': 'count', 'retained_complete_bundles': 'count',
                    'fallback_witnesses': 'count'}


def _json(path):
    return json.loads(Path(path).read_text())


def _identity(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError('reference identities must be nonempty strings')
    return value.strip().upper()


def _ids(values):
    if not isinstance(values, list):
        raise ValueError('reference identities must be a list')
    return {_identity(value) for value in values}


def _count(value, label, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError(f'{label} must be an integer >= {minimum}')
    return value


def _optional_resource(mapping, key, kind='number'):
    """Copy only a named finite, nonnegative scalar; never infer missing data."""
    value = mapping.get(key)
    if value is None:
        return None
    if kind == 'bool':
        if type(value) is not bool:
            raise ValueError(f'resource {key} must be boolean')
    elif kind == 'count':
        _count(value, f'resource {key}')
    elif type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError(f'resource {key} must be finite and nonnegative')
    return value


def _point_resources(diagnostic):
    return {key: _optional_resource(diagnostic, key, kind) for key, kind in _POINT_RESOURCES.items()}


def _inside(root, value):
    root = Path(root).resolve()
    path = (root / value).resolve()
    if not path.is_relative_to(root):
        raise ValueError('artifact/reference path escapes its registered directory')
    return path


def _validate_all(run_root):
    """Finish global validation without opening any evaluation reference."""
    run_root = Path(run_root)
    # The runner creates its case directory before historical inputs are ready
    # and registration.json is written. Treat that earlier lifecycle state as
    # unfinished too; unrelated exports/figures directories are not cases.
    registry = _json(ROOT / 'configs/chain_workbench_v2.json')
    for registered in registry['cases']:
        directory = _inside(run_root, registered['id'])
        if directory.exists() and not (directory / 'case.json').is_file():
            raise ValueError('unfinished registered case directory: case.json is absent; evaluation must wait')
    if any(not (path.parent / 'case.json').is_file() for path in run_root.glob('*/registration.json')):
        raise ValueError('unfinished registered case: case.json is absent; evaluation must wait')
    paths = sorted(run_root.glob('*/case.json'))
    if not paths:
        raise ValueError('input contains no completed case.json artifacts')
    validated, seen = [], set()
    for case_path in paths:
        folder = case_path.parent
        case = _json(case_path)
        case_id = case.get('id')
        if (not isinstance(case_id, str) or not re.fullmatch(r'[a-z][a-z0-9-]{1,63}', case_id)
                or case_id in seen):
            raise ValueError('case identities must be unique public registration identifiers')
        seen.add(case_id)
        if case.get('schema_version') != 'chain-workbench-case-v2' or case.get('labels_used') is not False or case.get('split') != 'development':
            raise ValueError('invalid completed case contract')
        _optional_resource(case, 'elapsed_seconds')
        _optional_resource(case, 'peak_rss_mib')
        registration_path = folder / 'registration.json'
        if digest(registration_path) != case.get('registration_sha256'):
            raise ValueError('registration hash mismatch')
        registration = _json(registration_path)
        if registration.get('schema_version') != 'chain-workbench-case-registration-v2' or registration.get('labels_opened') is not False:
            raise ValueError('invalid registration contract')
        spec, config = registration['case'], registration['config']
        if spec['id'] != case_id or spec['provider'] != case['provider'] or case['provider'] not in _PROVIDERS:
            raise ValueError('registration case/provider mismatch')
        fixed_scope = _count(case['source_scope_events'], 'source_scope_events', 1)
        ledger_hash = registration['ledger_sha256']
        if digest(Path(registration['data_root']) / spec['ledger']) != ledger_hash:
            raise ValueError('registered source ledger hash mismatch')
        config_hash = hashlib.sha256(canonical(config)).hexdigest()
        expected = {(track, policy) for track in (['base', 'expanded'] if spec.get('expand_window') else ['base'])
                    for policy in config['poi_policies']}
        if not expected or any(track not in _TRACKS or policy not in _POLICIES for track, policy in expected):
            raise ValueError('invalid registered variant matrix')
        actual, variants, original = set(), [], None
        track_fingerprints, track_graphs, history_identity = {}, {}, None
        for variant in case['variants']:
            pair = (variant['track'], variant['poi_policy'])
            if pair in actual or pair not in expected:
                raise ValueError('duplicate or unexpected variant')
            actual.add(pair)
            directory = _inside(folder, variant['path'])
            manifest_path = directory / 'manifest.json'
            if digest(manifest_path) != variant['manifest_sha256']:
                raise ValueError('variant manifest hash mismatch')
            manifest = _json(manifest_path)
            _optional_resource(manifest, 'online_seconds')
            if (manifest['case_id'], manifest['track'], manifest['poi_policy']) != (case_id, *pair):
                raise ValueError('manifest case/track/POI mismatch')
            provenance = manifest['provenance']
            if provenance['ledger_sha256'] != ledger_hash or provenance['config_sha256'] != config_hash:
                raise ValueError('manifest registration provenance hash mismatch')
            if provenance['fixed_scope_events'] != fixed_scope or manifest['candidate_events'] > fixed_scope:
                raise ValueError('fixed candidate scope differs between variants')
            declared = _ids(provenance['original_declared_event_ids'])
            if not declared or (original is not None and declared != original):
                raise ValueError('original declared POI denominator differs between variants')
            original = declared
            check = validate_variant(directory)
            for diagnostic in manifest['diagnostics'].values():
                if _optional_resource(diagnostic, 'selection_seconds') is None:
                    raise ValueError('frozen selection duration must be present')
                _point_resources(diagnostic)
            for key in ('valid', 'candidate_events', 'decision_points', 'poi_count'):
                if variant.get(key) != check[key]:
                    raise ValueError('case summary differs from validated variant')
            current_history = (manifest['artifacts']['history.json.gz'], manifest['cutoff_ns'])
            if history_identity is not None and current_history != history_identity:
                raise ValueError('history identity/cutoff must be shared across tracks and POI policies')
            history_identity = current_history
            candidates = read_gzip(directory / 'candidates.json.gz')
            fingerprint = hashlib.sha256()
            track = manifest['track']
            first_for_track = track not in track_graphs
            graph = {} if first_for_track else None
            declared_times = {}
            actual_pois = set()
            for row in candidates:
                event = _identity(row['event_id'])
                # Only the policy-specific POI flag may differ. This binds the
                # complete observed structure, semantics, and legacy evidence.
                encoded = canonical({key: value for key, value in row.items() if key != 'is_declared_poi'})
                fingerprint.update(encoded + b'\n')
                if graph is not None:
                    graph[event] = hashlib.sha256(encoded).digest()
                if event in declared:
                    declared_times[event] = (int(row['timestamp_ns']), str(row['event_id']))
                if row['is_declared_poi']:
                    actual_pois.add(event)
            del candidates
            if set(declared_times) != declared:
                raise ValueError('original declared POIs must be present in every candidate graph')
            earliest = min(declared, key=lambda event: declared_times[event])
            if manifest['poi_policy'] == 'declared' and actual_pois != declared:
                raise ValueError('declared POI policy differs from registered original declarations')
            if manifest['poi_policy'] == 'single' and actual_pois != {earliest}:
                raise ValueError('single POI policy must select the earliest original declaration')
            if manifest['poi_policy'] == 'adaptive' and earliest not in actual_pois:
                raise ValueError('adaptive POI policy must preserve its earliest original seed')
            if first_for_track:
                track_graphs[track] = graph
                track_fingerprints[track] = fingerprint.digest()
            elif fingerprint.digest() != track_fingerprints[track]:
                raise ValueError('candidate structure/evidence differs between POI policies')
            variants.append((directory, manifest))
        if actual != expected:
            raise ValueError('incomplete registered variant matrix')
        if 'expanded' in track_graphs:
            base_graph, expanded_graph = track_graphs['base'], track_graphs['expanded']
            if any(event not in expanded_graph or expanded_graph[event] != row_hash
                   for event, row_hash in base_graph.items()):
                raise ValueError('expanded graph must preserve every base event and its evidence')
        union_size = len(set().union(*(graph.keys() for graph in track_graphs.values())))
        if fixed_scope != union_size or fixed_scope != max(len(graph) for graph in track_graphs.values()):
            raise ValueError('fixed scope must equal the registered largest candidate union')
        validated.append((folder, case, registration, variants, original))
    return validated


def _load_reference(registration):
    """Return (positive_ids_or_none, status, metadata) after global validation.

    Metadata always contains reference_kind and reference_sha256; local subset
    metadata also contains reference_case_index. Parse and digest the same bytes.
    """
    spec = registration['case']
    reference = spec['reference']
    kind = reference['kind']
    if kind == 'unavailable':
        return None, 'unavailable', {'reference_kind': kind, 'reference_sha256': None}
    path = _inside(ROOT, reference['path'])
    contents = path.read_bytes()
    reference_hash = hashlib.sha256(contents).hexdigest()
    metadata = {'reference_kind': kind, 'reference_sha256': reference_hash}
    value = json.loads(contents)
    if kind == 'captain_events':
        annotation_metadata = value.get('metadata', {})
        if (annotation_metadata.get('groundtruth_family') != 'CAPTAIN/human_readable_gt'
                or spec['id'] not in {'cadets06', 'cadets12', 'cadets13'}
                or annotation_metadata.get('scenario') != spec['id'][-2:]):
            raise ValueError('CAPTAIN family/scenario does not match registered case')
        return _ids(value['attack_event_ids']), 'captain_event_pattern_reference', metadata
    if kind == 'local_critical_subset':
        index = _count(reference['case_index'], 'reference case_index')
        if value.get('protocol') != 'sparse-local-critical-edge-reference-v1' or index >= len(value.get('cases', [])):
            raise ValueError('invalid local critical reference protocol/index')
        case = value['cases'][index]
        if case.get('ledger_sha256') is not None and case['ledger_sha256'] != registration['ledger_sha256']:
            raise ValueError('local critical reference ledger hash mismatch')
        return _ids(case['critical_event_ids']), 'local_critical_partial_reference', {**metadata, 'reference_case_index': index}
    raise ValueError('unsupported registered reference kind')


def _ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def _unavailable_metrics():
    return {key: None for key in (
        'reference_chain_count', 'retained_reference_chains', 'reference_chain_retention',
        'positive_count', 'retained_positive_events', 'positive_retention',
        'incremental_positive_count', 'retained_incremental_positives', 'incremental_retention',
        'source_positive_events', 'candidate_positive_events', 'temporal_positive_events',
        'source_missing_positive_events', 'synthetic_lineage_positive_count',
        'retained_synthetic_lineage_positives', 'candidate_known_positive_events',
        'retained_source_positive_events', 'first_loss_counts', 'event_first_loss_counts',
        'chain_stage_counts', 'positive_stage_counts')}


def _evaluate_case(case, registration, variants, original_declared):
    positives, status, reference_metadata = _load_reference(registration)
    reference_hash = reference_metadata['reference_sha256']
    reference_summary = {'chain_count': None, 'covered_positive_events': None, 'singleton_positive_events': None,
                         'min_chain_events': None, 'max_chain_events': None, 'paths_are_exhaustive': False,
                         'paths_containing_synthetic_lineage': None, 'independent_attack_count': None}
    source_graph_hash = None
    if positives is not None:
        database = Path(registration['data_root']) / registration['case']['database']
        source_rows = load_source_events(database, positives)
        source_ids = {_identity(row['event_id']) for row in source_rows}
        # Fixed once from the source, never re-derived after candidate pruning.
        chains, derived = derive_reference_chains(source_rows, 'registered_positive_subgraph')
        paths = [chain['event_ids'] for chain in chains]
        covered = {event for path in paths for event in path}
        lengths = [len(path) for path in paths]
        reference_summary.update({
            'chain_count': len(chains), 'covered_positive_events': len(covered),
            'singleton_positive_events': len(source_ids - covered),
            'min_chain_events': min(lengths) if lengths else None,
            'max_chain_events': max(lengths) if lengths else None,
            'paths_containing_synthetic_lineage': sum(any('LINEAGE' in event for event in path) for path in paths),
        })
        if (derived['reference_chain_count'] != len(chains) or derived['covered_event_count'] != len(covered)
                or derived['singleton_count'] != len(source_ids - covered)
                or derived['exhaustive_path_enumeration'] is not False):
            raise ValueError('derived reference coverage diagnostics differ from actual fixed paths')
        source_graph_hash = derived['source_positive_graph_sha256']
        if not isinstance(source_graph_hash, str) or not re.fullmatch(r'[0-9a-f]{64}', source_graph_hash):
            raise ValueError('invalid canonical source-positive graph hash')
        incremental = positives - original_declared
        synthetic = {event for event in positives if 'LINEAGE' in event}
    else:
        source_rows, source_ids, chains, incremental, synthetic = [], set(), [], set(), set()
    public = {'id': case['id'], 'label': case['id'].upper(), 'provider': case['provider'],
              'split': 'development', 'annotation_status': status,
              'elapsed_seconds': _optional_resource(case, 'elapsed_seconds'),
              'peak_rss_mib': _optional_resource(case, 'peak_rss_mib'),
              'reference_sha256': reference_hash,
              'source_positive_snapshot_sha256': source_graph_hash,
              'source_positive_graph_sha256': source_graph_hash,
              'registration_sha256': case['registration_sha256'],
              'fixed_reference_summary': reference_summary,
              'reference_chain_scope': 'source_positive_subgraph_witnesses_not_complete_attacks',
              'variants': []}
    for directory, manifest in variants:
        n = manifest['candidate_events']
        fixed_scope = case['source_scope_events']
        # Only positive positions are needed after artifact validation. Avoid
        # allocating million-event ID sets for every method/budget point.
        positive_positions = {}
        if positives is not None:
            candidates = read_gzip(directory / 'candidates.json.gz')
            for index, row in enumerate(candidates):
                event = _identity(row['event_id'])
                if event in positives:
                    positive_positions[event] = index
            del candidates
        candidate_known_ids = set(positive_positions)
        result = {'track': manifest['track'], 'poi_policy': manifest['poi_policy'],
                  'candidate_events': n, 'poi_count': manifest['poi_count'],
                  'suggested_poi_count': len(manifest['poi_diagnostics'].get('suggested_event_ids', [])),
                  'source_scope_events': fixed_scope,
                  'candidate_scope_fraction': n / fixed_scope,
                  'online_seconds': _optional_resource(manifest, 'online_seconds'),
                  'history_event_count': manifest['history_count'],
                  'unknown_context_events': manifest['history_support']['unknown_context_events'],
                  'mean_history_confidence': manifest['history_support']['mean_confidence'],
                  'rows': []}
        with np.load(directory / 'eligibility.npz', allow_pickle=False) as eligibility, np.load(directory / 'decisions.npz', allow_pickle=False) as decisions:
            for method in METHODS:
                if positives is not None:
                    eligible = eligibility[method]
                    candidate_source_ids = candidate_known_ids & source_ids
                    temporal_source_ids = {event for event in candidate_source_ids if eligible[positive_positions[event]]}
                for budget in manifest['budgets']:
                    key = f'{method}@{budget}'
                    mask = decisions[key]
                    retained_events = int(mask.sum())
                    selected = {event for event, index in positive_positions.items() if mask[index]}
                    seconds = manifest['diagnostics'][key]['selection_seconds']
                    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not math.isfinite(seconds) or seconds < 0:
                        raise ValueError('invalid frozen selection duration')
                    point = {'method': method, 'budget': int(budget), 'retained_events': retained_events,
                             'compression': 1 - retained_events / n,
                             'fixed_scope_compression': 1 - retained_events / fixed_scope,
                             'selection_seconds': seconds, 'verified_attack_chain_retention': None,
                             **_point_resources(manifest['diagnostics'][key])}
                    if positives is None:
                        point.update(_unavailable_metrics())
                    else:
                        stages = {'source': source_ids, 'candidate': candidate_source_ids,
                                  'temporal_eligible': temporal_source_ids, 'retained': selected & temporal_source_ids}
                        chain_eval = evaluate_chains(chains, source_rows, stages)
                        funnel = evaluate_event_funnel(positives, stages)
                        retained = len(selected & positives)
                        retained_incremental = len(selected & incremental)
                        retained_chains = chain_eval['stages']['retained']['reference_chain_count']
                        point.update({
                            'reference_chain_count': len(chains), 'retained_reference_chains': retained_chains,
                            'reference_chain_retention': _ratio(retained_chains, len(chains)),
                            'positive_count': len(positives), 'retained_positive_events': retained,
                            'positive_retention': _ratio(retained, len(positives)),
                            'incremental_positive_count': len(incremental),
                            'retained_incremental_positives': retained_incremental,
                            'incremental_retention': _ratio(retained_incremental, len(incremental)),
                            'source_positive_events': len(source_ids),
                            'candidate_positive_events': len(candidate_source_ids),
                            'temporal_positive_events': len(temporal_source_ids),
                            'source_missing_positive_events': len(positives - source_ids),
                            'synthetic_lineage_positive_count': len(synthetic),
                            'retained_synthetic_lineage_positives': len(synthetic & selected),
                            'candidate_known_positive_events': len(candidate_known_ids),
                            'retained_source_positive_events': len(selected & source_ids),
                            'first_loss_counts': dict(chain_eval['first_loss_counts']),
                            'event_first_loss_counts': dict(funnel['first_loss_counts']),
                            'chain_stage_counts': {stage: chain_eval['stages'][stage]['reference_chain_count'] for stage in _STAGES},
                            'positive_stage_counts': {stage: funnel['stages'][stage]['retained_event_count'] for stage in _STAGES},
                        })
                    result['rows'].append(point)
        public['variants'].append(result)
    return public


def _public_readiness(config):
    # Descriptive text is registered project metadata, not copied source logs.
    reasons = {'available_partial_logs': 'Local partial logs are available; all registered cases are development data.',
               'annotation_only': 'Annotations are present but matching local raw events are unavailable; attack retention cannot be evaluated.'}
    providers = {'CADETS/THEIA/TRACE/FIVEDIRECTIONS', 'local annotation folders'}
    result = []
    for item in config.get('data_readiness', []):
        if item.get('dataset') not in {'E3', 'E5'} or item.get('status') not in reasons or item.get('provider') not in providers:
            raise ValueError('unregistered public data-readiness category')
        result.append({'dataset': item['dataset'], 'provider': item['provider'], 'status': item['status'], 'reason': reasons[item['status']]})
    return result


def evaluate_run(run_root, *, allow_partial=False):
    if type(allow_partial) is not bool:
        raise ValueError('allow_partial must be boolean')
    validated = _validate_all(run_root)
    # This config carries readiness categories, not event labels. References are
    # only opened by _evaluate_case after every frozen case has passed checks.
    config = _json(ROOT / 'configs/chain_workbench_v2.json')
    registered = {item['id']: item for item in config['cases']}
    if any(case['id'] not in registered or case['provider'] != registered[case['id']]['provider']
           for _, case, *_ in validated):
        raise ValueError('case/provider not registered for public aggregate output')
    completed = {case['id'] for _, case, *_ in validated}
    missing = sorted(set(registered) - completed)
    if missing and not allow_partial:
        raise ValueError('registered cases are missing; wait for the full matrix or explicitly use --allow-partial')
    report = {'schema_version': 'chain-workbench-v2-report', 'data_visibility': 'aggregate_only',
              'registered_cases': len(registered), 'completed_cases': len(completed),
              'missing_case_ids': missing, 'partial_evaluation': bool(missing),
              'evaluation_provenance': {
                  'evaluator_sha256': digest(__file__),
                  'chain_evaluation_sha256': digest(Path(evaluate_chains.__code__.co_filename)),
                  'reference_derivation_sha256': digest(Path(derive_reference_chains.__code__.co_filename)),
                  'registration_config_sha256': digest(ROOT / 'configs/chain_workbench_v2.json'),
                  'source_positive_snapshot_semantics': 'canonical_event_id_endpoints_relation_timestamp_host_in_derivation_order',
              },
              'methods': dict(METHODS), 'data_readiness': _public_readiness(config),
              'methodology': {'all_frozen_artifacts_validated_before_references': True,
                              'split': 'development',
                              'reference_chain_scope': 'source_positive_subgraph_witnesses_not_complete_attacks',
                              'incremental_denominator': 'fixed_positive_set_minus_original_declared_pois',
                              'unlabelled_event_policy': 'unknown_not_negative',
                              'fixed_scope_definition': 'registered_largest_candidate_union_not_full_database',
                              'source_stage_policy': 'stages_intersect_source_events; exact_positive_retention_reported_separately',
                              'verified_attack_chain_retention_available': False},
              'cases': [_evaluate_case(case, registration, variants, original)
                        for _, case, registration, variants, original in validated]}
    canonical(report)  # Reject NaN/infinity before any report file is written.
    return report


def write_flat_csv(report, path):
    records = []
    for case in report['cases']:
        for variant in case['variants']:
            base = {key: case[key] for key in ('id', 'provider', 'split', 'annotation_status')}
            base.update({key: case[key] for key in ('elapsed_seconds', 'peak_rss_mib', 'reference_sha256',
                                                   'source_positive_snapshot_sha256')})
            base.update({key: variant[key] for key in ('track', 'poi_policy', 'candidate_events', 'poi_count', 'source_scope_events')})
            base['online_seconds'] = variant['online_seconds']
            for point in variant['rows']:
                record = {**base, **{key: value for key, value in point.items() if not isinstance(value, dict)}}
                for prefix in ('first_loss_counts', 'event_first_loss_counts'):
                    for stage, count in (point.get(prefix) or {}).items():
                        record[f'{prefix}_{stage}'] = count
                records.append(record)
    fields = list(dict.fromkeys(key for record in records for key in record))
    with Path(path).open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader(); writer.writerows(records)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--allow-partial', action='store_true',
                        help='Explicitly evaluate completed selected cases; still reject any started unfinished case')
    args = parser.parse_args(argv)
    csv_path = args.output.with_suffix('.csv')
    if args.output.exists() or csv_path.exists():
        raise FileExistsError('aggregate output must be a new report and CSV')
    report = evaluate_run(args.input, allow_partial=args.allow_partial)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_json(args.output, report)
    write_flat_csv(report, csv_path)
    print(json.dumps({'cases': len(report['cases']), 'output': str(args.output)}))


if __name__ == '__main__':
    main()
