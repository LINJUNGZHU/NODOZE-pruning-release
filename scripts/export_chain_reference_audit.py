"""Local-only fixed-reference chain details, after global frozen validation.

This is an offline annotation overlay. It never changes retained decisions.
The deterministic source-positive paths may overlap and exclude singletons;
their count is not the number of attacks or all possible causal paths.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np

from scripts import evaluate_chain_workbench as evaluator
from scripts.adaptive_chain_inputs import derive_reference_chains, load_source_events
from tc_pruning.chain_evaluation import evaluate_chains
from tc_pruning.chain_workbench import digest, read_gzip, write_json


class ReferenceAuditExporter:
    def __init__(self, run_root):
        # All variants, including those not requested for export, are checked
        # before the first reference file can be opened.
        validated = evaluator._validate_all(run_root)
        self.cases = {case['id']: (registration, variants)
                      for _, case, registration, variants, _ in validated}
        self.manifest_hashes = {(folder/variant['path']).resolve():variant['manifest_sha256']
                               for folder, case, _, _, _ in validated for variant in case['variants']}
        self.references = {}

    def export(self, case_id, track, poi_policy, method, budget, output):
        output = Path(output)
        if output.exists():
            raise FileExistsError('reference audit output must be new')
        if case_id not in self.cases:
            raise ValueError('case was not frozen in this run')
        registration, variants = self.cases[case_id]
        choice = next(((directory, manifest) for directory, manifest in variants
                       if manifest['track'] == track and manifest['poi_policy'] == poi_policy), None)
        if choice is None:
            raise ValueError('variant was not frozen')
        directory, manifest = choice
        if type(budget) is not int or budget not in manifest['budgets'] or method not in manifest['methods']:
            raise ValueError('exact method and integer budget must have been frozen')
        # Recheck file hashes after global validation, before opening labels.
        def unchanged():
            if (digest(directory/'manifest.json') != self.manifest_hashes[directory]
                    or any(digest(directory/name) != expected for name, expected in manifest['artifacts'].items())):
                raise ValueError('frozen artifact changed after validation')
        unchanged()
        if case_id not in self.references:
            positives, status, reference_metadata = evaluator._load_reference(registration)
            reference_hash = reference_metadata['reference_sha256']
            spec = registration['case']
            rows = [] if positives is None else load_source_events(Path(registration['data_root'])/spec['database'], positives)
            chains, diagnostics = derive_reference_chains(rows, 'registered_positive_subgraph')
            self.references[case_id] = (positives, status, rows, chains, diagnostics, reference_hash)
        positives, status, rows, chains, diagnostics, reference_hash = self.references[case_id]
        audit = {'schema_version':'chain-workbench-reference-audit-v1',
                 'case_id':case_id, 'track':track, 'poi_policy':poi_policy,
                 'method':method, 'budget_edges':budget,
                 'source_manifest_sha256':self.manifest_hashes[directory],
                 'reference_sha256':reference_hash,
                 'source_positive_graph_sha256':diagnostics['source_positive_graph_sha256'],
                 'annotation_status':status,
                 'scope':'source_positive_subgraph_witnesses_not_complete_attacks',
                 'verified_attack_chain_count':None,
                 'selection_recomputed':False, 'offline_annotation_overlay':True,
                 'counts':{key:None for key in ('reference_chains','retained_reference_chains',
                                              'covered_positive_events','singleton_positive_events')},
                 'chains':[], 'events':[]}
        if positives is not None:
            candidates = read_gzip(directory/'candidates.json.gz')
            positions = {str(row['event_id']).strip().upper():index for index,row in enumerate(candidates)
                         if str(row['event_id']).strip().upper() in positives}
            del candidates
            with np.load(directory/'decisions.npz', allow_pickle=False) as data:
                mask = data[f'{method}@{budget}']
            with np.load(directory/'eligibility.npz', allow_pickle=False) as data:
                eligible = data[method]
            source = {row['event_id'] for row in rows}
            candidate = source & positions.keys()
            temporal = {event for event in candidate if eligible[positions[event]]}
            retained = {event for event in temporal if mask[positions[event]]}
            evaluation = evaluate_chains(chains, rows, {'source':source, 'candidate':candidate,
                'temporal_eligible':temporal, 'retained':retained})
            audit['counts'] = {'reference_chains':len(chains),
                'retained_reference_chains':evaluation['stages']['retained']['reference_chain_count'],
                'covered_positive_events':diagnostics['covered_event_count'],
                'singleton_positive_events':diagnostics['singleton_count']}
            audit['chains'] = [{'id':chain['id'], 'event_ids':chain['event_ids'],
                'status':'complete' if chain['stages']['retained']['complete'] else 'broken',
                'first_loss_stage':chain['first_loss_stage'] or 'surviving',
                'missing_event_ids':chain['stages']['retained']['missing_ids']}
                for chain in evaluation['chains']]
            for row in rows:
                event = {key:row[key] for key in ('event_id','src','dst','src_semantic','dst_semantic','relation')}
                a,b = (row['dst'],row['src']) if row['relation'].upper() == 'EVENT_EXECUTE' else (row['src'],row['dst'])
                event.update(timestamp_ns=str(int(row['timestamp_ns'])), causal_src=a, causal_dst=b,
                    retained=row['event_id'] in retained, candidate_present=row['event_id'] in candidate,
                    temporal_eligible=row['event_id'] in temporal)
                audit['events'].append(event)
        unchanged()
        output.parent.mkdir(parents=True, exist_ok=True)
        write_json(output, audit)
        return audit


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('input','output'):
        parser.add_argument('--'+name, type=Path, required=True)
    for name in ('case','track','poi-policy','method'):
        parser.add_argument('--'+name, required=True)
    parser.add_argument('--budget', type=int, required=True)
    args = parser.parse_args(argv)
    audit = ReferenceAuditExporter(args.input).export(args.case, args.track, args.poi_policy,
                                                     args.method, args.budget, args.output)
    print(audit['counts'])


if __name__ == '__main__':
    main()
