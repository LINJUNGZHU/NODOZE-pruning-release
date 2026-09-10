"""Publish same-configuration RASP-D development comparisons, not datasets."""
import argparse
import json
from pathlib import Path
from scripts.run_rasp import write_json


def publish(reports, cache_path):
    cache = json.loads(cache_path.read_text())
    main = cache['rasp_diverse_experiment']
    cases = []
    for name, path in reports:
        report = json.loads(Path(path).read_text())
        for key in ('config', 'scoring_config', 'implementation_sha256'):
            if report[key] != main[key]:
                raise ValueError(f'{name}: inconsistent {key}')
        if report['ground_truth_used_for_selection'] or any(r['lost_fork_connections'] or r['retained_edges'] > r['budget_edges'] for r in report['results']):
            raise ValueError(f'{name}: invalid experiment')
        cases.append(dict(report, case=name))
    cache['rasp_diverse_validation'] = cases
    write_json(cache_path, cache)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', nargs=2, action='append', required=True, metavar=('NAME', 'REPORT'))
    parser.add_argument('--cache', type=Path, default=Path('webapp/runtime/theia-case3-demo.json'))
    args = parser.parse_args()
    publish(args.case, args.cache)
