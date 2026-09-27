"""Attach resource repeats to independently verified immutable quality output."""
import argparse,gzip,json,statistics
from pathlib import Path
from tc_pruning.sparse_edge_evaluation import sha256_file


def read(path):
    with gzip.open(path,'rt') as f:return json.load(f)


def quartiles(values):
    q=statistics.quantiles(values,n=4,method='inclusive');return dict(median=statistics.median(values),q1=q[0],q3=q[2])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--quality-report',type=Path,required=True);p.add_argument('--input',type=Path,required=True);p.add_argument('--config',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():raise FileExistsError(a.output)
    report=json.loads(a.quality_report.read_text());cfg=json.loads(a.config.read_text());profiles=[]
    if report['protocol']!=cfg['protocol']:raise ValueError('wrong protocol')
    for case in cfg['cases']:
        i=case['case_index'];quality=read(a.input/'quality'/f'case{i}'/'manifest.json.gz')
        if quality['config_sha256']!=sha256_file(a.config):raise ValueError('quality config changed')
        for d in quality['decisions']:
            if sha256_file(Path(d['path']))!=d['sha256']:raise ValueError('verified decision changed')
        for pool in quality['pool_records']:
            if sha256_file(Path(pool['path']))!=pool['sha256']:raise ValueError('verified pool changed')
        repeats=[read(a.input/'profiles'/f'repeat{j}'/f'case{i}'/'manifest.json.gz') for j in range(cfg['profiling_repeats'])]
        for m in repeats:
            if m['source_sha256']!=quality['source_sha256'] or m['config_sha256']!=quality['config_sha256'] or m['ledger_sha256']!=quality['ledger_sha256'] or m['labels_used'] or not m['profile_only']:raise ValueError('repeat freeze mismatch')
            for d in m['decisions']:
                expected=next(q for q in quality['decisions'] if q['method']==d['method'] and q['budget']==d['budget'])
                for key in ('selected_events','trace','objective_value'):
                    if d.get(key)!=expected.get(key):raise ValueError('repeat output mismatch: '+key)
        timing=[]
        for method in cfg['methods']:
            for b in cfg['budgets']:
                values=[next(d['selection_seconds'] for d in m['decisions'] if d['method']==method and d['budget']==b) for m in repeats];q=quartiles(values)
                timing.append(dict(method=method,budget=b,median_seconds=q['median'],q1_seconds=q['q1'],q3_seconds=q['q3'],samples_seconds=values))
        elapsed=quartiles([m['elapsed_seconds'] for m in repeats]);rss=quartiles([m['peak_rss_mib'] for m in repeats])
        profiles.append(dict(case_index=i,repeats=len(repeats),whole_matrix_elapsed_median=elapsed['median'],whole_matrix_elapsed_quartiles=elapsed,whole_matrix_peak_rss_median=rss['median'],whole_matrix_peak_rss_quartiles=rss,selection=timing))
    report.update(profiles=profiles,verified_quality_report_sha256=sha256_file(a.quality_report),resource_merge_source_sha256=sha256_file(Path(__file__)),profile_identity_validation='counts/objectives/traces where emitted; methods without trace do not establish identical selected IDs')
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':main()
