"""Package executed decisions and manifests; large candidate pools stay local."""
import argparse,gzip,json,platform,shutil,subprocess
from pathlib import Path
import numpy as np,scipy
from tc_pruning.sparse_edge_evaluation import sha256_file


def read(path):
    with gzip.open(path,'rt') as f:return json.load(f)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--data-root',type=Path,required=True);p.add_argument('--config',type=Path,default=Path('configs/group_completion_v8.json'));a=p.parse_args()
    if a.output.exists():raise FileExistsError(a.output)
    a.output.mkdir(parents=True);records=[];cfg=json.loads(a.config.read_text())
    for case in cfg['cases']:
        i=case['case_index'];src=a.input/'quality'/f'case{i}';dest=a.output/'quality'/f'case{i}';dest.mkdir(parents=True)
        m=read(src/'manifest.json.gz')
        for entry in m['decisions']:
            file=Path(entry['path'])
            if sha256_file(file)!=entry['sha256']:raise ValueError('decision hash changed')
            (dest/'decisions').mkdir(exist_ok=True);shutil.copyfile(file,dest/'decisions'/file.name)
        shutil.copyfile(src/'manifest.json.gz',dest/'manifest.json.gz')
        for rep in range(cfg['profiling_repeats']):
            old=a.input/'profiles'/f'repeat{rep}'/f'case{i}'/'manifest.json.gz'
            new=a.output/'profiles'/f'repeat{rep}'/f'case{i}'/'manifest.json.gz';new.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(old,new)
        prefix=a.data_root/case['history_prefix']
        records.append(dict(case_index=i,ledger_sha256=case['ledger_sha256'],history_files={str(prefix.with_suffix(ext)):sha256_file(prefix.with_suffix(ext)) for ext in ('.json','.npz','.history.json.gz')},pool_records=m['pool_records']))
    audit=dict(quality_executions=5,profile_executions=25,decisions=len(cfg['cases'])*len(cfg['methods'])*len(cfg['budgets']),workers=5,threads_per_process=1,
        python=platform.python_version(),numpy=np.__version__,scipy=scipy.__version__,platform=platform.platform(),
        processor=platform.processor(),cpu_info=subprocess.check_output(['lscpu'],text=True),cpu_quota=Path('/sys/fs/cgroup/cpu.max').read_text().strip(),
        inputs=records,large_pool_archive=str(a.input/'quality'),limitation='pool certificates remain in local archive; published decisions include selected certificates; manifest paths are original execution paths, restore data or rerun to replay full pools')
    (a.output/'audit.json').write_text(json.dumps(audit,indent=2)+'\n')

if __name__=='__main__':main()
