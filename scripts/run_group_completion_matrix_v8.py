"""Run the frozen five-case quality matrix, then independent resource repeats."""
import argparse,concurrent.futures,os,subprocess,sys
from pathlib import Path


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--data-root',type=Path,required=True);p.add_argument('--workers',type=int,default=2);a=p.parse_args()
    if a.output.exists():raise FileExistsError(a.output)
    if a.workers<1:raise ValueError('workers must be positive')
    (a.output/'logs').mkdir(parents=True)
    env=dict(os.environ,PYTHONPATH='.',OPENBLAS_NUM_THREADS='1',OMP_NUM_THREADS='1')
    def run(job):
        i,rep=job;tag=f'quality-case{i}' if rep is None else f'repeat{rep}-case{i}'
        out=a.output/'quality' if rep is None else a.output/'profiles'/f'repeat{rep}'
        cmd=[sys.executable,'scripts/run_group_completion_v8.py','--case',str(i),'--data-root',str(a.data_root),'--output-dir',str(out)]
        if rep is not None:cmd+=['--profile-only']
        with (a.output/'logs'/f'{tag}.log').open('w') as f:r=subprocess.run(cmd,env=env,stdout=f,stderr=subprocess.STDOUT)
        print(tag,r.returncode,flush=True)
        if r.returncode:raise RuntimeError(f'{tag} failed; see log')
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as ex:
        list(ex.map(run,[(i,None) for i in range(5)]))
        list(ex.map(run,[(i,j) for j in range(5) for i in range(5)]))

if __name__=='__main__':main()
