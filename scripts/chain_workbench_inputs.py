"""Read-only, label-free boundary expansion for a declared investigation window.

A process cohort is an undirected *investigation* heuristic, not causal proof.
Strict direction and timestamp checks belong to downstream witness selection.
The reader never takes reference labels or desired coverage as an input.
"""
from __future__ import annotations

from collections import defaultdict, deque
from contextlib import closing
import math
from pathlib import Path
import sqlite3


PROCESS_TYPES={'process','proc','subject','subject_process'}
FIELDS=('event_id','src','dst','relation','timestamp_ns','host','src_type','dst_type','src_semantic','dst_semantic')


def _integer(value, name):
    if isinstance(value,bool) or not isinstance(value,(int,str)) or (isinstance(value,str) and not value.isdigit()):
        raise ValueError(name+' must be an exact nonnegative integer')
    result=int(value)
    if result<0:raise ValueError(name+' must be nonnegative')
    return result


def _seconds(value,name,allow_zero=False):
    if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value) or value<0 or (not allow_zero and value==0):
        raise ValueError(name+' must be finite and positive')
    result=int(value*10**9)
    if result==0 and not allow_zero:raise ValueError(name+' is below nanosecond precision')
    return result


def _id(value):return str(value).strip().upper()


def _cohort(rows,poi_ids):
    graph=defaultdict(set);seeds=set()
    for row in rows:
        proc=[str(row[side]) for side in ('src','dst') if str(row.get(side+'_type','')).lower() in PROCESS_TYPES]
        if _id(row['event_id']) in poi_ids:seeds.update(proc)
        if len(proc)==2:
            graph[proc[0]].add(proc[1]);graph[proc[1]].add(proc[0])
    seen=set(seeds);pending=deque(sorted(seeds))
    while pending:
        for other in sorted(graph[pending.popleft()]):
            if other not in seen:seen.add(other);pending.append(other)
    return seen


def read_interval(conn,lower,upper,limit):
    """Use the existing time index; one extra row detects bounded truncation."""
    raw=list(conn.execute('SELECT event_id,src,dst,relation,timestamp_ns,host FROM edges INDEXED BY idx_edges_time WHERE timestamp_ns>=? AND timestamp_ns<=? ORDER BY timestamp_ns,id LIMIT ?',
                          (lower,upper,limit+1)))
    truncated=len(raw)>limit;raw=raw[:limit]
    nodes={};ids=sorted({r[k] for r in raw for k in ('src','dst')})
    for start in range(0,len(ids),500):
        chunk=ids[start:start+500];marks=','.join('?' for _ in chunk)
        for node in conn.execute(f'SELECT uuid,node_type,semantic_key FROM nodes WHERE uuid IN ({marks})',chunk):
            nodes[node['uuid']]=node
    result=[]
    for r in raw:
        row=dict(r)
        for side in ('src','dst'):
            if row[side] not in nodes:raise ValueError('event endpoint is missing from source node table')
            node=nodes[row[side]];row[side+'_type']=node['node_type'];row[side+'_semantic']=node['semantic_key']
        row['is_declared_poi']=False;result.append(row)
    return result,truncated


def expand_candidate_window(database,base_rows,*,start_ns,end_ns,poi_event_ids,
                            step_seconds=300,max_extension_seconds=900,boundary_seconds=60,max_events=300000):
    lower,upper=_integer(start_ns,'start_ns'),_integer(end_ns,'end_ns')
    if upper<lower:raise ValueError('window end precedes start')
    step=_seconds(step_seconds,'step_seconds');span=_seconds(max_extension_seconds,'max_extension_seconds',True)
    band=_seconds(boundary_seconds,'boundary_seconds')
    if isinstance(max_events,bool) or not isinstance(max_events,int) or max_events<1:raise ValueError('max_events must be a positive integer')
    if not isinstance(poi_event_ids,(list,tuple,set)) or not poi_event_ids:raise ValueError('explicit POI event identities required')
    pois={_id(e) for e in poi_event_ids}
    selected={}
    for row in base_rows:
        event=_id(row['event_id'])
        if not event or event in selected:raise ValueError('base event identities must be unique and nonempty')
        timestamp=_integer(row['timestamp_ns'],'timestamp_ns')
        if not lower<=timestamp<=upper:raise ValueError('base event outside declared initial window')
        item={key:row.get(key) for key in FIELDS}
        item['timestamp_ns']=timestamp;item['is_declared_poi']=event in pois
        # Preserve legacy score only as provenance; downstream scoring decides
        # explicitly whether to use it or recompute all events from one model.
        if 'components' in row:item['components']=dict(row['components'])
        selected[event]=item
    if not pois<=selected.keys():raise ValueError('declared POIs absent from base candidates')
    if len(selected)>max_events:raise ValueError('candidate cap cannot remove base events')
    initial_count=len(selected);min_lower=max(0,lower-span);max_upper=upper+span
    if max_upper>=2**63:raise ValueError('window exceeds SQLite int64 time range')
    diagnostic={'policy':'active_process_boundary_v1','ground_truth_used':False,'initial_start_ns':str(lower),'initial_end_ns':str(upper),
                'initial_events':initial_count,'max_events':max_events,'step_seconds':step_seconds,'max_extension_seconds':max_extension_seconds,
                'boundary_seconds':boundary_seconds,'rounds':[],'stopping_reasons':[],'incomplete':False,'truncation_reason':None,
                'cohort_semantics':'undirected declared-process interaction cohort; not a causal or attack certificate'}
    active={'backward':True,'forward':True}
    boundary_stopped=set()
    uri=Path(database).resolve().as_uri()+'?mode=ro'
    with closing(sqlite3.connect(uri,uri=True)) as conn:
        conn.row_factory=sqlite3.Row;conn.execute('PRAGMA query_only=ON');conn.execute('BEGIN')
        while any(active.values()):
            cohort=_cohort(selected.values(),pois)
            for direction in ('backward','forward'):
                if not active[direction]:continue
                boundary=lower if direction=='backward' else upper
                at_limit=lower<=min_lower if direction=='backward' else upper>=max_upper
                if at_limit:
                    active[direction]=False;diagnostic['stopping_reasons'].append({'direction':direction,'reason':'extension_limit'});continue
                relevant=[]
                for r in selected.values():
                    t=r['timestamp_ns']
                    near=(lower<=t<=min(upper,lower+band)) if direction=='backward' else (max(lower,upper-band)<=t<=upper)
                    if near and any(str(r[side]) in cohort and str(r.get(side+'_type','')).lower() in PROCESS_TYPES for side in ('src','dst')):relevant.append(r)
                if not relevant:
                    active[direction]=False;boundary_stopped.add(direction)
                    diagnostic['stopping_reasons'].append({'direction':direction,'reason':'no_active_cohort_at_boundary'});continue
                remaining=max_events-len(selected)
                if remaining<=0:
                    diagnostic['incomplete']=True;diagnostic['truncation_reason']='candidate_event_limit';active={key:False for key in active};break
                lo,hi=(max(min_lower,lower-step),lower-1) if direction=='backward' else (upper+1,min(max_upper,upper+step))
                rows,truncated=read_interval(conn,lo,hi,remaining)
                for r in rows:
                    selected.setdefault(_id(r['event_id']),r)
                diagnostic['rounds'].append({'direction':direction,'start_ns':str(lo),'end_ns':str(hi),'frontier_events':len(relevant),'loaded_events':len(rows),'truncated':truncated})
                if direction=='backward':lower=lo
                else:upper=hi
                if truncated:
                    diagnostic['incomplete']=True;diagnostic['truncation_reason']='candidate_event_limit';active={key:False for key in active};break
            # A new process link found on either side can activate the other
            # boundary. A no-activity stop is provisional until the cohort is
            # stable; hard span limits and truncation remain terminal.
            if boundary_stopped and not diagnostic['incomplete']:
                grown_cohort=_cohort(selected.values(),pois)
                if grown_cohort!=cohort:
                    for direction in boundary_stopped:active[direction]=True
                    diagnostic['stopping_reasons']=[item for item in diagnostic['stopping_reasons']
                        if not (item['direction'] in boundary_stopped and item['reason']=='no_active_cohort_at_boundary')]
                    boundary_stopped.clear()
            if not active['backward'] and not active['forward']:break
    diagnostic.update(final_start_ns=str(lower),final_end_ns=str(upper),candidate_events=len(selected),added_events=len(selected)-initial_count,
                      cohort_process_count=len(_cohort(selected.values(),pois)),candidate_boundary_completeness='unverified')
    return sorted(selected.values(),key=lambda r:(r['timestamp_ns'],_id(r['event_id']))),diagnostic
