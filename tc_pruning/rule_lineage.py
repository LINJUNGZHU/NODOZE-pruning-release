"""Bounded executable lineage from corroborated behavior, never truth membership.

This is retrospective attribution. Descendants may be legitimate helpers: the
output is an attack-involvement hypothesis, not a claim that their binaries are
malware. Shared resources, OPEN events and PID equality never propagate it.
"""
SHELLS={'cmd.exe','powershell.exe','pwsh.exe','wscript.exe','cscript.exe','mshta.exe','sh','bash'}


def expand_lineage(rows, edges, config):
    by_id={e['id']:e for e in edges}
    births={}
    for e in edges:
        if e['relation']=='PROCESS_CREATE':births.setdefault(e['target'],e)
    terminated={}
    for e in edges:
        if e['relation']=='PROCESS_TERMINATE' and e['target'] in births and e['timestamp_ns']>=births[e['target']]['timestamp_ns']:
            terminated.setdefault(e['target'],e['timestamp_ns'])
    strong={r['id']:r for r in rows if r.get('behavioral_candidate',r['behavioral_match'])}
    chosen={}
    for nid,row in sorted(strong.items()):
        birth=births[nid]
        chosen[nid]=dict(kind='corroborated_behavior',root_node_id=nid,depth=0,
                         active_since_ns=birth['timestamp_ns'],expires_ns=birth['timestamp_ns']+config['lineage_seconds']*1_000_000_000,
                         chain_event_ids=[],root_evidence_event_ids=[birth['id']]+row['corroboration_event_ids'])
    for nid in sorted(strong):
        event=births[nid];parent=event['source'];birth=births.get(parent)
        if not birth or parent in chosen or event['timestamp_ns']>=terminated.get(parent,float('inf')):continue
        name=birth['raw']['properties'].get('image_path','').replace('/','\\').split('\\')[-1].lower()
        # Only an observed, recently started interpreter that directly launched
        # a corroborated root qualifies. Never label explorer/service ancestors.
        if name not in SHELLS or not 0<event['timestamp_ns']-birth['timestamp_ns']<=config['launcher_seconds']*1_000_000_000:continue
        chosen[parent]=dict(kind='observed_launcher',root_node_id=nid,depth=0,
                            active_since_ns=birth['timestamp_ns'],expires_ns=chosen[nid]['expires_ns'],
                            chain_event_ids=[birth['id'],event['id']],root_evidence_event_ids=[birth['id']]+chosen[nid]['root_evidence_event_ids'])
    for e in edges:  # caller provides strict deterministic timestamp order
        if e['relation']!='PROCESS_CREATE' or e['target'] in chosen:continue
        parent=chosen.get(e['source'])
        if not parent or parent['depth']>=config['lineage_depth'] or e['timestamp_ns']>=terminated.get(e['source'],float('inf')):continue
        if not parent['active_since_ns']<e['timestamp_ns']<=parent['expires_ns']:continue
        # A second creation of an existing UUID is inconsistent telemetry, not
        # evidence that an old unrelated process became a child.
        if births.get(e['target'],{}).get('id')!=e['id']:continue
        chain=[] if parent['kind']=='observed_launcher' else parent['chain_event_ids']
        chosen[e['target']]=dict(kind='execution_descendant',root_node_id=parent['root_node_id'],depth=parent['depth']+1,
                                active_since_ns=e['timestamp_ns'],expires_ns=parent['expires_ns'],
                                chain_event_ids=chain+[e['id']],root_evidence_event_ids=parent['root_evidence_event_ids'])
    for row in rows:
        witness=chosen.get(row['id']);row['legacy_prediction']=row['predicted_attack']
        row['review_candidate']=bool(row['anomaly_match'] and not witness)
        row['predicted_attack']=witness is not None;row['rule_witness']=witness
        row['decision_kind']=witness['kind'] if witness else 'anomaly_review_only' if row['review_candidate'] else 'unclassified'
        if witness:
            ids=list(dict.fromkeys(witness['root_evidence_event_ids']+witness['chain_event_ids']))
            row['evidence_event_ids']=ids;row['first_support_ns']=witness['active_since_ns']
            row['reasons']=[{'corroborated_behavior':'编码与隐藏执行同时出现，且创建后有出站通信或子进程支持',
                            'observed_launcher':'新启动的脚本解释器直接创建了有组合行为证据的进程；原始创建事件可核验',
                            'execution_descendant':'有组合行为证据的执行链实际创建了此进程；可能是侦察工具或辅助进程，需结合日志核验'}[witness['kind']]]
        else:row['reasons']=['仅有分位异常，列为复核候选，不单独判为攻击'] if row['review_candidate'] else ['未满足组合行为或受限启动链判定；不等于已确认正常']
        row['status']='inferred_attack' if witness else 'manual_seed' if row['seed_node'] else 'review_candidate' if row['review_candidate'] else 'unclassified'
    return dict(strong_roots=len(strong),launchers=sum(v['kind']=='observed_launcher' for v in chosen.values()),
                descendants=sum(v['kind']=='execution_descendant' for v in chosen.values()),
                review_only=sum(r['review_candidate'] for r in rows),
                policy='corroborated behavior OR recent observed interpreter launcher OR bounded execution descendant; anomaly alone only queues review')


def verify_witness(row, by_id, config):
    """Replay a positive rule witness from raw-derived events, not cached flags."""
    from tc_pruning.attack_inference import command_signals
    w=row.get('rule_witness')
    if not w:raise ValueError('missing rule witness')
    try:
        support=[by_id[i] for i in w['root_evidence_event_ids']]
        chain=[by_id[i] for i in w['chain_event_ids']]
    except KeyError as exc:raise ValueError('missing rule witness event') from exc
    roots=[e for e in support if e['relation']=='PROCESS_CREATE' and e['target']==w['root_node_id'] and len(command_signals(e['raw']))==2]
    if len(roots)!=1:raise ValueError('invalid behavioral root')
    root=roots[0];start=root['timestamp_ns'];expiry=start+config['lineage_seconds']*1_000_000_000
    corroborated=any(e['raw']['actorID']==root['target'] and e['timestamp_ns']>start and
                     (e['relation']=='PROCESS_CREATE' or e['raw']['object']=='FLOW' and e['raw']['properties'].get('direction','').lower()=='outbound') for e in support)
    if not corroborated:raise ValueError('uncorroborated behavioral root')
    launchers=[e for e in support if e['relation']=='PROCESS_CREATE' and e['target']==root['source'] and
               e['raw']['properties'].get('image_path','').replace('/','\\').split('\\')[-1].lower() in SHELLS and
               0<start-e['timestamp_ns']<=config['launcher_seconds']*1_000_000_000]
    if w['expires_ns']!=expiry:raise ValueError('invalid rule expiry')
    if w['kind']=='corroborated_behavior':
        if row['id']!=root['target'] or chain or w['depth']!=0 or w['active_since_ns']!=start:raise ValueError('invalid root witness')
    elif w['kind']=='observed_launcher':
        if len(launchers)!=1 or row['id']!=root['source'] or w['depth']!=0 or w['active_since_ns']!=launchers[0]['timestamp_ns'] or [e['id'] for e in chain]!=[launchers[0]['id'],root['id']]:raise ValueError('invalid launcher witness')
    elif w['kind']=='execution_descendant':
        if not chain or len(chain)!=w['depth'] or len(chain)>config['lineage_depth']:raise ValueError('invalid lineage depth')
        origins={root['target']:start}
        origins.update({e['target']:e['timestamp_ns'] for e in launchers})
        cursor=chain[0]['source'];when=origins.get(cursor)
        if when is None:raise ValueError('lineage has no proven origin')
        for e in chain:
            if any(t['relation']=='PROCESS_TERMINATE' and t['target']==cursor and when<=t['timestamp_ns']<=e['timestamp_ns'] for t in by_id.values()):raise ValueError('lineage continues after termination')
            if e['relation']!='PROCESS_CREATE' or e['source']!=cursor or not when<e['timestamp_ns']<=expiry:raise ValueError('invalid execution lineage')
            cursor=e['target'];when=e['timestamp_ns']
        if cursor!=row['id'] or when!=w['active_since_ns']:raise ValueError('lineage target mismatch')
    else:raise ValueError('unknown rule kind')
    if set(row['evidence_event_ids'])!=set(w['chain_event_ids'])|set(w['root_evidence_event_ids']):raise ValueError('rule evidence union mismatch')
    return True
