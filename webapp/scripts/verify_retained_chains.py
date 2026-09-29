"""Browser checks for actual retained graphs; fixture data is never a benchmark."""
from __future__ import annotations
import argparse
import json
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import urljoin
from urllib.request import ProxyHandler, build_opener
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]


def fixture():
    events = []
    def add(eid, src, dst, t, rel='WRITE', reverse=False, poi=False):
        events.append(dict(event_index=len(events), event_id=eid, src=src, dst=dst,
            src_semantic={'proc': '进程 B'}.get(src, src), dst_semantic={'exe':'<img src=x onerror=alert(1)>', 'file':'文件 C'}.get(dst, dst),
            src_type='process', dst_type='file', relation=rel, timestamp_ns=str(t),
            causal_src=dst if reverse else src, causal_dst=src if reverse else dst,
            causal_direction='dst_to_src' if reverse else 'src_to_dst', is_declared_poi=poi, score=0.5, host='test-host'))
    add('execute-a', 'proc', 'exe', 1234567890123456789, 'EVENT_EXECUTE', True, True)
    add('write-b', 'proc', 'file', 1234567890123456790)
    add('branch-c', 'proc', 'socket', 1234567890123456791, 'SEND')
    for n in range(102):
        add(f'isolated-{n:03}', f'src-{n}', f'dst-{n}', 1234567890123456800+n)
    paths = [dict(id='path-main', event_indices=[0, 1], event_ids=['execute-a','write-b'], singleton=False)]
    paths.extend(dict(id=f'path-{i}', event_indices=[i], event_ids=[e['event_id']], singleton=True) for i,e in enumerate(events) if i >= 2)
    return dict(schema_version='retained-chain-export-v1', case_id='browser-fixture', method='test-only', budget_edges=110,
        candidate_edges=200, retained_edges=len(events), actual_compression=1-len(events)/200,
        scope='retained_graph_only_not_complete_attack', events=events, nodes=[], paths=paths,
        observed_bundles=[dict(id='witness-1', event_indices=[0,1,2], event_ids=[e['event_id'] for e in events[:3]],
            paths=[[0,1],[0,2]], complete_in_candidate=False, boundary_status='truncated', scope='observed_witness_only_not_complete_attack')])


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        self.path = self.path.removeprefix('/assets')
        super().do_GET()
    def log_message(self, *_args):
        pass


def catalog():
    return dict(entries=[dict(id='fixture', label='合成浏览器检查（非实验成绩）', artifact_url='/assets/retained-test/retained-graph.json',
        downloads=dict(json='/assets/retained-test/retained-graph.json', csv='/assets/retained-test/retained-events.csv', graphml='/assets/retained-test/retained-graph.graphml'))])


def run(args):
    frontend=ROOT/'webapp/frontend'
    assert (frontend/'retained-chains.html').exists(), 'retained viewer has not been implemented'
    server=None
    if args.base_url:
        origin=args.base_url.rstrip('/')
    else:
        server=ThreadingHTTPServer(('127.0.0.1',0),partial(Handler,directory=str(frontend)))
        Thread(target=server.serve_forever,daemon=True).start()
        origin=f'http://127.0.0.1:{server.server_port}'
    output=Path(args.output);output.mkdir(parents=True,exist_ok=True)
    checks=[]
    try:
        with sync_playwright() as playwright:
            browser=playwright.chromium.launch(headless=True)
            page=browser.new_page(viewport=dict(width=1440,height=1050))
            errors=[]; page.on('pageerror',lambda error:errors.append(str(error)))
            page.route('**/retained-chain-catalog.json',lambda route:route.fulfill(json=catalog()))
            page.route('**/retained-test/retained-graph.json',lambda route:route.fulfill(json=fixture()))
            page.goto(origin+'/assets/retained-chains.html')
            page.locator('#viewer-content').wait_for(state='visible')
            assert page.locator('#metric-retained .metric-value').inner_text()=='105'
            assert page.locator('#metric-paths .metric-value').inner_text()=='1'
            assert page.locator('#metric-singletons .metric-value').inner_text()=='103'
            assert page.locator('#metric-pois .metric-value').inner_text()=='1'
            assert '1234567890123456789' in page.locator('#path-events').inner_text()
            assert '<img src=x onerror=alert(1)>' in page.locator('#path-events .flow-node').first.inner_text()
            assert page.locator('#path-events img').count()==0
            assert '目标 → 源' in page.locator('#path-events').inner_text()
            assert page.locator('#related-paths button').count()>=1
            page.locator('#related-paths button').first.click()
            assert '单事件路径' in page.locator('#path-status').inner_text()
            page.locator('#path-list button').first.focus();page.keyboard.press('Enter')
            assert 'path-main' in page.locator('#path-title').inner_text()
            page.locator('#collection-select').select_option('bundles')
            assert page.locator('#path-events .event-card').count()==4, 'shared branch event may repeat in witness view'
            assert '候选内仍不完整' in page.locator('#path-status').inner_text()
            assert page.locator('#path-events .branch-heading').count()==2
            checks.extend(['exact union counts','precise timestamp','EXECUTE direction','escaped labels','shared-entity branch navigation','keyboard path selection','partial witness scope'])
            for key,suffix in [('json','retained-graph.json'),('csv','retained-events.csv'),('graphml','retained-graph.graphml')]:
                assert page.locator('#download-'+key).get_attribute('href').endswith(suffix)
            seen=[]
            while True:
                seen.extend(page.locator('#event-table-body tr').evaluate_all("rows => rows.map(row => row.dataset.eventId)"))
                assert page.locator('#event-table-body tr').count()<=100
                if page.locator('#events-next').is_disabled():break
                page.locator('#events-next').click()
            assert len(seen)==105 and len(set(seen))==105
            page.locator('#event-search').fill('isolated-101')
            assert page.locator('#event-table-body tr').count()==1
            assert 'isolated-101' in page.locator('#event-table-body').inner_text()
            page.locator('#event-search').fill('文件 C')
            assert page.locator('#event-table-body tr').count()==1
            page.locator('#event-search').fill('')
            checks.extend(['three download formats','all-event pagination exact union','ID and semantic search'])
            role_fixture=fixture()
            role_fixture['events'][2]['is_declared_poi']=True
            role_fixture['poi_roles']=dict(original_declared_event_ids=['execute-a'],selected_event_ids=['execute-a','branch-c'],suggested_event_ids=['branch-c'],suggestions_are_verified_alerts=False)
            page.unroute('**/retained-test/retained-graph.json')
            page.route('**/retained-test/retained-graph.json',lambda route:route.fulfill(json=role_fixture))
            page.reload();page.locator('#viewer-content').wait_for(state='visible')
            assert page.locator('#metric-pois .metric-value').inner_text()=='2'
            assert '原始输入 POI' in page.locator('#path-events').inner_text()
            page.locator('#event-search').fill('branch-c')
            assert '算法建议 POI' in page.locator('#event-table-body').inner_text()
            assert '未核验' in page.locator('#event-table-body').inner_text()
            page.locator('#event-search').fill('')
            checks.append('original versus suggested POI roles')
            audit_artifact=role_fixture
            audit_artifact.update(source_manifest_sha256='a'*64,track='base',poi_policy='adaptive')
            audit_catalog=catalog()
            audit_catalog['entries'][0]['reference_audit_url']='/assets/retained-test/reference-audit.json'
            audit_catalog['entries'].append({**audit_catalog['entries'][0],'id':'mismatch','label':'Mismatched offline audit','reference_audit_url':'/assets/retained-test/wrong-reference-audit.json'})
            audit_events=[]
            for original in audit_artifact['events'][:2]:
                audit_events.append({**original,'retained':True,'candidate_present':True,'temporal_eligible':True})
            missing={**audit_events[1],'event_id':'LINEAGE-missing','dst':'absent','causal_dst':'absent','timestamp_ns':'1234567890123456792','retained':False,'candidate_present':False,'temporal_eligible':False}
            audit_events.append(missing)
            audit=dict(schema_version='chain-workbench-reference-audit-v1',case_id=audit_artifact['case_id'],track='base',poi_policy='adaptive',method=audit_artifact['method'],budget_edges=audit_artifact['budget_edges'],source_manifest_sha256='a'*64,annotation_status='local_critical_partial_reference',scope='source_positive_subgraph_witnesses_not_complete_attacks',verified_attack_chain_count=None,
                counts=dict(reference_chains=2,retained_reference_chains=1,covered_positive_events=3,singleton_positive_events=4),
                chains=[dict(id='reference-complete',status='complete',first_loss_stage='surviving',event_ids=['execute-a','write-b'],missing_event_ids=[]),dict(id='reference-broken',status='broken',first_loss_stage='candidate',event_ids=['execute-a','LINEAGE-missing'],missing_event_ids=['LINEAGE-missing'])],events=audit_events)
            # Offline references canonicalize identity while raw exports preserve spelling.
            for reference_event in audit['events']:reference_event['event_id']=reference_event['event_id'].upper()
            for chain in audit['chains']:
                chain['event_ids']=[value.upper() for value in chain['event_ids']]
                chain['missing_event_ids']=[value.upper() for value in chain['missing_event_ids']]
            page.unroute('**/retained-chain-catalog.json')
            page.route('**/retained-chain-catalog.json',lambda route:route.fulfill(json=audit_catalog))
            page.route('**/retained-test/reference-audit.json',lambda route:route.fulfill(json=audit))
            page.route('**/retained-test/wrong-reference-audit.json',lambda route:route.fulfill(json={**audit,'budget_edges':109}))
            page.reload();page.locator('#reference-audit-panel').wait_for(state='visible')
            page.locator('#reference-audit-status').wait_for(state='hidden')
            assert page.locator('#reference-audit-error').is_hidden(),page.locator('#reference-audit-error').inner_text()
            page.locator('#reference-audit-content').wait_for(state='visible')
            assert page.locator('#audit-retention').inner_text()=='1 / 2'
            assert '首次损失' not in page.locator('#audit-chain-status').inner_text()
            assert '3' in page.locator('#audit-covered').inner_text()
            assert '4' in page.locator('#audit-singletons').inner_text()
            page.locator('#export-select').select_option('1')
            page.locator('#reference-audit-error').wait_for(state='visible')
            assert page.locator('#download-reference-audit').get_attribute('href') is None, 'case switch must clear the previous audit download'
            page.locator('#export-select').select_option('0')
            page.locator('#reference-audit-content').wait_for(state='visible')
            page.locator('#audit-filter').select_option('broken')
            assert page.locator('#audit-chain-list button').count()==1
            assert page.locator('#audit-events .event-card.missing').count()==1
            assert '1234567890123456792' in page.locator('#audit-events').inner_text()
            assert 'LINEAGE' in page.locator('#audit-events').inner_text()
            assert '派生关系' in page.locator('#audit-events').inner_text()
            assert '候选' in page.locator('#audit-chain-status').inner_text()
            page.locator('#reference-audit-panel').scroll_into_view_if_needed()
            page.screenshot(path=str(output/'reference-audit-desktop.png'))
            page.set_viewport_size(dict(width=390,height=844))
            assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
            assert page.locator('#audit-events .event-card.missing').count()==1
            page.screenshot(path=str(output/'reference-audit-mobile.png'))
            page.set_viewport_size(dict(width=1440,height=1050))
            page.locator('#audit-filter').select_option('complete')
            assert page.locator('#audit-events .event-card.missing').count()==0
            assert page.locator('#audit-events img').count()==0
            # Binding covers the decision, not only the common source manifest.
            audit['budget_edges']=109
            page.reload();page.locator('#reference-audit-error').wait_for(state='visible')
            assert '冻结决策' in page.locator('#reference-audit-error').inner_text()
            assert page.locator('#download-reference-audit').get_attribute('href') is None, 'mismatched audit must not expose a stale download'
            assert page.locator('#viewer-content').is_visible()
            audit['budget_edges']=110
            audit['events'][0]['timestamp_ns']=1234567890123456789
            page.reload();page.locator('#reference-audit-error').wait_for(state='visible')
            assert '时间' in page.locator('#reference-audit-error').inner_text()
            assert page.locator('#viewer-content').is_visible()
            audit['events'][0]['timestamp_ns']='1234567890123456789'
            audit['budget_edges']=110;audit['source_manifest_sha256']='b'*64
            page.reload();page.locator('#reference-audit-error').wait_for(state='visible')
            assert '来源' in page.locator('#reference-audit-error').inner_text()
            audit.update(source_manifest_sha256='a'*64,annotation_status='unavailable',chains=[],events=[],counts=dict(reference_chains=None,retained_reference_chains=None,covered_positive_events=None,singleton_positive_events=None))
            page.reload();page.locator('#reference-audit-content').wait_for(state='visible')
            assert page.locator('#audit-retention').inner_text()=='N/A'
            assert page.locator('#audit-chain-list button').count()==0
            assert '没有可用参考标注' in page.locator('#audit-chain-list').inner_text()
            checks.extend(['complete/broken fixed references','missing reference events and precise times','LINEAGE derived relationship scope','reference audit source and decision binding','unavailable reference N/A'])
            delayed=[]
            page.unroute('**/retained-test/reference-audit.json')
            page.route('**/retained-test/reference-audit.json',lambda route:delayed.append(route))
            second=fixture();second['case_id']='other-case'
            page.route('**/retained-test/other-graph.json',lambda route:route.fulfill(json=second))
            audit_catalog['entries'].append(dict(id='other',label='Second export without reference audit',artifact_url='/assets/retained-test/other-graph.json',downloads={}))
            page.reload();page.locator('#viewer-content').wait_for(state='visible')
            page.wait_for_function("document.querySelector('#reference-audit-panel').hidden === false")
            page.locator('#export-select').select_option('2')
            page.locator('#viewer-content').wait_for(state='visible')
            assert 'other-case' in page.locator('#result-note').inner_text()
            assert delayed, 'first audit request was issued before switching'
            for route in delayed:route.fulfill(json=audit)
            page.wait_for_timeout(100)
            assert page.locator('#reference-audit-panel').is_hidden(), 'late audit must not attach to a different export'
            assert 'other-case' in page.locator('#result-note').inner_text()
            checks.extend(['reference audit 390px layout','malformed audit fails without hiding retained graph','catalog switch discards stale audit response'])
            page.goto(origin+'/assets/retained-chains.html?entry=other')
            page.locator('#viewer-content').wait_for(state='visible')
            assert page.locator('#export-select').input_value()=='2'
            assert 'other-case' in page.locator('#result-note').inner_text()
            page.goto(origin+'/assets/retained-chains.html?entry=missing-exact-export')
            page.locator('#load-error').wait_for(state='visible')
            assert '未找到指定导出' in page.locator('#load-error-detail').inner_text()
            page.goto(origin+'/assets/retained-chains.html?entry=other')
            page.locator('#viewer-content').wait_for(state='visible')
            checks.extend(['exact entry query selects requested frozen decision','unknown entry fails without substituting another graph'])
            page.screenshot(path=str(output/'fixture-desktop.png'),full_page=True)
            page.set_viewport_size(dict(width=390,height=844))
            assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), 'mobile horizontal overflow'
            page.screenshot(path=str(output/'fixture-mobile.png'),full_page=True)
            checks.append('390px responsive layout')
            page.unroute('**/retained-chain-catalog.json')
            page.route('**/retained-chain-catalog.json',lambda route:route.fulfill(status=404,body='missing'))
            page.reload();page.locator('#load-error').wait_for(state='visible')
            assert 'scripts.export_retained_chains' in page.locator('#load-error').inner_text()
            page.unroute('**/retained-chain-catalog.json')
            page.route('**/retained-chain-catalog.json',lambda route:route.fulfill(json={'entries':[]}))
            page.reload();page.locator('#load-error').wait_for(state='visible')
            assert '目录' in page.locator('#load-error-detail').inner_text()
            checks.extend(['missing catalog guidance','empty catalog guidance'])
            page.goto(origin+'/assets/retained-chains.html')
            page.locator('#load-error').wait_for(state='visible')
            if args.artifact:
                artifact=json.loads(Path(args.artifact).read_text())
                page.unroute('**/retained-chain-catalog.json')
                page.route('**/retained-chain-catalog.json',lambda route:route.fulfill(json=catalog()))
                page.unroute('**/retained-test/retained-graph.json')
                page.route('**/retained-test/retained-graph.json',lambda route:route.fulfill(json=artifact))
                page.set_viewport_size(dict(width=1440,height=1050));page.reload()
                page.locator('#viewer-content').wait_for(state='visible')
                assert page.locator('#metric-retained .metric-value').inner_text().replace(',','')==str(len(artifact['events']))
                paths=artifact['paths']
                assert page.locator('#metric-paths .metric-value').inner_text().replace(',','')==str(sum(len(p['event_indices'])>1 for p in paths))
                assert page.locator('#metric-singletons .metric-value').inner_text().replace(',','')==str(sum(len(p['event_indices'])==1 for p in paths))
                page.screenshot(path=str(output/'actual-desktop.png'),full_page=True)
                page.set_viewport_size(dict(width=390,height=844))
                assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
                page.screenshot(path=str(output/'actual-mobile.png'),full_page=True)
                page.screenshot(path=str(output/'actual-mobile-viewport.png'))
                checks.append(f"actual artifact: {len(artifact['events'])} events, {len(paths)} paths")
            if args.catalog:
                published=json.loads(Path(args.catalog).read_text())
                entries=published if isinstance(published,list) else published['entries']
                page.unroute('**/retained-chain-catalog.json')
                if args.base_url:
                    with build_opener(ProxyHandler({})).open(origin+'/assets/retained-chain-catalog.json') as response:
                        assert json.load(response)==published, 'live catalog differs from the supplied expected catalog'
                    checks.append('live HTTP catalog matches expected catalog; browser response not intercepted')
                else:
                    page.route('**/retained-chain-catalog.json',lambda route:route.fulfill(json=published))
                page.set_viewport_size(dict(width=1440,height=1050));page.reload()
                page.locator('#viewer-content').wait_for(state='visible')
                opener=build_opener(ProxyHandler({}))
                case_checks=[]
                for index,entry in enumerate(entries):
                    page.locator('#export-select').select_option(str(index))
                    page.locator('#viewer-content').wait_for(state='visible')
                    with opener.open(urljoin(origin,entry['artifact_url'])) as response:
                        actual=json.load(response)
                    assert page.locator('#metric-retained .metric-value').inner_text().replace(',','')==str(len(actual['events']))
                    singles=sum(len(item['event_indices'])==1 for item in actual['paths'])
                    assert page.locator('#metric-singletons .metric-value').inner_text().replace(',','')==str(singles)
                    assert page.locator('#metric-witnesses .metric-value').inner_text().replace(',','')==str(len(actual['observed_bundles']))
                    for format in ('json','csv','graphml'):
                        assert page.locator('#download-'+format).get_attribute('href')==entry['downloads'][format]
                        with opener.open(urljoin(origin,entry['downloads'][format])) as response:
                            assert response.status==200
                            assert response.read(), 'download must not be empty'
                    assert page.locator('#metric-pois .metric-value').inner_text().replace(',','')==str(sum(bool(e['is_declared_poi']) for e in actual['events']))
                    roles=actual.get('poi_roles')
                    if roles:
                        for ids,expected_role in [(roles['original_declared_event_ids'],'原始输入 POI'),(roles['suggested_event_ids'],'算法建议')]:
                            candidate=next((e for e in actual['events'] if e['event_id'] in ids),None)
                            if candidate:
                                page.locator('#event-search').fill(candidate['event_id'])
                                assert expected_role in page.locator('#event-table-body').inner_text()
                                page.locator('#event-search').fill('')
                    if actual['events']:
                        last=actual['events'][-1]
                        page.locator('#event-search').fill(last['event_id'])
                        assert last['event_id'] in page.locator('#event-table-body').inner_text()
                        assert last['timestamp_ns'] in page.locator('#event-table-body').inner_text()
                        page.locator('#event-search').fill('')
                    page.set_viewport_size(dict(width=390,height=844))
                    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
                    page.set_viewport_size(dict(width=1440,height=1050))
                    audit_counts=None
                    if entry.get('reference_audit_url'):
                        page.locator('#reference-audit-panel').wait_for(state='visible')
                        page.locator('#reference-audit-status').wait_for(state='hidden')
                        assert page.locator('#reference-audit-error').is_hidden(),page.locator('#reference-audit-error').inner_text()
                        with opener.open(urljoin(origin,entry['reference_audit_url'])) as response:reference=json.load(response)
                        audit_counts=reference['counts']
                        expected='N/A' if not audit_counts['reference_chains'] else f"{audit_counts['retained_reference_chains']:,} / {audit_counts['reference_chains']:,}"
                        assert page.locator('#audit-retention').inner_text()==expected
                        for status in ('complete','broken'):
                            expected_chains=[chain for chain in reference['chains'] if chain['status']==status]
                            page.locator('#audit-filter').select_option(status)
                            assert page.locator('#audit-chain-list button').count()==min(20,len(expected_chains))
                            if expected_chains:
                                if status=='complete':assert page.locator('#audit-events .event-card.missing').count()==0
                                else:assert '缺失' in page.locator('#audit-chain-status').inner_text()
                        page.locator('#audit-filter').select_option('all')
                        focused=(entry.get('case_id')=='cadets13' and entry.get('track')=='expanded' and entry.get('poi_policy')=='adaptive') or 'trace' in str(entry.get('case_id','')).lower()
                        if focused:
                            name='cadets13' if entry.get('case_id')=='cadets13' else 'trace'
                            if any(c['status']=='broken' for c in reference['chains']):page.locator('#audit-filter').select_option('broken')
                            page.locator('#reference-audit-panel').evaluate("node => node.scrollIntoView({block:'start'})")
                            page.screenshot(path=str(output/f'audit-{name}-desktop.png'))
                        page.set_viewport_size(dict(width=390,height=844))
                        assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
                        if focused:
                            page.locator('#reference-audit-panel').evaluate("node => node.scrollIntoView({block:'start'})")
                            page.screenshot(path=str(output/f'audit-{name}-mobile.png'))
                        page.set_viewport_size(dict(width=1440,height=1050))
                    case_checks.append(dict(id=entry['id'],events=len(actual['events']),paths=len(actual['paths']),singleton_paths=singles,witnesses=len(actual['observed_bundles']),reference_counts=audit_counts))
                page.screenshot(path=str(output/'catalog-desktop.png'))
                page.set_viewport_size(dict(width=390,height=844))
                page.screenshot(path=str(output/'catalog-mobile.png'))
                (output/'catalog-verification.json').write_text(json.dumps(case_checks,ensure_ascii=False,indent=2)+'\n')
                checks.append(f'published catalog: {len(entries)} cases, all downloads and exact last-event timestamps')
            assert not errors,errors
            browser.close()
    finally:
        if server:server.shutdown();server.server_close()
    report=dict(status='passed',checks=checks,browser_errors=[])
    (output/'verification.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(report,ensure_ascii=False))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url',help='Running app; --catalog verifies the real HTTP catalog without interception.');parser.add_argument('--artifact',help='Optional local artifact injected only for schema/UI checks.');parser.add_argument('--catalog',help='Expected catalog; checks every linked artifact and download over HTTP.');parser.add_argument('--output',default='/tmp/nodoze-retained-browser')
    run(parser.parse_args())
