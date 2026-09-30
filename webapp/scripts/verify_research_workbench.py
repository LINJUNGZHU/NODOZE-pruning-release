"""Browser regression for aggregate research overview, using synthetic-only fixtures."""
from __future__ import annotations
import argparse
import json
import hashlib
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import ProxyHandler, build_opener
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parents[2]
METHODS=['rarity_only','diffusion_only','rasp','context_v1','reliability','adaptive_v1','reliability_chain']


def fixture():
    variants=[]
    for track in ['base','expanded']:
        for policy,pois in [('single',1),('declared',3),('adaptive',5)]:
            candidate=100 if track=='base' else 200
            rows=[]
            for m,method in enumerate(METHODS):
                for budget in [10,20]:
                    retained=budget-(1 if m==0 else 0)
                    rows.append(dict(method=method,budget=budget,retained_events=retained,compression=1-retained/candidate,
                        reference_chain_count=2,retained_reference_chains=1 if budget==10 else 2,reference_chain_retention=.5 if budget==10 else 1.,
                        positive_count=10,source_positive_events=9,candidate_positive_events=8,temporal_positive_events=7,
                        retained_positive_events=7,positive_retention=.7,incremental_positive_count=5,retained_incremental_positives=2,incremental_retention=.4,
                        source_missing_positive_events=1,selection_seconds=.125))
            variants.append(dict(track=track,poi_policy=policy,candidate_events=candidate,poi_count=pois,source_scope_events=500,rows=rows))
    null_case=dict(id='unknown',label='未标注合成范围',provider='synthetic',split='development',annotation_status='unavailable',variants=[dict(variants[0])])
    null_case['variants'][0]['rows']=[dict(variants[0]['rows'][0],reference_chain_count=0,retained_reference_chains=0,reference_chain_retention=None,positive_count=0,retained_positive_events=0,positive_retention=None,incremental_positive_count=0,retained_incremental_positives=0,incremental_retention=None,source_positive_events=None,candidate_positive_events=None,temporal_positive_events=None)]
    return dict(schema_version='chain-workbench-v2-report',generated_at='2026-09-29T00:00:00Z',methods={method:dict(label=method,description='浏览器检查') for method in METHODS},
        cases=[dict(id='test',label='<img src=x onerror=alert(1)>',provider='synthetic',split='development',annotation_status='partial_positive',fixed_reference_summary=dict(chain_count=2,covered_positive_events=3,singleton_positive_events=4,min_chain_events=2,max_chain_events=3,paths_are_exhaustive=False,paths_containing_synthetic_lineage=2,independent_attack_count=None),variants=variants),null_case],
        data_readiness=[dict(dataset='E3',provider='test',status='ready',reason='合成检查，不代表实测'),dict(dataset='E5',provider='test',status='annotation_only',reason='只有标注，无匹配日志')])


def subgraph_fixture(base, blob):
    cases=[]
    for case in base['cases']:
        known=case['annotation_status']!='unavailable'
        summaries={scope:dict(input_events=5,excluded_synthetic_events=1 if scope=='native' else 0,synthetic_events=0 if scope=='native' else 1,inferred_host_dependencies=0,unverifiable_time_events=0,include_synthetic=scope=='augmented') for scope in ['native','augmented']}
        variants=[]
        for variant in case['variants']:
            rows=[]
            for row in variant['rows']:
                scopes={}
                for scope in ['native','augmented']:
                    count=2 if scope=='native' else 3
                    complete=count if row['budget']>=20 else (1 if scope=='native' else 0)
                    metrics=dict(reference_subgraph_count=count,complete_subgraphs=complete,subgraph_retention=complete/count,reference_events=4 if scope=='native' else 5,retained_reference_events=3,event_retention=.75 if scope=='native' else .6,singleton_event_count=1,retained_singleton_events=1,terminal_pairs=2,reachable_terminal_pairs=1,terminal_reachability=.5,reference_dependencies=4,retained_dependencies=2,dependency_retention=.5,fork_count=1,complete_forks=0,fork_retention=0.,join_count=1,complete_joins=0,join_retention=0.,independent_attack_count=None,attack_stage_completeness=None,first_loss_counts={'candidate':0,'temporal_eligible':0,'retained':count-complete,'surviving':complete},subgraph_stage_counts={'source':count,'candidate':count,'temporal_eligible':count,'retained':complete},event_stage_counts={'source':4,'candidate':4,'temporal_eligible':4,'retained':3})
                    if row['budget']>=20:
                        metrics['retained_reference_events']=metrics['reference_events'];metrics['event_retention']=1.
                        metrics.update(reachable_terminal_pairs=2,terminal_reachability=1.,retained_dependencies=4,dependency_retention=1.,complete_forks=1,fork_retention=1.,complete_joins=1,join_retention=1.)
                    if not known:metrics={key:None for key in metrics}
                    scopes[scope]=metrics
                rows.append({key:row.get(key) for key in ['method','budget','retained_events','compression','fixed_scope_compression']}|{'scopes':scopes})
            variants.append({key:variant[key] for key in ['track','poi_policy','candidate_events','source_scope_events','poi_count']}|{'rows':rows})
        cases.append({key:case.get(key) for key in ['id','label','provider','annotation_status','reference_sha256','source_positive_snapshot_sha256']}|{'positive_count':5 if known else None,'source_missing_positive_events':0 if known else None,'reference_summaries':summaries,'variants':variants})
    return {'schema_version':'chain-subgraph-report-v1','base_report_sha256':hashlib.sha256(blob).hexdigest(),'methods':base['methods'],'cases':cases}


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        self.path=self.path.removeprefix('/assets')
        super().do_GET()
    def log_message(self,*_args):pass


def run(args):
    frontend=ROOT/'webapp/frontend'
    assert (frontend/'research-workbench.html').exists(),'research overview is not implemented'
    server=None
    if args.base_url:origin=args.base_url.rstrip('/')
    else:
        server=ThreadingHTTPServer(('127.0.0.1',0),partial(Handler,directory=str(frontend)))
        Thread(target=server.serve_forever,daemon=True).start();origin=f'http://127.0.0.1:{server.server_port}'
    output=Path(args.output);output.mkdir(parents=True,exist_ok=True)
    checks=[]
    try:
        with sync_playwright() as pw:
            browser=pw.chromium.launch(headless=True)
            page=browser.new_page(viewport=dict(width=1440,height=1100));errors=[]
            page.on('pageerror',lambda error:errors.append(str(error)))
            fixture_bytes=json.dumps(fixture(),ensure_ascii=False).encode('utf-8')
            page.route('**/chain-workbench-summary.json',lambda route:route.fulfill(body=fixture_bytes,content_type='application/json'))
            page.route('**/chain-subgraph-summary.json',lambda route:route.fulfill(status=404,body='missing'))
            export_catalog={'entries':[{'id':'exact fixture / 10','study_version':'chain-workbench-v2','case_id':fixture()['cases'][0]['id'],'track':'base','poi_policy':'declared','method':'reliability_chain','budget_edges':10}]}
            page.route('**/retained-chain-catalog.json',lambda route:route.fulfill(json=export_catalog))
            page.goto(origin+'/assets/research-workbench.html')
            page.locator('#workbench-content').wait_for(state='visible')
            assert '候选事件条目预算' in page.locator('#comparison-note').inner_text()
            assert 'LINEAGE' in page.locator('#comparison-note').inner_text()
            assert page.locator('#exact-export-link').is_visible()
            assert page.locator('#exact-export-link').get_attribute('href')=='/assets/retained-chains.html?entry=exact%20fixture%20%2F%2010'
            assert '精确对应' in page.locator('#export-point-note').inner_text()
            for control, alternate, original in [('track-select','expanded','base'),('poi-select','single','declared'),('method-select','rarity_only','reliability_chain'),('case-select','1','0')]:
                page.locator('#'+control).select_option(alternate)
                assert page.locator('#exact-export-link').is_hidden(), control
                page.locator('#'+control).select_option(original)
                page.locator('#poi-select').select_option('declared')
                page.locator('#method-select').select_option('reliability_chain')
                assert page.locator('#exact-export-link').is_visible(), control
            assert page.locator('#curve-title').inner_text()=='压缩率—完整参考链保留率'
            assert page.locator('#retention-chart polyline').count()==7
            assert page.locator('#retention-chart circle').count()==14
            assert page.locator('#metric-verified .metric-value').inner_text()=='N/A'
            assert page.locator('#metric-reference .metric-value').inner_text()=='1 / 2'
            assert page.locator('#comparison-rows tr').count()==7
            assert '开发集' in page.locator('#case-note').inner_text()
            coverage=page.locator('#reference-coverage-note').inner_text()
            assert '3 / 7' in coverage and '4 个' in coverage
            assert '2 / 2' in coverage and 'LINEAGE' in coverage and '完全依赖' in coverage
            assert '仅有标注' in page.locator('#readiness-rows').inner_text()
            assert page.locator('img').count()==0
            assert '<img src=x onerror=alert(1)>' in page.locator('#case-select').inner_text()
            assert [cell.inner_text() for cell in page.locator('#stage-rows td.stage-count').all()]==['9','8','7','7']
            page.locator('#budget-select').select_option('20')
            assert page.locator('#exact-export-link').is_hidden()
            assert '未找到' in page.locator('#export-point-note').inner_text()
            page.locator('#point-export-command').locator('xpath=parent::details/summary').click()
            assert 'scripts.export_chain_workbench' in page.locator('#point-export-command').inner_text()
            checks.append('exact export link requires matching case/track/POI/method/integer budget')
            assert page.locator('#metric-reference .metric-value').inner_text()=='2 / 2'
            assert all('20'==cell.inner_text() for cell in page.locator('#comparison-rows td.raw-budget').all())
            page.locator('#track-select').select_option('expanded')
            assert page.locator('#metric-candidate .metric-value').inner_text()=='200'
            page.locator('#poi-select').select_option('adaptive')
            assert '5' in page.locator('#variant-note').inner_text()
            page.locator('#method-select').select_option('rarity_only')
            assert page.locator('#metric-retained .metric-value').inner_text()=='19'
            page.locator('#point-buttons button').first.focus();page.keyboard.press('Enter')
            assert page.locator('#budget-select').input_value()=='10'
            assert page.locator('#metric-retained .metric-value').inner_text()=='9'
            checks.extend(['all-method primary curve','exact raw-budget comparison','case/track/POI/method/budget controls','development scope','independent truth N/A','stage absolute counts','keyboard points','safe text','annotation-only E5'])
            page.screenshot(path=str(output/'fixture-desktop.png'),full_page=True)
            page.set_viewport_size(dict(width=390,height=844))
            assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth')
            assert page.locator('.chart-label').first.bounding_box()['height']>=9, 'mobile chart labels must remain readable'
            page.screenshot(path=str(output/'fixture-mobile.png'))
            checks.append('390px responsive layout')
            page.locator('#case-select').select_option('1')
            assert page.locator('#metric-reference .metric-value').inner_text()=='N/A'
            assert page.locator('#retention-chart circle').count()==0
            assert '没有可定义' in page.locator('#chart-note').inner_text()
            assert page.locator('#stage-rows td.stage-count').first.inner_text()=='N/A'
            checks.append('null and zero-denominator metrics')
            sidecar=subgraph_fixture(fixture(),fixture_bytes)
            page.unroute('**/chain-subgraph-summary.json')
            page.route('**/chain-subgraph-summary.json',lambda route:route.fulfill(json=sidecar))
            page.reload();page.locator('#subgraph-content').wait_for(state='visible')
            assert page.locator('#subgraph-curve-title').inner_text()=='压缩率—参考事件保留率'
            assert page.locator('#retention-target-result').get_attribute('data-budget')=='20'
            method_before=page.locator('#method-select').input_value()
            page.locator('#apply-retention-target').click()
            assert page.locator('#budget-select').input_value()=='20'
            assert page.locator('#method-select').input_value()==method_before
            assert '离线' in page.locator('#retention-target-note').inner_text()
            page.locator('#budget-select').select_option('10')
            page.locator('#subgraph-metric-select').select_option('dependency_retention')
            assert '依赖保留率' in page.locator('#subgraph-curve-title').inner_text()
            page.locator('#subgraph-metric-select').select_option('subgraph_retention')
            assert '完整参考子图' in page.locator('#subgraph-curve-title').inner_text()
            page.locator('#subgraph-metric-select').select_option('event_retention')
            assert page.locator('#subgraph-chart circle').count()==14
            assert page.locator('#subgraph-metric-complete .metric-value').inner_text()=='1 / 2'
            assert page.locator('#subgraph-metric-verified .metric-value').inner_text()=='N/A'
            assert page.locator('#metric-reference .metric-value').inner_text()=='1 / 2'
            page.locator('#subgraph-scope').select_option('augmented')
            assert page.locator('#subgraph-metric-complete .metric-value').inner_text()=='0 / 3'
            assert '分母' in page.locator('#subgraph-scope-note').inner_text()
            assert 'LINEAGE' in page.locator('#subgraph-quality-note').inner_text()
            assert page.locator('#subgraph-stage-rows tr').count()==4
            page.locator('#subgraph-point-buttons button').last.focus();page.keyboard.press('Enter')
            assert page.locator('#budget-select').input_value()=='20'
            assert page.locator('#subgraph-metric-complete .metric-value').inner_text()=='3 / 3'
            assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth')
            assert page.locator('#subgraph-chart').evaluate("svg => { const axis = svg.querySelectorAll('.chart-axis-title')[1].getBoundingClientRect(); const ticks = [...svg.querySelectorAll('.chart-label')].filter((_, index) => index % 2 === 0); return ticks.every(tick => axis.right + 2 < tick.getBoundingClientRect().left); }"), 'mobile vertical title must not overlap percentage ticks'
            page.locator('#subgraph-panel').screenshot(path=str(output/'subgraph-fixture-mobile.png'))
            page.locator('#case-select').select_option('1')
            assert page.locator('#subgraph-metric-complete .metric-value').inner_text()=='N/A'
            assert page.locator('#subgraph-chart circle').count()==0
            assert page.locator('#apply-retention-target').is_disabled()
            assert page.locator('#retention-target-result').get_attribute('data-status')=='unavailable'
            checks.append('offline joint retention floor selects an observed budget, preserves method and rejects unavailable references')
            checks.extend(['optional subgraph native/augmented denominators','subgraph dependency/fork/join and stage metrics','subgraph independent attacks N/A','subgraph keyboard budget and 390px layout'])
            sidecar['base_report_sha256']='0'*64
            page.reload();page.locator('#subgraph-status').wait_for(state='visible')
            page.wait_for_function("() => document.querySelector('#subgraph-status').textContent.includes('哈希')")
            assert page.locator('#workbench-content').is_visible()
            assert page.locator('#subgraph-content').is_hidden()
            sidecar['base_report_sha256']=hashlib.sha256(fixture_bytes).hexdigest()
            sidecar['cases'][0]['variants'][0]['rows'][0]['scopes']['augmented']['subgraph_retention']=1.
            page.reload();page.wait_for_function("() => document.querySelector('#subgraph-status').textContent.includes('比例')")
            assert page.locator('#subgraph-content').is_hidden()
            sidecar['cases'][0]['variants'][0]['rows'][0]['scopes']['augmented']['subgraph_retention']=0.
            checks.append('subgraph curve ratio must equal its numerator and denominator')
            sidecar['cases'][0]['variants'][0]['rows'][0]['retained_events']+=1
            page.reload();page.wait_for_function("() => document.querySelector('#subgraph-status').textContent.includes('冻结决策')")
            assert page.locator('#workbench-content').is_visible()
            checks.append('subgraph stale hash and mismatched decision rejected without breaking v2')
            page.unroute('**/chain-subgraph-summary.json')
            page.route('**/chain-subgraph-summary.json',lambda route:route.fulfill(status=404,body='missing'))
            page.reload();page.wait_for_function("() => document.querySelector('#subgraph-status').textContent.includes('尚未')")
            assert page.locator('#workbench-content').is_visible()
            checks.append('missing subgraph sidecar preserves original report')
            page.unroute('**/chain-workbench-summary.json')
            page.route('**/chain-workbench-summary.json',lambda route:route.fulfill(status=404,body='missing'))
            page.reload();page.locator('#load-error').wait_for(state='visible')
            assert 'chain-workbench-summary.json' in page.locator('#load-error').inner_text()
            checks.append('missing aggregate guidance')
            if args.report:
                report=json.loads(Path(args.report).read_text())
                page.unroute('**/chain-workbench-summary.json')
                page.unroute('**/retained-chain-catalog.json')
                page.unroute('**/chain-subgraph-summary.json')
                if args.base_url:
                    with build_opener(ProxyHandler({})).open(origin+'/assets/chain-workbench-summary.json') as response:
                        assert json.load(response)==report, 'live summary differs from the supplied expected report'
                    checks.append('live HTTP summary matches expected report; browser response not intercepted')
                else:
                    page.route('**/chain-workbench-summary.json',lambda route:route.fulfill(body=Path(args.report).read_bytes(),content_type='application/json'))
                actual_subgraphs=None
                if args.subgraph_report:
                    actual_subgraphs=json.loads(Path(args.subgraph_report).read_text())
                    assert actual_subgraphs['base_report_sha256']==hashlib.sha256(Path(args.report).read_bytes()).hexdigest()
                    if args.base_url:
                        with build_opener(ProxyHandler({})).open(origin+'/assets/chain-subgraph-summary.json') as response:
                            assert json.load(response)==actual_subgraphs, 'live subgraph summary differs from supplied expected sidecar'
                    else:
                        page.route('**/chain-subgraph-summary.json',lambda route:route.fulfill(json=actual_subgraphs))
                page.set_viewport_size(dict(width=1440,height=1100));page.reload()
                page.locator('#workbench-content').wait_for(state='visible')
                if actual_subgraphs:page.locator('#subgraph-content').wait_for(state='visible')
                count=0;subgraph_checks=0
                for ci,case in enumerate(report['cases']):
                    page.locator('#case-select').select_option(str(ci))
                    for variant in case['variants']:
                        page.locator('#track-select').select_option(variant['track'])
                        page.locator('#poi-select').select_option(variant['poi_policy'])
                        assert page.locator('#metric-candidate .metric-value').inner_text().replace(',','')==str(variant['candidate_events'])
                        for method in dict.fromkeys(row['method'] for row in variant['rows']):
                            rows=[r for r in variant['rows'] if r['method']==method]
                            page.locator('#method-select').select_option(method)
                            for row in [rows[0],rows[-1]]:
                                page.locator('#budget-select').select_option(str(row['budget']))
                                assert page.locator('#metric-retained .metric-value').inner_text().replace(',','')==str(row['retained_events'])
                                expected='N/A' if not row['reference_chain_count'] or row['reference_chain_retention'] is None else f"{row['retained_reference_chains']:,} / {row['reference_chain_count']:,}"
                                assert page.locator('#metric-reference .metric-value').inner_text()==expected
                                count+=1
                                if actual_subgraphs:
                                    source_case=next(c for c in actual_subgraphs['cases'] if c['id']==case['id'])
                                    source_variant=next(v for v in source_case['variants'] if v['track']==variant['track'] and v['poi_policy']==variant['poi_policy'])
                                    source_row=next(r for r in source_variant['rows'] if r['method']==method and r['budget']==row['budget'])
                                    for scope in ['native','augmented']:
                                        page.locator('#subgraph-scope').select_option(scope)
                                        metrics=source_row['scopes'][scope]
                                        expected='N/A' if not metrics['reference_subgraph_count'] else f"{metrics['complete_subgraphs']:,} / {metrics['reference_subgraph_count']:,}"
                                        assert page.locator('#subgraph-metric-complete .metric-value').inner_text()==expected
                                        assert page.locator('#subgraph-metric-verified .metric-value').inner_text()=='N/A'
                                        subgraph_checks+=1
                if actual_subgraphs:checks.append(f'actual subgraph sidecar: {subgraph_checks} exact method/variant/endpoint/scope checks')
                if args.base_url:
                    try:
                        with build_opener(ProxyHandler({})).open(origin+'/assets/retained-chain-catalog.json') as response:
                            linked_catalog=json.load(response)
                    except HTTPError as error:
                        if error.code!=404:raise
                        linked_catalog={'entries':[]}
                    linked=0
                    for entry in linked_catalog.get('entries',[]):
                        if entry.get('study_version')!='chain-workbench-v2':continue
                        target=next(((i,case) for i,case in enumerate(report['cases']) if case['id']==entry['case_id']),None)
                        if target is None:continue
                        ci,case=target
                        target_variant=next((v for v in case['variants'] if v['track']==entry['track'] and v['poi_policy']==entry['poi_policy']),None)
                        assert target_variant is not None, 'v2 catalog references an unknown frozen variant'
                        assert any(r['method']==entry['method'] and r['budget']==entry['budget_edges'] for r in target_variant['rows'])
                        page.locator('#case-select').select_option(str(ci))
                        page.locator('#track-select').select_option(entry['track'])
                        page.locator('#poi-select').select_option(entry['poi_policy'])
                        page.locator('#method-select').select_option(entry['method'])
                        page.locator('#budget-select').select_option(str(entry['budget_edges']))
                        assert page.locator('#exact-export-link').is_visible()
                        assert page.locator('#exact-export-link').get_attribute('href')=='/assets/retained-chains.html?entry='+quote(entry['id'],safe='')
                        linked+=1
                    checks.append(f'live exact representative-export links: {linked} matching frozen decisions')
                for name,match in [('cadets13',lambda item:item['id']=='cadets13'),('trace',lambda item:'trace' in item['id'].lower())]:
                    target=next(((i,case) for i,case in enumerate(report['cases']) if match(case)),None)
                    if target is None:continue
                    ci,case=target
                    page.locator('#case-select').select_option(str(ci))
                    preferred=next((v for v in case['variants'] if v['track']==('expanded' if name=='cadets13' else 'base') and v['poi_policy']=='adaptive'),case['variants'][0])
                    page.locator('#track-select').select_option(preferred['track'])
                    page.locator('#poi-select').select_option(preferred['poi_policy'])
                    available={r['method'] for r in preferred['rows']}
                    method='reliability_chain' if 'reliability_chain' in available else preferred['rows'][0]['method']
                    page.locator('#method-select').select_option(method)
                    values=[r['budget'] for r in preferred['rows'] if r['method']==method]
                    page.locator('#budget-select').select_option(str(1024 if 1024 in values else values[0]))
                    page.evaluate('window.scrollTo(0,0)')
                    page.screenshot(path=str(output/f'overview-{name}.png'))
                    page.locator('#reference-coverage-note').screenshot(path=str(output/f'overview-{name}-reference-scope.png'))
                    page.locator('#curve-title').locator('xpath=ancestor::section[1]').screenshot(path=str(output/f'overview-{name}-curve.png'))
                    if actual_subgraphs:
                        for scope in ['native','augmented']:
                            page.locator('#subgraph-scope').select_option(scope)
                            page.locator('#subgraph-panel').screenshot(path=str(output/f'overview-{name}-subgraphs-{scope}.png'))
                            page.set_viewport_size(dict(width=390,height=844))
                            assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth')
                            page.locator('#subgraph-panel').evaluate("node=>node.scrollIntoView({block:'start'})")
                            page.screenshot(path=str(output/f'overview-{name}-subgraphs-{scope}-mobile.png'))
                            page.locator('#subgraph-chart').screenshot(path=str(output/f'overview-{name}-subgraphs-{scope}-mobile-curve.png'))
                            page.set_viewport_size(dict(width=1440,height=1100))
                page.evaluate('window.scrollTo(0,0)');page.screenshot(path=str(output/'actual-desktop.png'))
                page.set_viewport_size(dict(width=390,height=844))
                assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth')
                page.screenshot(path=str(output/'actual-mobile.png'))
                checks.append(f'actual report: {len(report["cases"])} cases, {count} method/variant endpoint checks')
            assert not errors,errors
            browser.close()
    finally:
        if server:server.shutdown();server.server_close()
    result=dict(status='passed',checks=checks,browser_errors=[])
    (output/'verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--subgraph-report',help='Optional expected additive subgraph summary, bound to exact --report bytes.');parser.add_argument('--base-url',help='Use a running app; with --report, verify its real HTTP summary without interception.');parser.add_argument('--report',help='Expected aggregate JSON; local mode supplies it as a fixture, live mode checks the served copy.');parser.add_argument('--output',default='/tmp/nodoze-workbench-browser')
    run(parser.parse_args())
