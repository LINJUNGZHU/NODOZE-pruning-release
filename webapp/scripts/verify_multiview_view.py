"""Browser regression for learned views and evidence-bound summaries."""
import json
import os
from pathlib import Path
import sys
from urllib.request import build_opener, ProxyHandler
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from webapp.scripts.verify_attack_report import verify


def main():
    url=os.environ.get('NODOZE_TEST_URL','http://127.0.0.1:8001');results=[];errors=[]
    http=build_opener(ProxyHandler({}))
    def download(path):
        # Large raw exports should not cross Playwright’s browser IPC transport.
        with http.open(url+path,timeout=90) as response:
            return json.load(response)
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=['--no-sandbox','--no-proxy-server'])
        page=browser.new_page(viewport=dict(width=1440,height=1100))
        page.on('pageerror',lambda e:errors.append(str(e)))
        page.goto(url);page.wait_for_function('state.data && !state.busy',timeout=90000)
        original=page.evaluate('({id:state.data.dataset.id,poi:state.data.poi.event_id,detector:state.data.attack.detector})')
        def analyze(detector):
            page.select_option('#detector',detector)
            with page.expect_response(lambda r:r.url.endswith('/prune') and r.request.method=='POST',timeout=90000) as response:
                page.click('#apply-poi')
            page.wait_for_function('!state.busy',timeout=90000)
            assert response.value.status==200,response.value.text()[:500]
            assert page.evaluate('state.data.attack.detector')==detector
        try:
            catalog=page.request.get(url+'/api/datasets').json()
            assert catalog['multiview_available']
            for entry in catalog['datasets']:
                page.click(f'[data-case="{entry["id"]}"]')
                page.wait_for_function('(id)=>state.data?.dataset.id===id&&!state.busy',arg=entry['id'],timeout=90000)
                analyze('multiview')
                page.wait_for_function('Number(document.querySelector("#before").dataset.renderedEdges)===state.data.metrics.candidate_edges',timeout=90000)
                assert page.locator('#quantile-control').is_hidden()
                assert 'TAPAS' in page.locator('#tapas-evaluation').inner_text()
                assert page.locator('#attack-story').is_visible()
                page.locator('#attack-nodes [data-node]').first.click()
                assert page.locator('.view-evidence meter').count()==3
                assert '不是攻击概率' in page.locator('#detail-content').inner_text()
                page.locator('#detail-content [data-event]').first.click()
                page.wait_for_function('document.querySelector("#detail-title").textContent==="原始事件与评分依据"')
                page.click('#close-detail')
                report=download(f'/api/datasets/{entry["id"]}/attack-report')
                checks=verify(report);assert checks['story_facts_verified'] and checks['activity_membership_verified']
                page.locator('#attack-story [data-event]').first.click()
                page.wait_for_function('document.querySelector("#detail-title").textContent==="原始事件与评分依据"')
                page.click('#close-detail')
                assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
                page.set_viewport_size(dict(width=390,height=844))
                assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
                page.set_viewport_size(dict(width=1440,height=1100))
                results.append(dict(id=entry['id'],full_edges=entry['metrics']['candidate_edges'],
                    predictions=report['attack']['summary']['inferred_attack_nodes'],verification=checks))
                print(results[-1],flush=True)
            page.click(f'[data-case="{original["id"]}"]')
            page.wait_for_function('(id)=>state.data.dataset.id===id&&!state.busy',arg=original['id'],timeout=90000)
            analyze('rules')
            assert page.locator('#attack-nodes [data-node]').count()==9
            assert page.locator('#attack-story article').count()==3
            (ROOT/'docs/figures').mkdir(exist_ok=True)
            page.screenshot(path=str(ROOT/'docs/figures/paper-fusion-workspace.png'),full_page=True)
            assert not errors,errors
        finally:
            # Restore every private test cache to the established default detector.
            for entry in page.request.get(url+'/api/datasets').json()['datasets']:
                view=download(f'/api/datasets/{entry["id"]}/view')
                page.request.post(url+f'/api/datasets/{entry["id"]}/prune',data=dict(poi_event_id=view['poi']['event_id'],detector='rules',compact=True),timeout=90000)
            browser.close()
    (ROOT/'docs/multiview-browser-verification.json').write_text(json.dumps(dict(cases=results,errors=errors,desktop_overflow=False,mobile_overflow=False),indent=2)+'\n')


if __name__=='__main__':main()
