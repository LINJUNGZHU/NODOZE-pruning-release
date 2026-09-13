"""Read-only browser and export regression against prepared example caches."""
import json
import os
from pathlib import Path
import sys
from urllib.request import build_opener,ProxyHandler
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from webapp.scripts.verify_attack_report import verify


def main():
    url=os.environ.get('NODOZE_TEST_URL','http://127.0.0.1:8001');http=build_opener(ProxyHandler({}));results=[];errors=[]
    def get(path):
        with http.open(url+path,timeout=90) as response:return json.load(response)
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=['--no-sandbox','--no-proxy-server'])
        page=browser.new_page(viewport=dict(width=1440,height=1100));page.on('pageerror',lambda e:errors.append(str(e)))
        page.goto(url);page.wait_for_function('state.data&&!state.busy',timeout=90000)
        for entry in get('/api/datasets')['datasets']:
            page.click(f'[data-case="{entry["id"]}"]')
            page.wait_for_function('(id)=>state.data?.dataset.id===id&&!state.busy',arg=entry['id'],timeout=90000)
            assert 'PDF' in page.locator('#attack-evaluation').inner_text()
            assert page.locator('#tapas-evaluation').count()==0
            page.select_option('#graph-view','investigation')
            page.wait_for_function('Number(document.querySelector("#after").dataset.renderedEdges)===state.data.context_graph.summary.selected_events')
            assert page.evaluate('Number(document.querySelector("#before").dataset.renderedEdges)===state.data.metrics.candidate_edges')
            assert page.evaluate('document.querySelector("#metrics").children[1].children[1].textContent===fmt(state.data.context_graph.summary.selected_events)')
            page.locator('#pdf-reference summary').click()
            assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
            page.set_viewport_size(dict(width=390,height=844));assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
            page.set_viewport_size(dict(width=1440,height=1100))
            page.click('#tab-events');page.select_option('#edge-decision','context_graph')
            page.wait_for_function('state.table?.total===state.data.context_graph.summary.selected_events')
            if page.evaluate('state.table.total>0'):
                page.locator('#edge-rows [data-event]').first.click();page.wait_for_function('document.querySelector("#detail-dialog").open');page.click('#close-detail')
            document=get(f'/api/datasets/{entry["id"]}/attack-report');checks=verify(document)
            assert checks['context_bundle_references_verified']
            results.append(dict(id=entry['id'],context=document['context_graph']['summary'],pdf=document['attack']['evaluation']['pdf_benchmark']['node_metrics'],verification=checks))
            print(entry['id'],'PASS',flush=True)
            page.click('#tab-attack')
            if entry['id']=='optc-0201':page.screenshot(path=str(ROOT/'docs/figures/pdf-context-workspace.png'),full_page=True)
        assert not errors,errors;browser.close()
    (ROOT/'docs/pdf-context-browser-verification.json').write_text(json.dumps(dict(cases=results,page_errors=errors,desktop_overflow=False,mobile_overflow=False),ensure_ascii=False,indent=2)+'\n')


if __name__=='__main__':main()
