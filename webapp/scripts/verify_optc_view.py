"""Exercise the redesigned workspace against actual full-size cases and APIs."""
import json
import os
from pathlib import Path
import sys
import time
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from webapp.scripts.verify_attack_report import verify as verify_attack
from webapp.scripts.verify_decision_audit import verify as verify_decision


def main():
    url=os.environ.get('NODOZE_TEST_URL','http://127.0.0.1:8000');runtime=ROOT/'webapp/runtime'
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=['--no-sandbox','--no-proxy-server'])
        page=browser.new_page(viewport={'width':1440,'height':1100});errors=[]
        page.on('pageerror',lambda e:errors.append(str(e)))
        page.goto(url);page.wait_for_function('state.data && !state.busy',timeout=90000)
        original=page.evaluate('({id:state.data.dataset.id,poi:state.data.poi.event_id,algorithm:state.data.algorithm,detector:state.data.attack.detector,q:state.data.attack.config.anomaly_quantile})')
        base=url+'/api/datasets/'+original['id'];catalog=page.request.get(url+'/api/datasets').json()['datasets']
        snapshots=[]
        def run():
            with page.expect_response(lambda r:r.url.endswith('/prune') and r.request.method=='POST',timeout=90000) as response:page.click('#apply-poi')
            page.wait_for_function('!state.busy',timeout=90000)
            return response.value
        try:
            assert len(catalog)>=4
            for entry in catalog:
                start=time.monotonic();page.click(f'[data-case="{entry["id"]}"]')
                page.wait_for_function('(id)=>state.data?.dataset.id===id && !state.busy',arg=entry['id'],timeout=90000)
                page.wait_for_function('document.querySelector("#before").dataset.renderedEdges===String(state.data.metrics.candidate_edges)',timeout=90000)
                counts=page.evaluate('({raw:Number(document.querySelector("#before").dataset.renderedEdges),kept:Number(document.querySelector("#after").dataset.renderedEdges),m:state.data.metrics,sampled:state.data.graph.sampled,unique:new Set(state.data.graph.edges.map(e=>e[0])).size})')
                assert counts['raw']==counts['unique']==entry['metrics']['candidate_edges']
                assert counts['kept']==counts['m']['retained_edges'] and not counts['sampled']
                snapshots.append(dict(id=entry['id'],edges=counts['raw'],kept=counts['kept'],load_and_draw_seconds=time.monotonic()-start))
                print('Full graph verified',snapshots[-1],flush=True)
                if entry['id'].endswith('60m'):
                    page.screenshot(path=str(runtime/'workspace-large.png'),full_page=True)
                    page.set_viewport_size({'width':390,'height':844})
                    assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
                    page.screenshot(path=str(runtime/'workspace-mobile.png'),full_page=True);page.set_viewport_size({'width':1440,'height':1100})
            page.click(f'[data-case="{original["id"]}"]');page.wait_for_function('(id)=>state.data.dataset.id===id&&!state.busy',arg=original['id'],timeout=90000)
            inferred=page.evaluate('state.data.attack.nodes.filter(n=>n.predicted_attack).map(n=>n.id)')
            assert page.locator('#attack-nodes [data-node]').count()==len(inferred)
            page.locator('#attack-nodes [data-node]').first.click();assert page.locator('#detail-dialog').is_visible()
            assert page.locator('#detail-content [data-event]').count()>0
            page.locator('#detail-content [data-event]').first.click();page.wait_for_function('document.querySelector("#detail-title").textContent==="原始事件与评分依据"')
            assert '来源行' in page.locator('#detail-content').inner_text();page.click('#close-detail')
            assert 'TAPAS' in page.locator('#tapas-evaluation').inner_text()
            page.click('#view-activity');page.wait_for_function('state.table?.total===state.data.attack.summary.activity_edges')
            page.click('#tab-attack')
            report=page.request.get(base+'/attack-report').json();assert verify_attack(report)['rule_witnesses_verified']
            assert verify_attack(report)['activity_membership_verified']
            for path in report['attack']['paths']:
                page.select_option('#attack-path-select',path['id'])
                assert page.locator('#attack-path [data-path-node]').count()==len(path['node_ids'])
                assert page.locator('#attack-path-events button').count()==len(path['event_ids'])
            page.click('#tab-events');page.wait_for_selector('#edge-rows [data-event]')
            assert page.locator('#edge-rows tr').count()==20
            page.select_option('#edge-decision','removed');page.wait_for_function('state.table?.edges.length && state.table.edges.every(e=>!e.retained)')
            page.click('#next-page');page.wait_for_function('state.table.page===1')
            page.click('#clear-edge');page.fill('#edge-search',original['poi'])
            page.wait_for_function('(id)=>state.table?.total===1 && state.table.edges[0].id===id',arg=original['poi'])
            page.locator('#edge-rows [data-event]').first.click();page.wait_for_selector('#use-event-poi');page.click('#use-event-poi')
            assert page.input_value('#poi-id')==original['poi']
            page.click('#clear-edge');page.click('#tab-attack')
            other=page.evaluate('(id)=>state.data.poi_presets.find(p=>p.event_id!==id).event_id',original['poi'])
            old_history=page.evaluate('state.data.history.history_edges');page.select_option('#poi-select',other)
            assert run().status==200
            assert page.evaluate('state.data.history.history_edges')!=old_history
            assert page.evaluate('state.data.history.last_event_ns < state.data.history.cutoff_ns')
            page.select_option('#poi-select','custom');page.fill('#poi-id','not-an-event')
            assert run().status==400
            assert page.evaluate('state.data.poi.event_id')==other
            page.select_option('#poi-select',original['poi']);assert run().status==200
            assert page.locator('#error').is_hidden()
            page.select_option('#detector','rules_legacy');assert run().status==200
            assert page.evaluate('state.data.attack.detector')=='rules_legacy'
            assert page.evaluate('state.data.attack.summary.inferred_attack_nodes')<len(inferred)
            page.select_option('#detector','neural');assert run().status==200
            assert page.evaluate('state.data.attack.detector')=='neural'
            assert page.evaluate('state.data.attack.contract.truth_used') is False
            assert page.evaluate('state.data.attack.model.weights_sha256')
            assert '深度学习' in page.locator('#attack-summary').inner_text()
            neural_report=page.request.get(base+'/attack-report').json();assert verify_attack(neural_report)['roles_verified']
            page.screenshot(path=str(runtime/'workspace-neural.png'),full_page=True)
            page.select_option('#detector','rules');assert run().status==200
            assert set(page.evaluate('state.data.attack.nodes.filter(n=>n.predicted_attack).map(n=>n.id)'))==set(inferred)
            # Both pruning modes still have replayable decision certificates.
            for mode in ('evidence','context'):
                page.locator('.advanced').first.evaluate('(e)=>e.open=true');page.select_option('#selection-mode',mode)
                assert run().status==200
                assert verify_decision(page.request.get(base+'/decision-audit').json())['greedy_ranking_replayed']
            page.locator('.advanced').first.evaluate('(e)=>e.open=false');page.screenshot(path=str(runtime/'workspace-desktop.png'),full_page=True)
            assert not errors,errors
        finally:
            restored=page.request.post(base+'/prune',data=dict(poi_event_id=original['poi'],budget_ratio=original['algorithm']['budget_ratio'],
                    selection_mode=original['algorithm']['selection_mode'],detector=original['detector'],attack_quantile=original['q'],compact=True),timeout=90000)
            assert restored.status==200
            browser.close()
        result=dict(cases=snapshots,browser_errors=errors,mobile_overflow=False,checks=['all events drawn once','all four real cases','node evidence and paths','paginated event search','manual POI and failure recovery','enhanced/legacy/neural recompute','TAPAS and public labels displayed separately','complete activity log filter','download audit replay','original state restored'])
        (ROOT/'docs/rule-lineage-browser-verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(result,ensure_ascii=False),flush=True)


if __name__=='__main__':main()
