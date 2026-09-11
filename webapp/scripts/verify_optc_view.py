"""Check the actual OPTC page against the API, including mobile and interactions."""
import json
from pathlib import Path
import sys
from playwright.sync_api import sync_playwright

runtime=Path(__file__).resolve().parents[1]/'runtime'
sys.path.insert(0,str(runtime.parents[1]))
from webapp.scripts.verify_decision_audit import verify
with sync_playwright() as p:
    browser=p.chromium.launch(headless=True,args=['--no-sandbox','--no-proxy-server'])
    page=browser.new_page(viewport={'width':1440,'height':1100})
    errors=[]
    page.on('pageerror',lambda error:errors.append(str(error)))
    page.goto('http://127.0.0.1:8000')
    page.wait_for_function("document.querySelector('#health').textContent === '数据就绪'",timeout=60000)
    data=page.request.get('http://127.0.0.1:8000/api/datasets/optc-0201/graph').json()
    sample=set(data['display_event_ids'])
    visible=[e for e in data['edges'] if e['id'] in sample]
    kept=sum(e['retained'] for e in visible)
    assert page.locator('#before-count').inner_text().startswith(f'{len(visible)} 边')
    assert page.locator('#after-count').inner_text().startswith(f'{kept} 边')
    assert 0<kept<len(visible)
    assert page.locator('#before [stroke-dasharray]').count()>0
    assert page.locator('#after [stroke-dasharray]').count()==0
    assert page.locator('#run-log').inner_text().count('\n')>=4
    assert page.locator('#edge-rows tr').count()==30
    page.check('#show-scores')
    assert page.locator('#before .graph-edge text').count()==len(visible)
    page.locator('#before .graph-edge').first.click(force=True)
    assert page.locator('#event-detail').get_attribute('open') is not None
    page.select_option('#edge-decision','removed')
    assert set(page.locator('#edge-rows .badge').all_text_contents())=={'删除'}
    page.click('#next-page');assert '第 2 /' in page.locator('#page-info').inner_text()
    page.click('#clear-edge')
    seed=data['truth']['seed_event_id']
    page.fill('#edge-search',seed)
    assert page.locator('#edge-rows tr').count()==1
    page.locator('#edge-rows tr').first.click()
    assert seed in page.locator('#details').inner_text()
    page.click('#clear-edge')
    page.select_option('#edge-decision','reference')
    assert str(data['truth']['matched_events']) in page.locator('#edge-total').inner_text()
    page.click('#clear-edge');page.locator('#event-detail').evaluate('(e)=>e.open=false')
    original_poi=data['poi']['event_id']
    other=next(preset for preset in data['poi_presets'] if preset['event_id']!=original_poi)
    page.select_option('#poi-select',other['event_id'])
    assert page.input_value('#poi-id')==other['event_id']
    with page.expect_response(lambda r:r.url.endswith('/prune') and r.request.method=='POST',timeout=60000) as response:
        page.click('#apply-poi')
    assert response.value.status==200
    page.wait_for_function("!document.querySelector('#apply-poi').disabled",timeout=60000)
    changed=page.evaluate('({poi:state.data.poi,history:state.data.history})')
    assert changed['poi']['event_id']==other['event_id']
    assert changed['history']['history_edges']!=data['history']['history_edges']
    assert changed['history']['last_event_ns']<changed['history']['cutoff_ns']
    assert page.locator('#poi-evidence').inner_text().startswith('当前 POI：')
    assert '已应用' in page.locator('#prune-status').inner_text()
    page.fill('#poi-id','not-an-event')
    page.click('#apply-poi')
    page.wait_for_function("document.querySelector('#prune-status').textContent.includes('重算失败')",timeout=60000)
    assert not page.locator('#error').is_hidden()
    page.select_option('#poi-select',original_poi)
    with page.expect_response(lambda r:r.url.endswith('/prune') and r.request.method=='POST',timeout=60000):
        page.click('#apply-poi')
    page.wait_for_function("!document.querySelector('#apply-poi').disabled",timeout=60000)
    assert page.input_value('#poi-id')==original_poi
    assert page.locator('#error').is_hidden()
    assert page.locator('#edge-rows td:nth-child(4)').count()==30

    for mode in ('evidence','context'):
        page.select_option('#selection-mode',mode)
        with page.expect_response(lambda r:r.url.endswith('/prune') and r.request.method=='POST',timeout=60000):
            page.click('#apply-poi')
        page.wait_for_function("!document.querySelector('#apply-poi').disabled",timeout=60000)
        assert page.evaluate('state.data.decision_contract.mode')==mode
        audit=page.request.get('http://127.0.0.1:8000/api/datasets/optc-0201/decision-audit').json()
        assert verify(audit)['greedy_ranking_replayed']
        (runtime/f'{mode}-decision-audit.json').write_text(json.dumps(audit))
        assert '完整时序路径校验通过' in page.locator('#decision-summary').inner_text()
        assert '真实同分不会被扰动' in page.locator('#score-note').inner_text()
        if mode=='evidence':
            page.select_option('#edge-decision','connector')
            assert page.locator('#edge-rows tr[data-id]').count()>0
            assert '完整时序路径连接边' in page.locator('#edge-rows').inner_text()
            page.click('#clear-edge')
    assert page.locator('#edge-rows td:nth-child(3)').first.get_attribute('title') is not None
    page.uncheck('#show-scores');page.evaluate('window.scrollTo(0,0)')
    page.screenshot(path=str(runtime/'optc-desktop.png'),full_page=True)
    page.set_viewport_size({'width':390,'height':844})
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    page.screenshot(path=str(runtime/'optc-mobile.png'),full_page=True)
    assert not errors,errors
    print(json.dumps({'before':len(visible),'after':kept,'candidate_edges':len(data['edges']),'browser_errors':errors,'mobile':'passed','manual_poi_recompute':'passed','invalid_poi_recovery':'passed','both_modes_audit_replay':'passed'}))
    browser.close()
