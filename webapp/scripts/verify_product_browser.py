"""Actual browser acceptance: node input, witness, export, reopen, mobile and offline records."""
import argparse
import json
import time
from pathlib import Path
from playwright.sync_api import sync_playwright


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--url',default='http://127.0.0.1:8002')
    parser.add_argument('--output',type=Path,default=Path('docs/product/screenshots'));args=parser.parse_args()
    args.output.mkdir(parents=True,exist_ok=True);notes={};errors=[]
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=['--no-sandbox'])
        page=browser.new_page(viewport={'width':1600,'height':1000})
        page.on('pageerror',lambda e:errors.append(str(e)))
        page.goto(args.url,wait_until='networkidle');page.wait_for_selector('.node-item')
        page.screenshot(path=str(args.output/'workspace-ready.png'),full_page=True)
        page.locator('#node-search').fill('powershell.exe');page.wait_for_timeout(500)
        page.locator('.node-item').first.click();page.wait_for_selector('.anchor-item');page.locator('.anchor-item').last.click()
        page.locator('#budget').fill('1000')
        t=time.monotonic();page.locator('#run-button').click()
        page.wait_for_selector('#result:not([hidden])',timeout=180000);page.wait_for_selector('[data-detail]',timeout=60000)
        page.wait_for_function("() => document.querySelector('#run-status').textContent.includes('独立调查已保存')")
        notes['full_ui_seconds']=round(time.monotonic()-t,3);notes['metrics']=page.locator('#metrics').inner_text()
        first=page.locator('#run-meta').inner_text();page.evaluate('window.scrollTo(0,0)')
        page.screenshot(path=str(args.output/'investigation-desktop.png'),full_page=True)
        page.locator('[data-detail]').first.click();page.wait_for_selector('#event-dialog[open]')
        assert page.locator('.witness-row').count()>0
        page.screenshot(path=str(args.output/'event-witness.png'));page.locator('#close-dialog').click()
        with page.expect_download() as download:page.locator('#export-json').click()
        downloaded=args.output/'evidence-download.json';download.value.save_as(str(downloaded))
        evidence=json.loads(downloaded.read_text());assert len(evidence['events'])==evidence['metrics']['retained_edges'];downloaded.unlink()
        notes['run_id']=evidence['run']['id'];notes['certificate']=evidence['certificate']
        with page.expect_download() as download:page.locator('#export-csv').click()
        notes['csv_download']=download.value.suggested_filename
        page.locator('#budget').fill('256');page.locator('#run-button').click()
        page.wait_for_function(f"() => document.querySelector('#run-meta').textContent.indexOf('{evidence['run']['id'][:10]}')===-1",timeout=180000)
        page.wait_for_function("() => document.querySelector('#run-status').textContent.includes('独立调查已保存')");page.wait_for_selector('[data-detail]')
        page.locator('#history-nav').click();page.wait_for_selector('.history-row')
        page.locator(f'[data-run="{evidence["run"]["id"]}"]').click();page.wait_for_selector('[data-detail]')
        assert page.locator('#run-meta').inner_text()==first
        page.set_viewport_size({'width':390,'height':844});page.wait_for_timeout(300);page.evaluate('window.scrollTo(0,0)')
        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth'), 'Mobile horizontal overflow'
        page.screenshot(path=str(args.output/'investigation-mobile.png'),full_page=True)
        # Frozen browser view must not depend on source cache or catalog.
        page.route('**/api/datasets**',lambda route:route.fulfill(status=503,content_type='application/json',body='{"error":"source offline"}'))
        page.reload(wait_until='networkidle');page.wait_for_selector('.history-row')
        page.locator(f'[data-run="{evidence["run"]["id"]}"]').click();page.wait_for_selector('[data-detail]')
        assert page.locator('#run-meta').inner_text()==first
        assert page.locator('#run-button').is_disabled()
        with page.expect_download() as download:page.locator('#export-json').click()
        assert download.value.suggested_filename.endswith('.json')
        notes['offline_reopen_and_export']=True;notes['mobile_overflow']=False;notes['browser_errors']=errors
        assert not errors,errors
        browser.close()
    (args.output.parent/'browser-validation.json').write_text(json.dumps(notes,ensure_ascii=False,indent=2))
    print(json.dumps(notes,ensure_ascii=False))


if __name__=='__main__':main()
