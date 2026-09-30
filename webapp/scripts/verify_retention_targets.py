"""Check every offline target profile against the live workbench controls."""
import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from urllib.request import ProxyHandler, build_opener

from playwright.sync_api import sync_playwright


def run(args):
    report=json.loads(Path(args.analysis).read_text())
    opener=build_opener(ProxyHandler({}))
    origin=args.base_url.rstrip('/')
    blob=opener.open(origin+'/assets/chain-subgraph-summary.json').read()
    assert hashlib.sha256(blob).hexdigest()==report['source_report_sha256']
    subgraphs=json.loads(blob)
    groups=defaultdict(list)
    for row in report['rows']:
        groups[(row['case_id'],row['track'],row['poi_policy'],row['method'],row['scope'])].append(row)
    output=Path(args.output);output.mkdir(parents=True,exist_ok=True)
    errors=[];checks=0;applied=0
    with sync_playwright() as pw:
        browser=pw.chromium.launch(headless=True)
        page=browser.new_page(viewport=dict(width=1440,height=1100))
        page.on('pageerror',lambda error:errors.append(str(error)))
        page.goto(origin+'/assets/research-workbench.html')
        page.locator('#subgraph-content').wait_for(state='visible')
        case_order=page.locator('#case-select option').evaluate_all('(nodes) => nodes.map(n => n.value)')
        base=json.loads(opener.open(origin+'/assets/chain-workbench-summary.json').read())
        assert len(case_order)==len(base['cases'])
        indexes={c['id']:i for i,c in enumerate(base['cases'])}
        for index,(key,rows) in enumerate(groups.items()):
            case,track,poi,method,scope=key
            outcomes=page.evaluate('''({index,track,poi,method,scope,rows}) => {
                const change=(id,value)=>{const n=document.getElementById(id);n.value=String(value);n.dispatchEvent(new Event('change',{bubbles:true}));};
                change('case-select',index);change('track-select',track);change('poi-select',poi);change('method-select',method);change('subgraph-scope',scope);
                return rows.map(row=>{
                    change('retention-target',row.target);
                    const terminal=document.getElementById('retention-terminals');terminal.checked=row.require_terminals;terminal.dispatchEvent(new Event('change',{bubbles:true}));
                    const result=document.getElementById('retention-target-result');
                    return {status:result.dataset.status,budget:result.dataset.budget||null,disabled:document.getElementById('apply-retention-target').disabled};
                });
            }''',dict(index=indexes[case],track=track,poi=poi,method=method,scope=scope,rows=rows))
            for row,actual in zip(rows,outcomes):
                assert actual['status']==row['status'],(key,row['target'],actual,row['status'])
                assert actual['budget']==(str(row['selected']['budget']) if row['selected'] else None),(key,row,actual)
                assert actual['disabled']==(row['status']!='met')
                checks+=1
            # Last profile is 100% plus terminals; applying never changes method/POI.
            last=rows[-1]
            if last['status']=='met':
                page.locator('#apply-retention-target').click()
                assert page.locator('#budget-select').input_value()==str(last['selected']['budget'])
                assert page.locator('#method-select').input_value()==method
                assert page.locator('#poi-select').input_value()==poi
                applied+=1
            if index%100==0: print(f'Validated {checks} target profiles',flush=True)
        for case,track in [('cadets06','base'),('cadets13','base'),('cadets13','expanded'),('theia-case3','base'),('trace-case5-paper','base')]:
            page.locator('#case-select').select_option(str(indexes[case]))
            page.locator('#track-select').select_option(track)
            page.locator('#poi-select').select_option('declared')
            page.locator('#method-select').select_option('reliability_chain')
            page.locator('#subgraph-scope').select_option('native')
            page.locator('#retention-target').select_option('.95' if page.locator('#retention-target option[value=".95"]').count() else '0.95')
            page.locator('#retention-terminals').uncheck()
            page.locator('#subgraph-metric-select').select_option('event_retention')
            page.locator('.retention-target-box').screenshot(path=str(output/f'{case}-{track}-desktop.png'))
            page.set_viewport_size(dict(width=390,height=844))
            assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
            page.locator('.retention-target-box').screenshot(path=str(output/f'{case}-{track}-mobile.png'))
            page.locator('#subgraph-chart').screenshot(path=str(output/f'{case}-{track}-mobile-curve.png'))
            page.set_viewport_size(dict(width=1440,height=1100))
        assert not errors,errors
        browser.close()
    result=dict(status='passed',target_profiles_checked=checks,exact_budget_applications=applied,
                browser_errors=errors,source_report_sha256=report['source_report_sha256'],
                desktop_and_390px=True,live_responses_not_intercepted=True)
    (output/'verification.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--analysis',required=True)
    parser.add_argument('--base-url',default='http://127.0.0.1:8000')
    parser.add_argument('--output',required=True)
    run(parser.parse_args())
