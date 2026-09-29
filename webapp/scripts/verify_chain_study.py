"""Exercise the static chain dashboard with deterministic, non-benchmark data."""
from __future__ import annotations

import argparse
import json
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]


def fixture():
    def metric(n, d):
        return {"numerator": n, "denominator": d, "value": n / d if d else None}

    events = [
        {"event_id": "event-a", "src": "b", "dst": "a", "src_label": "进程 B", "dst_label": "<img src=x onerror=alert(1)>", "relation": "EVENT_EXECUTE", "causal_direction": "dst_to_src", "timestamp_ns": "1234567890123456789"},
        {"event_id": "event-b", "src": "b", "dst": "c", "src_label": "进程 B", "dst_label": "文件 C", "relation": "WRITE", "timestamp_ns": "1234567890123456790"},
    ]
    events[0]["evidence"] = {"raw_rarity": 0.72, "novelty": 0.61, "contextual_surprise": 0.23, "confidence": 0.18, "anomaly_score": 0.09, "reason": "历史支持不足，新颖行为保持待核验", "score_rasp": 0.84, "score_contextual": 0.35}
    rows = []
    for method in ["baseline", "adaptive"]:
        for budget, kept in [(0.1, ["event-a"]), (0.2, ["event-a", "event-b"])]:
            full = len(kept) == 2
            stages = {
                "candidate": {"reference_chain_count": 1, "reference_chain_retention": metric(1, 1)},
                "retained": {"reference_chain_count": int(full), "reference_chain_retention": metric(int(full), 1)},
            }
            rows.append({
                "method": method, "budget_ratio": budget, "budget_edges": round(100 * budget),
                "retained_edges": round(100 * budget), "actual_compression": 1 - budget,
                "complete_reference_retention": metric(int(full), 1),
                "verified_attack_chain_retention": metric(0, 0), "candidate_chain_coverage": metric(1, 1),
                "positive_event_retention": metric(len(kept), 2), "retained_event_ids": [event.upper() for event in kept],
                "chain_evaluation": {"stage_order": ["candidate", "retained"], "stages": stages,
                    "first_loss_counts": {"candidate": 0, "retained": int(not full)},
                    "event_funnel": {"reference_event_count": 2, "first_loss_counts": {"candidate": 0, "retained": int(not full)}, "stages": {
                        "candidate": {"retained_event_count": 2, "total_retention": metric(2, 2), "conditional_retention": metric(2, 2), "missing_ids": [], "lost_ids": []},
                        "retained": {"retained_event_count": len(kept), "total_retention": metric(len(kept), 2), "conditional_retention": metric(len(kept), 2), "missing_ids": [] if full else ["event-b"], "lost_ids": [] if full else ["event-b"]}}},
                    "chains": [{"id": "chain-1", "admission_status": "admitted", "required_event_ids": ["event-a", "event-b"], "missing_source_ids": [], "first_loss_stage": None if full else "retained", "stages": {"candidate": {"complete": True, "missing_ids": []}, "retained": {"complete": full, "missing_ids": [] if full else ["event-b"]}}, "breakpoints": []}]},
                "diagnostics": {"history": "fixture"},
            })
    # Match the published report: per-point chains do not repeat reference identities.
    for row in rows:
        evaluator = row["chain_evaluation"]
        evaluator["stage_order"] = ["candidate", "temporal_eligible", "bundle_eligible", "retained"]
        for name in ("temporal_eligible", "bundle_eligible"):
            evaluator["stages"][name] = evaluator["stages"]["candidate"]
            evaluator["first_loss_counts"][name] = 0
            evaluator["event_funnel"]["stages"][name] = evaluator["event_funnel"]["stages"]["candidate"]
            evaluator["event_funnel"]["first_loss_counts"][name] = 0
        for chain in evaluator["chains"]:
            for name in ("temporal_eligible", "bundle_eligible"):
                chain["stages"][name] = {"complete": True}
            chain["stages"] = {name: {"complete": stage["complete"]} for name, stage in chain["stages"].items()}
            chain["source_validation"] = {"status": "valid", "valid": True}
            for key in list(chain):
                if key not in {"id", "source_validation", "admission_status", "first_loss_stage", "stages"}:
                    del chain[key]
    return {"schema_version": "adaptive-chain-study-v1", "generated_at": "2026-09-29T00:00:00Z", "methodology": {"scope": "合成浏览器检查，不代表实验成绩"}, "cases": [{
        "id": "fixture", "label": "合成浏览器检查", "kind": "synthetic", "reference_scope": "合成参考范围", "candidate_edges": 100,
        "source_provenance": {"source": "test-only"}, "reference_chains": [{"id": "chain-1", "title": "两事件参考链", "kind": "synthetic", "event_ids": ["event-a", "event-b"], "events": events}], "results": rows}]}


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        self.path = self.path.removeprefix("/assets")
        super().do_GET()

    def log_message(self, *_args):
        pass


def verify_fixture():
    frontend = ROOT / "webapp" / "frontend"
    assert (frontend / "chain-study.html").exists(), "chain dashboard is not implemented"
    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, directory=str(frontend)))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1360, "height": 980})
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.route("**/chain-study-results.json", lambda route: route.fulfill(json=fixture()))
            url = f"http://127.0.0.1:{server.server_port}/assets/chain-study.html"
            page.goto(url)
            page.locator("#study-content").wait_for(state="visible")
            assert page.locator("#curve-title").inner_text() == "压缩率—完整参考链保留率"
            assert page.locator("#metric-verified .metric-value").inner_text() == "N/A"
            page.locator("#budget-select").select_option("0")
            assert page.locator(".event-row.missing").count() == 1
            assert page.locator("#chain-events").inner_text().find("1234567890123456789") >= 0
            assert page.locator("#chain-events img").count() == 0
            assert "时序见证覆盖" in page.locator("#stage-rows").inner_text()
            assert "完整路径束可用" in page.locator("#stage-rows").inner_text()
            assert "<img src=x onerror=alert(1)>" in page.locator("#chain-events .event-row").first.locator(".event-node").first.inner_text(), "EXECUTE must render destination-to-source causal flow"
            assert "目标 → 源" in page.locator("#chain-events").inner_text()
            assert page.locator(".event-evidence").count() == 1, "optional evidence appears only where supplied"
            assert "0.72" in page.locator(".event-evidence summary").inner_text()
            page.locator(".event-evidence summary").click()
            assert "上下文偏离" in page.locator(".event-evidence").inner_text()
            assert "0.23" in page.locator(".event-evidence").inner_text()
            assert "置信度反映历史支持" in page.locator(".event-evidence").inner_text()
            assert "<img src=x onerror=alert(1)>" in page.locator("#chain-events").inner_text()
            page.locator("#budget-select").select_option("1")
            assert page.locator(".event-row.missing").count() == 0
            page.locator("#method-select").select_option("baseline")
            assert page.locator("#point-buttons button").count() == 2
            page.locator("#point-buttons button").first.focus()
            page.keyboard.press("Enter")
            assert page.locator("#budget-select").input_value() == "0"
            branched = fixture()
            extra = {"event_id": "event-c", "src": "b", "dst": "d", "src_label": "进程 B", "dst_label": "分支 D", "relation": "SEND", "timestamp_ns": "1234567890123456791"}
            branched["cases"][0]["reference_chains"][0]["branches"] = [["event-c"]]
            branched["cases"][0]["reference_chains"][0]["events"].append(extra)
            for row in branched["cases"][0]["results"]:
                row["retained_event_ids"].append("EVENT-C")
            page.unroute("**/chain-study-results.json")
            page.route("**/chain-study-results.json", lambda route: route.fulfill(json=branched))
            page.reload()
            page.locator("#study-content").wait_for(state="visible")
            assert page.locator("#chain-events .event-row").count() == 3, "primary witness and branch must both be visible"
            assert page.locator("#branch-select option").count() == 3
            page.locator("#branch-select").select_option("1")
            assert page.locator("#chain-events .event-row").count() == 1
            page.set_viewport_size({"width": 390, "height": 844})
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            assert not errors, errors
            summary = fixture()
            summary["data_visibility"] = "aggregate_only"
            for case in summary["cases"]:
                case["reference_chain_count"] = len(case["reference_chains"])
                case["reference_chains"] = []
                for row in case["results"]:
                    row["retained_event_ids"] = []
                    row["chain_evaluation"]["chains"] = []
            summary_requests = []
            def serve_summary(route):
                summary_requests.append(route.request.url)
                route.fulfill(json=summary)
            page.unroute("**/chain-study-results.json")
            page.route("**/chain-study-results.json", lambda route: route.fulfill(status=404, body="missing"))
            page.route("**/chain-study-summary.json", serve_summary)
            page.reload()
            page.locator("#study-content").wait_for(state="visible")
            assert "仅展示汇总指标；完整链事件请在本机生成详细报告" in page.locator("#aggregate-notice").inner_text()
            assert page.locator("#retention-chart polyline").count() > 0
            assert page.locator("#metric-complete .metric-value").inner_text() == "1 / 1"
            assert page.locator("#chain-events .event-row").count() == 0
            assert "1 条固定参考链" in page.locator("#chain-list").inner_text()
            assert page.locator("#download-report").get_attribute("href") == "/assets/chain-study-summary.json"
            assert len(summary_requests) == 1
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            summary_requests.clear()
            page.unroute("**/chain-study-results.json")
            page.route("**/chain-study-results.json", lambda route: route.fulfill(status=403, body="forbidden"))
            page.reload()
            page.locator("#load-error").wait_for(state="visible")
            assert "403" in page.locator("#load-error-detail").inner_text()
            assert not summary_requests, "access denied must not trigger aggregate fallback"
            page.unroute("**/chain-study-results.json")
            page.route("**/chain-study-results.json", lambda route: route.fulfill(status=404, body="missing"))
            page.unroute("**/chain-study-summary.json")
            page.route("**/chain-study-summary.json", lambda route: route.fulfill(status=404, body="missing"))
            page.reload()
            page.locator("#load-error").wait_for(state="visible")
            assert "生成" in page.locator("#load-error").inner_text()
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
    print(json.dumps({"ok": True, "checks": ["404-only aggregate fallback", "403 fails without fallback", "both reports missing", "compact evaluator schema", "contextual evidence", "EXECUTE causal direction", "branches", "metric scope", "null verified metric", "missing edges", "exact timestamps", "safe text", "budget and keyboard controls", "mobile layout", "missing report state"]}, ensure_ascii=False))


def verify_report(report_path: Path, output: Path, base_url: str | None = None):
    report = json.loads(report_path.read_text())
    frontend = ROOT / "webapp" / "frontend"
    server = None
    if base_url is None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, directory=str(frontend)))
        Thread(target=server.serve_forever, daemon=True).start()
        base_url = f"http://127.0.0.1:{server.server_port}"
    output.mkdir(parents=True, exist_ok=True)
    checks = []
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1440, "height": 1060})
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            if server is not None:
                page.route("**/chain-study-results.json", lambda route: route.fulfill(path=str(report_path.resolve()), content_type="application/json"))
            page.goto(f"{base_url.rstrip('/')}/assets/chain-study.html")
            page.locator("#study-content").wait_for(state="visible", timeout=120000)
            for case_index, case in enumerate(report["cases"]):
                page.locator("#case-select").select_option(str(case_index))
                assert page.locator("#metric-candidate .metric-value").inner_text() == format(case["candidate_edges"], ",")
                methods = sorted({row["method"] for row in case["results"]})
                method_checks = 0
                for method in methods:
                    page.locator("#method-select").select_option(method)
                    rows = sorted([row for row in case["results"] if row["method"] == method], key=lambda row: row["budget_ratio"])
                    assert page.locator("#point-buttons button").count() == len(rows)
                    for point_index in sorted({0, len(rows) - 1}):
                        page.locator("#budget-select").select_option(str(point_index))
                        expected = rows[point_index]
                        retention = expected["complete_reference_retention"]
                        denominator = retention.get("denominator")
                        expected_count = f'{retention["numerator"]:,} / {denominator:,}' if denominator else "N/A"
                        assert page.locator("#metric-complete .metric-value").inner_text() == expected_count
                        assert page.locator("#metric-retained .metric-value").inner_text() == format(expected["retained_edges"], ",")
                        if not (expected.get("verified_attack_chain_retention") or {}).get("denominator"):
                            assert page.locator("#metric-verified .metric-value").inner_text() == "N/A"
                        assert "temporal_eligible" not in page.locator("#stage-rows").inner_text()
                        assert "bundle_eligible" not in page.locator("#stage-rows").inner_text()
                        method_checks += 1
                if "adaptive" in methods:
                    page.locator("#method-select").select_option("adaptive")
                page.locator("#budget-select").select_option("0")
                for chain_index, chain in enumerate(case["reference_chains"]):
                    if len(chain.get("event_ids", [])) > 40:
                        page.locator("#chain-list button").nth(chain_index).click()
                        assert page.locator("#chain-events .event-row").count() == 40
                        page.locator("#event-next").click()
                        assert page.locator("#chain-events .event-row").count() > 0
                        break
                if case_index == 0:
                    page.evaluate("window.scrollTo(0, 0)")
                    page.screenshot(path=str(output / "desktop.png"))
                    page.locator(".chart-panel").screenshot(path=str(output / "curve.png"))
                    page.locator("#chain-title").scroll_into_view_if_needed()
                    page.screenshot(path=str(output / "chain-events.png"))
                page.set_viewport_size({"width": 390, "height": 844})
                assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), case["id"]
                if case_index == 0:
                    page.evaluate("window.scrollTo(0, 0)")
                    page.screenshot(path=str(output / "mobile.png"))
                page.set_viewport_size({"width": 1440, "height": 1060})
                checks.append({"case": case["id"], "methods": len(methods), "budget_checks": method_checks, "reference_chains": case.get("reference_chain_count", len(case["reference_chains"])), "data_visibility": report.get("data_visibility", "detailed"), "mobile_overflow": False})
            assert not errors, errors
            browser.close()
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
    result = {"ok": True, "report": str(report_path), "cases": checks, "console_errors": errors}
    (output / "verification.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, help="Also verify a real generated report.")
    parser.add_argument("--output", type=Path, default=Path("/tmp/nodez-chain-real-check"))
    parser.add_argument("--base-url", help="Verify an already running app without intercepting its report response.")
    args = parser.parse_args()
    verify_fixture()
    if args.report:
        verify_report(args.report, args.output, args.base_url)
