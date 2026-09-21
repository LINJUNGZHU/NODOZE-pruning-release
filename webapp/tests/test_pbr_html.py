from pathlib import Path

from bs4 import BeautifulSoup


ROOT = Path(__file__).resolve().parents[2]


def _page():
    return BeautifulSoup(
        (ROOT / "webapp/frontend/index.html").read_text(encoding="utf-8"),
        "html.parser",
    )


def test_each_dataset_compares_only_retained_methods():
    page = _page()
    datasets = page.select("#algorithm-comparison [data-dataset]")

    assert [section["data-dataset"] for section in datasets] == [
        "CADETS_E3", "TRACE_E3",
    ]
    for section in datasets:
        assert [row["data-algorithm"] for row in section.select("[data-algorithm]")] == [
            "A_rasp", "A_rasp-PBR", "C_branch_fair",
        ]
        assert section.select_one('[data-algorithm="A_rasp-PBR"] .recommended')


def test_both_formal_pbr_results_and_scope_are_visible():
    page = _page()
    text = page.select_one("#algorithm-comparison").get_text(" ", strip=True)

    assert "CADETS E3" in text
    assert "TRACE E3" in text
    assert "845" in text
    assert "31 / 32" in text
    assert "38 / 39" in text
    assert "28 / 28" in text
    assert "11,232" in text
    assert "19 / 19" in text
    assert "11 / 11" in text
    assert "9 / 9" in text
    assert "20,000" in text
    assert "ORTHRUS" in text
    assert "KAIROS" in text


def test_advantages_are_visualized_as_accessible_charts():
    page = _page()

    assert [card["data-capability"] for card in page.select(".capability-card")] == [
        "attack-nodes", "attack-paths", "graph-pruning",
    ]
    for dataset in page.select("#algorithm-comparison [data-dataset]"):
        charts = dataset.select("[data-chart]")
        assert {chart["data-chart"] for chart in charts} == {
            "attack-node-retention", "attack-edge-retention",
            "attack-path-retention", "graph-pruning",
        }
        assert all(chart.get("aria-label") for chart in charts)
        assert len(dataset.select(".chart-bar[data-method]")) >= 8


def test_legacy_algorithm_picker_is_removed_from_html():
    html = (ROOT / "webapp/frontend/index.html").read_text(encoding="utf-8")

    assert 'id="algorithm-mode"' not in html
    assert "完整 RASP-RCVP" not in html
    assert "关系感知" not in html
    assert "当前默认" not in html
