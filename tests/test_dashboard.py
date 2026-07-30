from datetime import date, datetime, timedelta

from qday.dashboard.html import project_completion, render_dashboard
from qday.risk import score_asset
from qday.scanners.certs import CertFileScanner
from qday.store import Store


def _hist(points):
    t0 = datetime(2026, 1, 1)
    return [{"started_at": (t0 + timedelta(days=d)).isoformat(),
             "total": total, "vulnerable": vulnerable}
            for d, total, vulnerable in points]


def test_projection_linear_progress():
    projected = project_completion(_hist([(0, 10, 10), (100, 10, 5)]))
    assert projected is not None
    assert projected.date() == date(2026, 7, 20)


def test_projection_needs_two_runs():
    assert project_completion(_hist([(0, 10, 5)])) is None
    assert project_completion([]) is None


def test_projection_flat_or_worsening_trend():
    assert project_completion(_hist([(0, 10, 5), (100, 10, 5)])) is None
    assert project_completion(_hist([(0, 10, 2), (100, 10, 8)])) is None


def test_projection_already_done():
    projected = project_completion(_hist([(0, 10, 5), (100, 10, 0)]))
    assert projected.date() == date(2026, 4, 11)


def test_projection_skips_empty_runs():
    hist = _hist([(0, 0, 0), (10, 10, 10), (110, 10, 5)])
    assert project_completion(hist) is not None


def test_dashboard_renders_burndown_card(cert_dir, tmp_path):
    store = Store(tmp_path / "d.db")
    assets = list(CertFileScanner(cert_dir).scan())
    scores = {a.asset_id: score_asset(a) for a in assets}
    store.save_run(assets, scores)
    html = render_dashboard(store)
    assert "Burndown projection" in html
    assert "at least two scan runs" in html
