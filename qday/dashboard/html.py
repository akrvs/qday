"""Server-rendered dashboard page: migration progress vs. PQC deadlines.

Pure HTML/CSS from store data — no JS framework, no external assets, so the
page works air-gapped (the audience includes defense suppliers).
"""

from __future__ import annotations

import html as _html
from datetime import date, datetime, timedelta

from ..store import Store

# Regulatory milestones the progress is tracked against.
DEADLINES = (
    ("2027-01-01", "CNSA 2.0: new national-security systems PQC-only"),
    ("2030-12-31", "NIST IR 8547: 112-bit-security algorithms deprecated"),
    ("2035-12-31", "NIST / CNSA 2.0: quantum-vulnerable crypto disallowed"),
)

_RISK_ORDER = ("critical", "high", "medium", "low", "none")
# Status palette (validated set) — always paired with a text label.
_RISK_COLOR = {"critical": "#d03b3b", "high": "#ec835a",
               "medium": "#fab219", "low": "#0ca30c", "none": "#898781"}
_RISK_ICON = {"critical": "&#9650;", "high": "&#9650;", "medium": "&#9679;",
              "low": "&#9660;", "none": "&#9660;"}

_CSS = """
:root {
  --surface: #fcfcfb; --page: #f9f9f7; --ink: #0b0b0b; --ink-2: #52514e;
  --muted: #898781; --grid: #e1e0d9; --border: rgba(11,11,11,0.10);
  --accent: #256abf; --track: #e1e0d9;
}
@media (prefers-color-scheme: dark) {
  :root {
    --surface: #1a1a19; --page: #0d0d0d; --ink: #ffffff; --ink-2: #c3c2b7;
    --muted: #898781; --grid: #2c2c2a; --border: rgba(255,255,255,0.10);
    --accent: #3987e5; --track: #2c2c2a;
  }
}
* { box-sizing: border-box; margin: 0; }
body { background: var(--page); color: var(--ink); padding: 24px;
       font-family: system-ui, -apple-system, "Segoe UI", sans-serif; }
h1 { font-size: 20px; } h1 small { color: var(--muted); font-weight: 400; }
h2 { font-size: 13px; color: var(--ink-2); text-transform: uppercase;
     letter-spacing: .04em; margin-bottom: 10px; }
.card { background: var(--surface); border: 1px solid var(--border);
        border-radius: 8px; padding: 16px; margin-top: 16px; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
         gap: 16px; margin-top: 16px; }
.tile { background: var(--surface); border: 1px solid var(--border);
        border-radius: 8px; padding: 14px 16px; }
.tile .v { font-size: 26px; font-weight: 650; }
.tile .k { font-size: 12px; color: var(--ink-2); margin-top: 2px; }
.bar-track { background: var(--track); border-radius: 4px; height: 10px;
             overflow: hidden; margin-top: 8px; }
.bar-fill { background: var(--accent); height: 100%; border-radius: 4px 0 0 4px; }
.deadlines { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
             gap: 12px; }
.deadline { border-left: 2px solid var(--grid); padding-left: 10px; }
.deadline .d { font-weight: 650; }
.deadline .days { color: var(--ink-2); font-size: 13px; }
.deadline .what { color: var(--muted); font-size: 12px; margin-top: 2px; }
.dist { display: grid; grid-template-columns: max-content 1fr max-content;
        gap: 6px 10px; align-items: center; }
.dist .label { font-size: 13px; color: var(--ink-2); }
.dist .n { font-size: 13px; font-variant-numeric: tabular-nums; }
.dist .track { background: none; height: 12px; }
.dist .fill { height: 12px; border-radius: 0 4px 4px 0; min-width: 2px; }
.deltagrid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
             gap: 20px; }
.deltahead { font-size: 13px; font-weight: 650; margin-bottom: 8px; }
.deltahead .n { color: var(--muted); font-weight: 400; }
.deltarow { display: flex; align-items: baseline; gap: 8px; padding: 3px 0;
            font-size: 13px; border-bottom: 1px solid var(--grid); }
.deltarow .sign { font-weight: 700; width: 12px; }
.deltarow .dloc { color: var(--ink-2); overflow: hidden; text-overflow: ellipsis;
                  white-space: nowrap; }
.wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th { text-align: left; color: var(--muted); font-weight: 500;
     border-bottom: 1px solid var(--grid); padding: 6px 10px 6px 0; }
td { border-bottom: 1px solid var(--grid); padding: 6px 10px 6px 0;
     white-space: nowrap; }
td.num { font-variant-numeric: tabular-nums; }
.chip { font-size: 12px; }
.footnote { color: var(--muted); font-size: 12px; margin-top: 12px; }
"""


def render_dashboard(store: Store) -> str:
    run_id = store.latest_run_id()
    if run_id is None:
        return _page("<p>No scan runs yet. Run <code>qday scan</code>.</p>")

    info = store.run_info(run_id)
    rows = store.assets_for_run(run_id)
    total = len(rows)
    vulnerable = sum(r["quantum_vulnerable"] for r in rows)
    safe_pct = 100.0 * (total - vulnerable) / total if total else 0.0
    critical = sum(1 for r in rows if r["risk_level"] == "critical")

    tiles = f"""
    <div class="tiles">
      <div class="tile"><div class="v">{total}</div>
        <div class="k">crypto assets inventoried</div></div>
      <div class="tile"><div class="v">{vulnerable}</div>
        <div class="k">quantum-vulnerable</div></div>
      <div class="tile"><div class="v">{critical}</div>
        <div class="k">critical risk</div></div>
      <div class="tile"><div class="v">{safe_pct:.0f}%</div>
        <div class="k">PQC-safe (migrated)</div>
        <div class="bar-track"><div class="bar-fill"
             style="width:{safe_pct:.1f}%"></div></div></div>
    </div>"""

    today = date.today()
    dl = []
    for iso, what in DEADLINES:
        d = date.fromisoformat(iso)
        days = (d - today).days
        dl.append(f"""<div class="deadline"><div class="d">{d.year}</div>
          <div class="days">{days:,} days remaining</div>
          <div class="what">{_esc(what)}</div></div>""")
    deadlines = ('<div class="card"><h2>Deadline timeline</h2>'
                 f'<div class="deadlines">{"".join(dl)}</div></div>')

    counts = {lvl: 0 for lvl in _RISK_ORDER}
    for r in rows:
        counts[r["risk_level"] or "none"] += 1
    peak = max(counts.values()) or 1
    dist_rows = []
    for lvl in _RISK_ORDER:
        n = counts[lvl]
        width = 100.0 * n / peak
        dist_rows.append(
            f'<span class="label">{_RISK_ICON[lvl]} {lvl}</span>'
            f'<span class="track"><span class="fill" '
            f'style="width:{width:.1f}%;background:{_RISK_COLOR[lvl]}">'
            f'</span></span><span class="n">{n}</span>')
    dist = ('<div class="card"><h2>Assets by risk level</h2>'
            f'<div class="dist">{"".join(dist_rows)}</div></div>')

    body_rows = []
    for r in rows[:50]:
        lvl = r["risk_level"] or "none"
        score = f"{r['risk_score']:.1f}" if r["risk_score"] is not None else "–"
        body_rows.append(
            f'<tr><td><span class="chip" style="color:{_RISK_COLOR[lvl]}">'
            f'{_RISK_ICON[lvl]}</span> {lvl}</td>'
            f'<td class="num">{score}</td>'
            f'<td>{_esc(r["algorithm"])}</td>'
            f'<td class="num">{r["key_size"] or "–"}</td>'
            f'<td>{_esc(r["asset_type"])}</td>'
            f'<td>{_esc(r["location"])}</td></tr>')
    table = ('<div class="card"><h2>Highest-risk assets</h2><div class="wrap">'
             '<table><tr><th>Risk</th><th>Score</th><th>Algorithm</th>'
             '<th>Bits</th><th>Type</th><th>Location</th></tr>'
             + "".join(body_rows) + "</table></div>"
             + (f'<div class="footnote">Showing 50 of {total} assets.</div>'
                if total > 50 else "") + "</div>")

    hist = store.run_history()
    diff_card = _diff_card(store, hist, run_id)
    hist_rows = "".join(
        f'<tr><td class="num">{h["id"]}</td><td>{_esc(h["started_at"])}</td>'
        f'<td>{_esc(h["label"] or "–")}</td><td class="num">{h["total"]}</td>'
        f'<td class="num">{h["vulnerable"]}</td>'
        f'<td class="num">{100.0 * (h["total"] - h["vulnerable"]) / h["total"]:.0f}%'
        f'</td></tr>'
        for h in hist if h["total"])
    trend = ('<div class="card"><h2>Scan history</h2><div class="wrap">'
             '<table><tr><th>Run</th><th>Started</th><th>Label</th>'
             '<th>Assets</th><th>Vulnerable</th><th>PQC-safe</th></tr>'
             + hist_rows + "</table></div></div>")

    label = f" — {_esc(info['label'])}" if info["label"] else ""
    header = (f'<h1>QDAY <small>run {run_id}{label} · '
              f'{_esc(info["started_at"])}</small></h1>')
    return _page(header + tiles + deadlines + _burndown_card(hist) + dist
                 + diff_card + table + trend)


def project_completion(history: list[dict]) -> datetime | None:
    points = []
    for h in history:
        if not h["total"]:
            continue
        t = datetime.fromisoformat(h["started_at"])
        pct = 100.0 * (h["total"] - h["vulnerable"]) / h["total"]
        points.append((t, pct))
    if len(points) < 2:
        return None
    if points[-1][1] >= 100.0:
        return points[-1][0]
    t0 = points[0][0]
    xs = [(t - t0).total_seconds() / 86400 for t, _ in points]
    ys = [pct for _, pct in points]
    n = len(points)
    mean_x, mean_y = sum(xs) / n, sum(ys) / n
    var = sum((x - mean_x) ** 2 for x in xs)
    if var == 0:
        return None
    slope = sum((x - mean_x) * (y - mean_y)
                for x, y in zip(xs, ys)) / var
    if slope <= 0:
        return None
    intercept = mean_y - slope * mean_x
    days = (100.0 - intercept) / slope
    if days - xs[-1] > 40000:
        return None
    return t0 + timedelta(days=days)


def _burndown_card(hist: list[dict]) -> str:
    usable = [h for h in hist if h["total"]]
    projected = project_completion(hist)
    if len(usable) < 2:
        body = ('<p class="footnote">Need at least two scan runs to fit a '
                'migration trend.</p>')
    elif projected is None:
        body = ('<p class="footnote">No downward trend yet — the PQC-safe '
                'share is flat or falling across runs.</p>')
    else:
        done = projected.date()
        verdicts = []
        for iso, what in DEADLINES:
            d = date.fromisoformat(iso)
            if done <= d:
                verdicts.append(
                    f'<div class="deadline"><div class="d" '
                    f'style="color:{_RISK_COLOR["low"]}">meets {d.year}</div>'
                    f'<div class="what">{_esc(what)}</div></div>')
            else:
                verdicts.append(
                    f'<div class="deadline"><div class="d" '
                    f'style="color:{_RISK_COLOR["critical"]}">misses {d.year} '
                    f'by {(done - d).days:,} days</div>'
                    f'<div class="what">{_esc(what)}</div></div>')
        body = (f'<p>Projected 100% PQC-safe: <b>{done.isoformat()}</b> '
                f'at the current pace.</p>'
                f'<div class="deadlines" style="margin-top:10px">'
                + "".join(verdicts) + "</div>")
    return f'<div class="card"><h2>Burndown projection</h2>{body}</div>'


def _diff_card(store: Store, hist: list[dict], run_id: int) -> str:
    """Movement since the previous run: what got introduced vs. retired.
    This is the migration signal — a snapshot can't show whether you're
    gaining or shedding vulnerable crypto."""
    prior = [h["id"] for h in hist if h["id"] < run_id]
    if not prior:
        return ('<div class="card"><h2>Change since last scan</h2>'
                '<p class="footnote">First recorded run — no prior scan to '
                'compare against yet.</p></div>')
    delta = store.diff_runs(prior[-1], run_id)
    new, resolved = delta["new"], delta["resolved"]

    def block(title, rows, sign, color):
        if not rows:
            items = '<div class="footnote">none</div>'
        else:
            items = "".join(
                f'<div class="deltarow"><span class="sign" '
                f'style="color:{color}">{sign}</span> '
                f'<span class="chip">{_esc(r["algorithm"])}</span> '
                f'<span class="dloc">{_esc(r["location"])}</span></div>'
                for r in rows[:15])
            if len(rows) > 15:
                items += (f'<div class="footnote">+{len(rows) - 15} more</div>')
        return (f'<div class="deltacol"><div class="deltahead">{title} '
                f'<span class="n">({len(rows)})</span></div>{items}</div>')

    return ('<div class="card"><h2>Change since last scan '
            f'(run {prior[-1]} &rarr; {run_id})</h2>'
            '<div class="deltagrid">'
            + block("New / regressed", new, "&plus;", _RISK_COLOR["critical"])
            + block("Resolved", resolved, "&minus;", _RISK_COLOR["low"])
            + "</div></div>")


def _esc(s) -> str:
    return _html.escape(str(s))


def _page(body: str) -> str:
    return (f"<!doctype html><html><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>QDAY dashboard</title><style>{_CSS}</style></head>"
            f"<body>{body}</body></html>")
