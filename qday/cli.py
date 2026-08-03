"""Command-line entry point.

    qday scan  [--tls HOST[:PORT] ...] [--ssh HOST[:PORT] ...]
               [--discover HOST|CIDR[:PORTS] ...]
               [--certs DIR] [--code DIR] [--deps DIR] [--agility TOML]
               [--config qday.toml] [--fail-on LEVEL]
    qday report [--run ID] [--json]
    qday runs  [--json]
    qday trend [--json]
    qday prune (--keep N | --older-than DAYS) [--dry-run]
    qday diff  [--from ID] [--to ID] [--json] [--fail-on-new LEVEL]
    qday export [--run ID] -o cbom.json
    qday import CBOM.json [--label TEXT]
    qday serve  [--port 8080]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor

from .model import CryptoAsset
from .store import Store

DEFAULT_DB = "data/qday.db"

_LEVEL_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _parse_endpoints(targets: list[str], default_port: int,
                     kind: str) -> list[tuple[str, int]] | None:
    endpoints: list[tuple[str, int]] = []
    for target in targets:
        host, _, port = target.partition(":")
        port_num = int(port) if port.isdigit() else (
            default_port if not port else 0)
        if not host or not 0 < port_num < 65536:
            print(f"invalid {kind} target {target!r}: expected HOST[:PORT]",
                  file=sys.stderr)
            return None
        endpoints.append((host, port_num))
    return endpoints


def _cmd_scan(args: argparse.Namespace) -> int:
    from .config import DEFAULT_CONFIG, ConfigError, load_config

    tls_targets = list(args.tls or [])
    ssh_targets = list(args.ssh or [])
    cert_dirs = list(args.certs or [])
    code_dirs = list(args.code or [])
    dep_dirs = list(args.deps or [])
    agility_files = list(args.agility or [])
    annotations: list[dict] = []
    waivers: list[dict] = []

    config_path = args.config
    if config_path is None and os.path.exists(DEFAULT_CONFIG):
        config_path = DEFAULT_CONFIG
    if config_path:
        try:
            cfg = load_config(config_path)
        except (OSError, ConfigError) as exc:
            print(f"config error: {exc}", file=sys.stderr)
            return 2
        tls_targets += cfg["tls"]
        ssh_targets += cfg["ssh"]
        cert_dirs += cfg["certs"]
        code_dirs += cfg["code"]
        dep_dirs += cfg["deps"]
        agility_files += cfg["agility"]
        annotations = cfg["annotations"]
        waivers = cfg["waivers"]

    discover_specs = list(args.discover or [])
    if discover_specs:
        from .discovery import DiscoveryError, discover
        try:
            live = discover(discover_specs)
        except (DiscoveryError, ValueError) as exc:
            print(f"discovery error: {exc}", file=sys.stderr)
            return 2
        print(f"discovery: {len(live)} live endpoint(s) found")
        tls_targets += live

    if not (tls_targets or ssh_targets or cert_dirs or code_dirs or dep_dirs
            or agility_files):
        print("nothing to scan: pass --tls/--ssh/--certs/--code/--deps/"
              "--agility or add a [scan] section to qday.toml",
              file=sys.stderr)
        return 2

    assets: list[CryptoAsset] = []
    if tls_targets:
        from .scanners.tls import TlsScanner
        endpoints = _parse_endpoints(tls_targets, 443, "TLS")
        if endpoints is None:
            return 2
        # Handshakes are network-bound; a pool turns N × timeout into ~timeout.
        with ThreadPoolExecutor(max_workers=min(16, len(endpoints))) as pool:
            for result in pool.map(
                    lambda hp: list(TlsScanner(*hp).scan()), endpoints):
                assets.extend(result)
    if ssh_targets:
        from .scanners.ssh import SshScanner
        endpoints = _parse_endpoints(ssh_targets, 22, "SSH")
        if endpoints is None:
            return 2
        with ThreadPoolExecutor(max_workers=min(16, len(endpoints))) as pool:
            for result in pool.map(
                    lambda hp: list(SshScanner(*hp).scan()), endpoints):
                assets.extend(result)
    if cert_dirs:
        from .scanners.certs import CertFileScanner
        for d in cert_dirs:
            assets.extend(CertFileScanner(d).scan())
    if code_dirs:
        from .scanners.code import CodeScanner
        for d in code_dirs:
            assets.extend(CodeScanner(d).scan())
    if dep_dirs:
        from .scanners.deps import DepScanner
        for d in dep_dirs:
            assets.extend(DepScanner(d).scan())
    if agility_files:
        from .scanners.agility import AgilityScanner
        for f in agility_files:
            assets.extend(AgilityScanner(f).scan())

    annotated = 0
    if annotations:
        from .config import apply_annotations
        annotated = apply_annotations(assets, annotations)

    from .risk import score_asset
    scores = {a.asset_id: score_asset(a) for a in assets}

    waived = 0
    if waivers:
        from .config import apply_waivers
        waived = apply_waivers(assets, scores, waivers)

    store = Store(args.db)
    run_id = store.save_run(assets, scores, label=args.label)
    vulnerable = sum(1 for a in assets if a.quantum_vulnerable)
    note = f", {annotated} annotated via config" if annotated else ""
    note += f", {waived} waived" if waived else ""
    print(f"run {run_id}: {len(assets)} crypto assets found, "
          f"{vulnerable} quantum-vulnerable{note}  (db: {args.db})")

    if args.fail_on:
        threshold = _LEVEL_RANK[args.fail_on]
        worst = max((_LEVEL_RANK.get(level, 0)
                     for _, level in scores.values()), default=0)
        if worst >= threshold:
            print(f"fail-on={args.fail_on}: threshold met (exit 3)",
                  file=sys.stderr)
            return 3
    return 0


def _cmd_diff(args: argparse.Namespace) -> int:
    store = Store(args.db)
    history = store.run_history()
    if len(history) < 2 and not (args.from_run and args.to_run):
        print("need at least two runs to diff", file=sys.stderr)
        return 1
    from_id = args.from_run or history[-2]["id"]
    to_id = args.to_run or history[-1]["id"]
    delta = store.diff_runs(from_id, to_id)

    if args.json:
        print(json.dumps({"from": from_id, "to": to_id, **delta}, indent=2))
    else:
        print(f"run {from_id} -> run {to_id}: "
              f"+{len(delta['new'])} new, -{len(delta['resolved'])} resolved, "
              f"{len(delta['persisting'])} persisting")
        for tag, rows in (("+", delta["new"]), ("-", delta["resolved"])):
            for r in rows:
                print(f"  {tag} [{r['risk_level'] or '-'}] "
                      f"{r['algorithm']:<8} {r['asset_type']:<14} "
                      f"{r['location']}")

    if args.fail_on_new:
        threshold = _LEVEL_RANK[args.fail_on_new]
        worst = max((_LEVEL_RANK.get(r["risk_level"], 0)
                     for r in delta["new"]), default=-1)
        if worst >= threshold:
            print(f"fail-on-new={args.fail_on_new}: new asset at threshold "
                  "(exit 3)", file=sys.stderr)
            return 3
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    store = Store(args.db)
    run_id = args.run or store.latest_run_id()
    if run_id is None:
        print("no scan runs recorded yet — run `qday scan` first",
              file=sys.stderr)
        return 1
    from .risk import remediation
    rows = store.assets_for_run(run_id)
    for r in rows:
        r["remediation"] = remediation(r["algorithm"], r["asset_type"],
                                       r["key_size"])
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0

    info = store.run_info(run_id)
    total = len(rows)
    vulnerable = sum(r["quantum_vulnerable"] for r in rows)
    migrated_pct = 100.0 * (total - vulnerable) / total if total else 0.0
    print(f"Run {run_id}  ({info['started_at']}"
          + (f", label: {info['label']}" if info["label"] else "") + ")")
    print(f"Assets: {total}   quantum-vulnerable: {vulnerable}   "
          f"PQC-safe: {migrated_pct:.1f}%\n")
    fmt = "{:<9} {:<6} {:<8} {:<7} {:<14} {:<38} {}"
    print(fmt.format("RISK", "SCORE", "ALGO", "BITS", "TYPE", "MIGRATE-TO",
                     "LOCATION"))
    for r in rows:
        print(fmt.format(
            r["risk_level"] or "-",
            f"{r['risk_score']:.1f}" if r["risk_score"] is not None else "-",
            r["algorithm"], r["key_size"] or "-", r["asset_type"],
            r["remediation"] or "-", r["location"]))
    return 0


def _cmd_runs(args: argparse.Namespace) -> int:
    store = Store(args.db)
    history = store.run_history()
    if not history:
        print("no scan runs recorded yet — run `qday scan` first",
              file=sys.stderr)
        return 1
    for h in history:
        h["safe_pct"] = round(
            100.0 * (h["total"] - h["vulnerable"]) / h["total"], 1) \
            if h["total"] else 0.0
    if args.json:
        print(json.dumps(history, indent=2))
        return 0
    fmt = "{:<5} {:<21} {:>7} {:>11} {:>6}  {}"
    print(fmt.format("RUN", "STARTED", "ASSETS", "VULNERABLE", "SAFE%",
                     "LABEL"))
    for h in history:
        print(fmt.format(h["id"], h["started_at"], h["total"],
                         h["vulnerable"], f"{h['safe_pct']:.1f}",
                         h["label"] or "-"))
    return 0


def _cmd_trend(args: argparse.Namespace) -> int:
    store = Store(args.db)
    history = store.run_history()
    if not history:
        print("no scan runs recorded yet — run `qday scan` first",
              file=sys.stderr)
        return 1
    points = [{"id": h["id"], "started_at": h["started_at"],
               "safe_pct": round(100.0 * (h["total"] - h["vulnerable"])
                                 / h["total"], 1) if h["total"] else 0.0}
              for h in history]
    if args.json:
        print(json.dumps(points, indent=2))
        return 0
    width = 40
    for pt in points:
        bar = "#" * round(pt["safe_pct"] / 100 * width)
        print(f"run {pt['id']:<4} {pt['started_at']:<21} "
              f"{pt['safe_pct']:>5.1f}% |{bar:<{width}}|")
    return 0


def _cmd_prune(args: argparse.Namespace) -> int:
    if (args.keep is not None and args.keep < 0) or \
            (args.older_than is not None and args.older_than < 0):
        print("prune: value must be >= 0", file=sys.stderr)
        return 2
    store = Store(args.db)
    history = store.run_history()
    if args.keep is not None:
        doomed = history[:-args.keep] if args.keep else history
    else:
        from datetime import datetime, timedelta, timezone
        cutoff = datetime.now(timezone.utc) - timedelta(days=args.older_than)
        doomed = [h for h in history
                  if datetime.fromisoformat(h["started_at"]) < cutoff]
    if not doomed:
        print("nothing to prune")
        return 0
    ids = [h["id"] for h in doomed]
    listing = ", ".join(str(i) for i in ids)
    if args.dry_run:
        print(f"would delete {len(ids)} run(s): {listing}")
        return 0
    store.delete_runs(ids)
    print(f"deleted {len(ids)} run(s): {listing}")
    return 0


def _cmd_export(args: argparse.Namespace) -> int:
    store = Store(args.db)
    run_id = args.run or store.latest_run_id()
    if run_id is None:
        print("no scan runs recorded yet", file=sys.stderr)
        return 1
    if args.html:
        from .dashboard.html import render_dashboard
        out = render_dashboard(store, run_id)
        path = ("qday-report.html" if args.output == "cbom.json"
                else args.output)
        kind = "HTML report"
    else:
        from .cbom import export_cbom
        doc = export_cbom(store.assets_for_run(run_id),
                          store.run_info(run_id))
        out = json.dumps(doc, indent=2)
        path = args.output
        kind = "CycloneDX CBOM"
    if path == "-":
        print(out)
    else:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        print(f"wrote {kind} to {path}")
    return 0


def _cmd_import(args: argparse.Namespace) -> int:
    from .cbom import import_cbom
    try:
        with open(args.file, "rb") as fh:
            doc = json.load(fh)
        assets = import_cbom(doc)
    except (OSError, ValueError) as exc:
        print(f"import error: {exc}", file=sys.stderr)
        return 2
    from .risk import score_asset
    scores = {a.asset_id: score_asset(a) for a in assets}
    store = Store(args.db)
    run_id = store.save_run(assets, scores,
                            label=args.label or f"import {args.file}")
    vulnerable = sum(1 for a in assets if a.quantum_vulnerable)
    print(f"run {run_id}: imported {len(assets)} crypto assets, "
          f"{vulnerable} quantum-vulnerable  (db: {args.db})")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    from .dashboard.server import serve
    serve(args.db, args.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="qday", description=__doc__)
    p.add_argument("--db", default=DEFAULT_DB, help="sqlite database path")
    sub = p.add_subparsers(dest="command", required=True)

    ps = sub.add_parser("scan", help="run scanners and record a run")
    ps.add_argument("--tls", action="append", metavar="HOST[:PORT]",
                    help="scan a live TLS endpoint (repeatable)")
    ps.add_argument("--ssh", action="append", metavar="HOST[:PORT]",
                    help="scan a live SSH endpoint (repeatable)")
    ps.add_argument("--discover", action="append", metavar="HOST|CIDR[:PORTS]",
                    help="probe a host/CIDR + port list, scan what answers "
                         "(e.g. 10.0.0.0/28:443,8443)")
    ps.add_argument("--certs", action="append", metavar="DIR",
                    help="scan a directory for certificate/key files "
                         "(repeatable)")
    ps.add_argument("--code", action="append", metavar="DIR",
                    help="scan a source tree for crypto usage (repeatable)")
    ps.add_argument("--deps", action="append", metavar="DIR",
                    help="scan dependency manifests for crypto libraries "
                         "(repeatable)")
    ps.add_argument("--agility", action="append", metavar="TOML",
                    help="inventory a crypto-agility policy file (repeatable)")
    ps.add_argument("--label", help="label for this run")
    ps.add_argument("--config", metavar="TOML",
                    help="scan config (default: qday.toml if present)")
    ps.add_argument("--fail-on", choices=list(_LEVEL_RANK),
                    help="exit 3 if any asset reaches this risk level "
                         "(CI gate)")
    ps.set_defaults(fn=_cmd_scan)

    pd = sub.add_parser("diff", help="compare two runs (default: last two)")
    pd.add_argument("--from", dest="from_run", type=int, metavar="ID")
    pd.add_argument("--to", dest="to_run", type=int, metavar="ID")
    pd.add_argument("--json", action="store_true")
    pd.add_argument("--fail-on-new", choices=list(_LEVEL_RANK),
                    help="exit 3 if a NEW asset reaches this risk level "
                         "(CI gate that ignores known backlog)")
    pd.set_defaults(fn=_cmd_diff)

    pr = sub.add_parser("report", help="print inventory for a run")
    pr.add_argument("--run", type=int, help="run id (default: latest)")
    pr.add_argument("--json", action="store_true")
    pr.set_defaults(fn=_cmd_report)

    pl = sub.add_parser("runs", help="list recorded runs")
    pl.add_argument("--json", action="store_true")
    pl.set_defaults(fn=_cmd_runs)

    pt = sub.add_parser("trend", help="print PQC-safe percentage per run")
    pt.add_argument("--json", action="store_true")
    pt.set_defaults(fn=_cmd_trend)

    pp = sub.add_parser("prune", help="delete old runs from the database")
    sel = pp.add_mutually_exclusive_group(required=True)
    sel.add_argument("--keep", type=int, metavar="N",
                     help="keep only the last N runs")
    sel.add_argument("--older-than", type=int, metavar="DAYS",
                     help="delete runs older than DAYS days")
    pp.add_argument("--dry-run", action="store_true",
                    help="print what would be deleted without deleting")
    pp.set_defaults(fn=_cmd_prune)

    pe = sub.add_parser("export",
                        help="export CycloneDX CBOM or static HTML report")
    pe.add_argument("--run", type=int, help="run id (default: latest)")
    pe.add_argument("--html", action="store_true",
                    help="write a single-file HTML report instead of a CBOM "
                         "(default output: qday-report.html)")
    pe.add_argument("-o", "--output", default="cbom.json",
                    help="output file, or - for stdout")
    pe.set_defaults(fn=_cmd_export)

    pi = sub.add_parser("import",
                        help="import a CycloneDX CBOM as a new run")
    pi.add_argument("file", metavar="CBOM.json")
    pi.add_argument("--label", help="label for this run")
    pi.set_defaults(fn=_cmd_import)

    pv = sub.add_parser("serve", help="serve the migration dashboard")
    pv.add_argument("--port", type=int, default=8080)
    pv.set_defaults(fn=_cmd_serve)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
