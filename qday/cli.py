"""Command-line entry point.

    qday scan  [--tls HOST[:PORT] ...] [--discover HOST|CIDR[:PORTS] ...]
               [--certs DIR] [--code DIR] [--deps DIR]
               [--config qday.toml] [--fail-on LEVEL]
    qday report [--run ID] [--json]
    qday diff  [--from ID] [--to ID]
    qday export [--run ID] -o cbom.json
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


def _cmd_scan(args: argparse.Namespace) -> int:
    from .config import DEFAULT_CONFIG, ConfigError, load_config

    tls_targets = list(args.tls or [])
    cert_dirs = [args.certs] if args.certs else []
    code_dirs = [args.code] if args.code else []
    dep_dirs = [args.deps] if args.deps else []
    annotations: list[dict] = []

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
        cert_dirs += cfg["certs"]
        code_dirs += cfg["code"]
        dep_dirs += cfg["deps"]
        annotations = cfg["annotations"]

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

    if not (tls_targets or cert_dirs or code_dirs or dep_dirs):
        print("nothing to scan: pass --tls/--certs/--code/--deps or add a "
              "[scan] section to qday.toml", file=sys.stderr)
        return 2

    assets: list[CryptoAsset] = []
    if tls_targets:
        from .scanners.tls import TlsScanner

        def scan_one(target: str) -> list[CryptoAsset]:
            host, _, port = target.partition(":")
            return list(TlsScanner(host, int(port or 443)).scan())

        # Handshakes are network-bound; a pool turns N × timeout into ~timeout.
        with ThreadPoolExecutor(max_workers=min(16, len(tls_targets))) as pool:
            for result in pool.map(scan_one, tls_targets):
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

    annotated = 0
    if annotations:
        from .config import apply_annotations
        annotated = apply_annotations(assets, annotations)

    from .risk import score_asset
    scores = {a.asset_id: score_asset(a) for a in assets}

    store = Store(args.db)
    run_id = store.save_run(assets, scores, label=args.label)
    vulnerable = sum(1 for a in assets if a.quantum_vulnerable)
    note = f", {annotated} annotated via config" if annotated else ""
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

    print(f"run {from_id} -> run {to_id}: "
          f"+{len(delta['new'])} new, -{len(delta['resolved'])} resolved, "
          f"{len(delta['persisting'])} persisting")
    for tag, rows in (("+", delta["new"]), ("-", delta["resolved"])):
        for r in rows:
            print(f"  {tag} [{r['risk_level'] or '-'}] {r['algorithm']:<8} "
                  f"{r['asset_type']:<14} {r['location']}")
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    store = Store(args.db)
    run_id = args.run or store.latest_run_id()
    if run_id is None:
        print("no scan runs recorded yet — run `qday scan` first",
              file=sys.stderr)
        return 1
    rows = store.assets_for_run(run_id)
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
    fmt = "{:<9} {:<6} {:<8} {:<7} {:<14} {}"
    print(fmt.format("RISK", "SCORE", "ALGO", "BITS", "TYPE", "LOCATION"))
    for r in rows:
        print(fmt.format(
            r["risk_level"] or "-",
            f"{r['risk_score']:.1f}" if r["risk_score"] is not None else "-",
            r["algorithm"], r["key_size"] or "-", r["asset_type"],
            r["location"]))
    return 0


def _cmd_export(args: argparse.Namespace) -> int:
    from .cbom import export_cbom
    store = Store(args.db)
    run_id = args.run or store.latest_run_id()
    if run_id is None:
        print("no scan runs recorded yet", file=sys.stderr)
        return 1
    doc = export_cbom(store.assets_for_run(run_id), store.run_info(run_id))
    out = json.dumps(doc, indent=2)
    if args.output == "-":
        print(out)
    else:
        with open(args.output, "w") as fh:
            fh.write(out + "\n")
        print(f"wrote CycloneDX CBOM to {args.output}")
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
    ps.add_argument("--discover", action="append", metavar="HOST|CIDR[:PORTS]",
                    help="probe a host/CIDR + port list, scan what answers "
                         "(e.g. 10.0.0.0/28:443,8443)")
    ps.add_argument("--certs", metavar="DIR",
                    help="scan a directory for certificate/key files")
    ps.add_argument("--code", metavar="DIR",
                    help="scan a source tree for crypto usage")
    ps.add_argument("--deps", metavar="DIR",
                    help="scan dependency manifests for crypto libraries")
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
    pd.set_defaults(fn=_cmd_diff)

    pr = sub.add_parser("report", help="print inventory for a run")
    pr.add_argument("--run", type=int, help="run id (default: latest)")
    pr.add_argument("--json", action="store_true")
    pr.set_defaults(fn=_cmd_report)

    pe = sub.add_parser("export", help="export CycloneDX CBOM")
    pe.add_argument("--run", type=int, help="run id (default: latest)")
    pe.add_argument("-o", "--output", default="cbom.json",
                    help="output file, or - for stdout")
    pe.set_defaults(fn=_cmd_export)

    pv = sub.add_parser("serve", help="serve the migration dashboard")
    pv.add_argument("--port", type=int, default=8080)
    pv.set_defaults(fn=_cmd_serve)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
