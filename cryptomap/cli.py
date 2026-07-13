"""Command-line entry point.

    cryptomap scan  [--tls HOST[:PORT] ...] [--certs DIR] [--code DIR]
    cryptomap report [--run ID] [--json]
    cryptomap export [--run ID] -o cbom.json
    cryptomap serve  [--port 8080]
"""

from __future__ import annotations

import argparse
import json
import sys

from .model import CryptoAsset
from .store import Store

DEFAULT_DB = "data/cryptomap.db"


def _cmd_scan(args: argparse.Namespace) -> int:
    assets: list[CryptoAsset] = []

    if args.tls:
        from .scanners.tls import TlsScanner
        for target in args.tls:
            host, _, port = target.partition(":")
            assets.extend(TlsScanner(host, int(port or 443)).scan())
    if args.certs:
        from .scanners.certs import CertFileScanner
        assets.extend(CertFileScanner(args.certs).scan())
    if args.code:
        from .scanners.code import CodeScanner
        assets.extend(CodeScanner(args.code).scan())

    if not (args.tls or args.certs or args.code):
        print("nothing to scan: pass --tls, --certs and/or --code",
              file=sys.stderr)
        return 2

    from .risk import score_asset
    scores = {a.asset_id: score_asset(a) for a in assets}

    store = Store(args.db)
    run_id = store.save_run(assets, scores, label=args.label)
    vulnerable = sum(1 for a in assets if a.quantum_vulnerable)
    print(f"run {run_id}: {len(assets)} crypto assets found, "
          f"{vulnerable} quantum-vulnerable  (db: {args.db})")
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    store = Store(args.db)
    run_id = args.run or store.latest_run_id()
    if run_id is None:
        print("no scan runs recorded yet — run `cryptomap scan` first",
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
    p = argparse.ArgumentParser(prog="cryptomap", description=__doc__)
    p.add_argument("--db", default=DEFAULT_DB, help="sqlite database path")
    sub = p.add_subparsers(dest="command", required=True)

    ps = sub.add_parser("scan", help="run scanners and record a run")
    ps.add_argument("--tls", action="append", metavar="HOST[:PORT]",
                    help="scan a live TLS endpoint (repeatable)")
    ps.add_argument("--certs", metavar="DIR",
                    help="scan a directory for certificate/key files")
    ps.add_argument("--code", metavar="DIR",
                    help="scan a source tree for crypto usage")
    ps.add_argument("--label", help="label for this run")
    ps.set_defaults(fn=_cmd_scan)

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
