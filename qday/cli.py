"""Command-line entry point.

    qday scan  [--tls HOST[:PORT] ...] [--ssh HOST[:PORT] ...]
               [--starttls PROTO:HOST[:PORT] ...]
               [--discover HOST|CIDR[:PORTS] ...]
               [--certs DIR] [--code DIR] [--deps DIR] [--agility TOML]
               [--config qday.toml] [--fail-on LEVEL] [--fail-under PCT]
    qday report [--run ID] [--json]
    qday runs  [--json]
    qday trend [--json]
    qday prune (--keep N | --older-than DAYS) [--dry-run]
    qday waivers [--config qday.toml]
    qday diff  [--from ID] [--to ID] [--json] [--fail-on-new LEVEL]
    qday export [--run ID] [--html | --csv | --sarif] -o cbom.json
    qday import CBOM.json [--label TEXT]
    qday serve  [--port 8080]
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import sys
import tarfile
from concurrent.futures import ThreadPoolExecutor
from datetime import date

from .model import CryptoAsset, Exposure
from .store import Store

DEFAULT_DB = "data/qday.db"

_LEVEL_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_STARTTLS_PORTS = {"smtp": 587, "imap": 143, "pop3": 110}


def _resolve_exposures(
        endpoints: list[tuple[str, int]]) -> tuple[dict, list[tuple[str, int]]]:
    """Map endpoints whose host resolves only to private addresses to
    Exposure.INTERNAL; return (exposures, private_endpoints)."""
    exposures: dict = {}
    private: list[tuple[str, int]] = []
    for endpoint in endpoints:
        try:
            infos = socket.getaddrinfo(endpoint[0], None,
                                       type=socket.SOCK_STREAM)
            addrs = {ipaddress.ip_address(info[4][0]) for info in infos}
        except (OSError, ValueError):
            continue
        if addrs and all(addr.is_private for addr in addrs):
            exposures[endpoint] = Exposure.INTERNAL
            private.append(endpoint)
    return exposures, private


def _gate_private_targets(
        groups: list[list[tuple[str, int]]], authorized: bool) -> int | None:
    """Refuse network scans of private-range targets without authorization."""
    if authorized:
        return None
    flagged: list[str] = []
    seen: set = set()
    for endpoints in groups:
        _, private = _resolve_exposures(endpoints)
        for host, port in private:
            if (host, port) not in seen:
                seen.add((host, port))
                flagged.append(f"{host}:{port}")
    if not flagged:
        return None
    print("private-range target(s) found: " + ", ".join(flagged),
          file=sys.stderr)
    print("scanning internal networks needs authorization: pass "
          "--i-own-this-network or set authorized_private = true under "
          "[scan] in qday.toml", file=sys.stderr)
    return 2


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


def _parse_starttls(targets: list[str]) -> list[tuple[str, int, str]] | None:
    triples: list[tuple[str, int, str]] = []
    for target in targets:
        proto, _, rest = target.partition(":")
        proto = proto.lower()
        if proto not in _STARTTLS_PORTS or not rest:
            print(f"invalid starttls target {target!r}: expected "
                  "smtp|imap|pop3:HOST[:PORT]", file=sys.stderr)
            return None
        endpoints = _parse_endpoints([rest], _STARTTLS_PORTS[proto],
                                     "STARTTLS")
        if endpoints is None:
            return None
        triples.append((*endpoints[0], proto))
    return triples


def _cmd_scan(args: argparse.Namespace) -> int:
    from .config import DEFAULT_CONFIG, ConfigError, load_config

    tls_targets = list(args.tls or [])
    ssh_targets = list(args.ssh or [])
    starttls_targets = list(args.starttls or [])
    cert_dirs = list(args.certs or [])
    code_dirs = list(args.code or [])
    dep_dirs = list(args.deps or [])
    agility_files = list(args.agility or [])
    annotations: list[dict] = []
    waivers: list[dict] = []
    cfg: dict = {}

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
        starttls_targets += cfg["starttls"]
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

    if not (tls_targets or ssh_targets or starttls_targets or cert_dirs
            or code_dirs or dep_dirs or agility_files or args.image):
        print("nothing to scan: pass --tls/--ssh/--starttls/--certs/--image/"
              "--code/--deps/--agility or add a [scan] section to qday.toml",
              file=sys.stderr)
        return 2

    authorized = args.i_own_this_network or bool(cfg.get("authorized_private"))
    tls_endpoints = _parse_endpoints(tls_targets, 443, "TLS") \
        if tls_targets else []
    if tls_targets and tls_endpoints is None:
        return 2
    ssh_endpoints = _parse_endpoints(ssh_targets, 22, "SSH") \
        if ssh_targets else []
    if ssh_targets and ssh_endpoints is None:
        return 2
    starttls_triples = _parse_starttls(starttls_targets) \
        if starttls_targets else []
    if starttls_targets and starttls_triples is None:
        return 2

    exposure_maps: dict[str, dict] = {}
    private_seen: set = set()
    for name, pairs in (("tls", tls_endpoints),
                        ("ssh", ssh_endpoints),
                        ("starttls", [(h, p) for h, p, _ in starttls_triples])):
        exposures, private = _resolve_exposures(pairs)
        exposure_maps[name] = exposures
        private_seen.update(private)
    if private_seen and not authorized:
        flagged = ", ".join(f"{h}:{p}" for h, p in sorted(private_seen))
        print(f"private-range target(s) found: {flagged}", file=sys.stderr)
        print("scanning internal networks needs authorization: pass "
              "--i-own-this-network or set authorized_private = true under "
              "[scan] in qday.toml", file=sys.stderr)
        return 2
    if private_seen:
        print(f"internal scope authorized for {len(private_seen)} "
              "private-range endpoint(s)")

    assets: list[CryptoAsset] = []
    if tls_endpoints:
        from .scanners.tls import TlsScanner
        exps = exposure_maps["tls"]

        def scan_tls(endpoint):
            scanner = TlsScanner(endpoint[0], endpoint[1],
                                 exposure=exps.get(endpoint, Exposure.PUBLIC))
            return list(scanner.scan())

        with ThreadPoolExecutor(max_workers=min(16, len(tls_endpoints))) as pool:
            for result in pool.map(scan_tls, tls_endpoints):
                assets.extend(result)
    if starttls_triples:
        from .scanners.tls import TlsScanner
        exps = exposure_maps["starttls"]

        def scan_starttls(triple):
            scanner = TlsScanner(triple[0], triple[1], exposure=exps.get(
                (triple[0], triple[1]), Exposure.PUBLIC), starttls=triple[2])
            return list(scanner.scan())

        with ThreadPoolExecutor(max_workers=min(16, len(starttls_triples))) as pool:
            for result in pool.map(scan_starttls, starttls_triples):
                assets.extend(result)
    if ssh_endpoints:
        from .scanners.ssh import SshScanner
        exps = exposure_maps["ssh"]

        def scan_ssh(endpoint):
            scanner = SshScanner(endpoint[0], endpoint[1],
                                 exposure=exps.get(endpoint, Exposure.PUBLIC))
            return list(scanner.scan())

        with ThreadPoolExecutor(max_workers=min(16, len(ssh_endpoints))) as pool:
            for result in pool.map(scan_ssh, ssh_endpoints):
                assets.extend(result)
    if cert_dirs:
        from .scanners.certs import CertFileScanner
        for d in cert_dirs:
            assets.extend(CertFileScanner(d).scan())
    if args.image:
        from .scanners.image import ImageScanner
        for image_path in args.image:
            try:
                assets.extend(ImageScanner(image_path).scan())
            except (tarfile.TarError, OSError) as exc:
                print(f"image error: {image_path}: {exc}", file=sys.stderr)
                return 2
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
        from .config import apply_waivers, expired_waiver_hits
        waived = apply_waivers(assets, scores, waivers)
        expired = expired_waiver_hits(assets, waivers)
        if expired and not args.allow_expired_waivers:
            for w, n in expired:
                print(f"expired waiver {w['match']!r} (until {w['until']}) "
                      f"still covers {n} asset(s)", file=sys.stderr)
            print("renew or drop the waiver, or pass --allow-expired-waivers",
                  file=sys.stderr)
            return 3

    policy = cfg.get("policy")
    if policy:
        from .config import policy_violations
        violations = policy_violations(assets, scores, policy)
        if violations:
            detail = ", ".join(f"{family} x{n}"
                               for family, n in sorted(violations.items()))
            print(f"policy violation(s): {detail}", file=sys.stderr)
            print("these algorithm families are outside [policy] "
                  "allowed_algorithms", file=sys.stderr)
            return 3

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

    if args.fail_under is not None and assets:
        safe_pct = 100.0 * (len(assets) - vulnerable) / len(assets)
        if safe_pct < args.fail_under:
            print(f"fail-under={args.fail_under:g}: only {safe_pct:.1f}% "
                  "PQC-safe (exit 3)", file=sys.stderr)
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

    if args.fail_on_regression and delta.get("regressed"):
        names = ", ".join(r["location"] for r in delta["regressed"][:5])
        more = f" (+{len(delta['regressed']) - 5} more)" \
            if len(delta["regressed"]) > 5 else ""
        print(f"fail-on-regression: {len(delta['regressed'])} asset(s) went "
              f"PQC-safe -> quantum-vulnerable: {names}{more}", file=sys.stderr)
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


def _milestones_for(cfg: dict) -> list[dict]:
    return cfg.get("milestones") or []


def _run_milestone(run_date: date, milestones: list[dict]) -> str:
    """The label of the newest milestone on/before this run's date, if any."""
    hits = [m for m in milestones if m["date"] <= run_date]
    if not hits:
        return ""
    latest = max(hits, key=lambda m: m["date"])
    return f"  [{latest['label']} @ {latest['date'].isoformat()}]"


def _cmd_trend(args: argparse.Namespace) -> int:
    from .config import DEFAULT_CONFIG, ConfigError, load_config

    store = Store(args.db)
    history = store.run_history()
    if not history:
        print("no scan runs recorded yet - run `qday scan` first",
              file=sys.stderr)
        return 1
    milestones = []
    config_path = args.config
    if config_path is None and os.path.exists(DEFAULT_CONFIG):
        config_path = DEFAULT_CONFIG
    if config_path:
        try:
            cfg = load_config(config_path)
        except (OSError, ConfigError) as exc:
            print(f"config error: {exc}", file=sys.stderr)
            return 2
        milestones = _milestones_for(cfg)
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
        stamp = pt["started_at"][:10]
        note = ""
        if milestones:
            from datetime import date as _date

            try:
                note = _run_milestone(_date.fromisoformat(stamp), milestones)
            except ValueError:
                note = ""
        print(f"run {pt['id']:<4} {pt['started_at']:<21} "
              f"{pt['safe_pct']:>5.1f}% |{bar:<{width}}|{note}")
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


def _cmd_waivers(args: argparse.Namespace) -> int:
    from datetime import date
    from fnmatch import fnmatch

    from .config import DEFAULT_CONFIG, ConfigError, load_config

    config_path = args.config
    if config_path is None and os.path.exists(DEFAULT_CONFIG):
        config_path = DEFAULT_CONFIG
    if config_path is None:
        print("no config found: pass --config or add qday.toml",
              file=sys.stderr)
        return 2
    try:
        cfg = load_config(config_path)
    except (OSError, ConfigError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    waivers = cfg["waivers"]
    if not waivers:
        print("no waivers defined")
        return 0

    store = Store(args.db)
    latest = store.latest_run_id()
    locations = ([r["location"] for r in store.assets_for_run(latest)]
                 if latest else [])
    today = date.today()
    fmt = "{:<8} {:<11} {:>6} {:>7}  {:<28} {}"
    print(fmt.format("STATUS", "UNTIL", "DAYS", "ASSETS", "MATCH", "REASON"))
    for w in waivers:
        days = (w["until"] - today).days
        status = "ACTIVE" if days >= 0 else "EXPIRED"
        hits = sum(1 for loc in locations if fnmatch(loc, w["match"]))
        print(fmt.format(status, w["until"].isoformat(), days, hits,
                         w["match"], w["reason"]))
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
    elif args.md:
        from .dashboard.html import render_markdown
        out = render_markdown(store, run_id)
        path = ("qday-report.md" if args.output == "cbom.json"
                else args.output)
        kind = "Markdown report"
    elif args.csv:
        import csv
        import io

        from .risk import remediation
        columns = ["asset_id", "name", "asset_type", "algorithm", "key_size",
                   "curve", "location", "scanner", "exposure",
                   "data_lifespan_years", "quantum_vulnerable", "risk_score",
                   "risk_level", "remediation"]
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=columns,
                                extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        for r in store.assets_for_run(run_id):
            r["remediation"] = remediation(r["algorithm"], r["asset_type"],
                                           r["key_size"])
            writer.writerow(r)
        out = buf.getvalue().rstrip("\n")
        path = ("qday-report.csv" if args.output == "cbom.json"
                else args.output)
        kind = "CSV report"
    elif args.sarif:
        from .sarif import export_sarif
        doc = export_sarif(store.assets_for_run(run_id))
        out = json.dumps(doc, indent=2)
        path = "qday.sarif" if args.output == "cbom.json" else args.output
        kind = "SARIF report"
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


def _cmd_tickets(args: argparse.Namespace) -> int:
    from .risk import remediation

    store = Store(args.db)
    run_id = args.run or store.latest_run_id()
    if run_id is None:
        print("no scan runs recorded yet", file=sys.stderr)
        return 1
    rows = store.assets_for_run(run_id)
    if args.fail_on:
        threshold = _LEVEL_RANK[args.fail_on]
        rows = [r for r in rows
                if _LEVEL_RANK.get(r["risk_level"] or "none", 0) >= threshold]
    else:
        rows = [r for r in rows if r["risk_score"]]

    def title(r: dict) -> str:
        bits = f"-{r['key_size']}" if r["key_size"] else ""
        return (f"Migrate {r['algorithm']}{bits} {r['asset_type']} "
                f"at {r['location']}")

    out_parts = []
    for i, r in enumerate(rows):
        fix = remediation(r["algorithm"], r["asset_type"],
                          r.get("key_size")) or "assess manually"
        score = (f"{r['risk_score']:.1f}"
                 if r["risk_score"] is not None else "-")
        if args.format == "jira":
            body = (f"h3. {title(r)}\n\n"
                    f"||Field||Value||\n"
                    f"|Risk|{r['risk_level'] or 'none'} ({score})|\n"
                    f"|Algorithm|{r['algorithm']}|\n"
                    f"|Type|{r['asset_type']}|\n"
                    f"|Source|{r['scanner']}|\n"
                    f"|Migrate to|{fix}|\n"
                    f"|Run|{run_id}|")
        else:
            body = (f"### {title(r)}\n\n"
                    f"- **Risk:** {r['risk_level'] or 'none'} ({score})\n"
                    f"- **Algorithm:** {r['algorithm']}\n"
                    f"- **Type:** {r['asset_type']}\n"
                    f"- **Source:** {r['scanner']}\n"
                    f"- **Migrate to:** {fix}\n"
                    f"- **Run:** {run_id}")
        out_parts.append(body)
    out = ("\n\n---\n\n".join(out_parts) + "\n") if out_parts else ""
    if not rows:
        print("no findings at this threshold - nothing to file")
        return 0
    if args.output == "-":
        print(out, end="")
    else:
        path = args.output
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"wrote {len(rows)} ticket(s) to {path}")
    return 0


def _cmd_policy(args: argparse.Namespace) -> int:
    from .config import (
        DEFAULT_CONFIG,
        ConfigError,
        load_config,
        violations_from_rows,
    )
    from .model import canonical_family

    config_path = args.config
    if config_path is None and os.path.exists(DEFAULT_CONFIG):
        config_path = DEFAULT_CONFIG
    if config_path is None:
        print("no config found: pass --config or add qday.toml",
              file=sys.stderr)
        return 2
    try:
        cfg = load_config(config_path)
    except (OSError, ConfigError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    allowed = cfg.get("policy")
    if not allowed:
        print("no [policy] allowed_algorithms list in the config")
        return 0

    store = Store(args.db)
    run_id = args.run or store.latest_run_id()
    if run_id is None:
        print("no scan runs recorded yet", file=sys.stderr)
        return 1
    rows = store.assets_for_run(run_id)
    violations = violations_from_rows(rows, allowed)
    if not violations:
        print(f"run {run_id}: every family is inside the policy")
        return 0
    print(f"run {run_id}: policy violation(s):")
    for family, count in sorted(violations.items(), key=lambda kv: -kv[1]):
        print(f"  {canonical_family(family)}: {count} asset(s)")
    return 3


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
    ps.add_argument("--starttls", action="append",
                    metavar="PROTO:HOST[:PORT]",
                    help="scan a STARTTLS endpoint, PROTO one of smtp/imap/"
                         "pop3 (repeatable)")
    ps.add_argument("--discover", action="append", metavar="HOST|CIDR[:PORTS]",
                    help="probe a host/CIDR + port list, scan what answers "
                         "(e.g. 10.0.0.0/28:443,8443)")
    ps.add_argument("--certs", action="append", metavar="DIR",
                    help="scan a directory for certificate/key files "
                         "(repeatable)")
    ps.add_argument("--image", action="append", metavar="IMAGE.tar",
                    help="scan a docker-save/OCI image archive for "
                         "certificate/key material (repeatable)")
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
    ps.add_argument("--fail-under", type=float, metavar="PCT",
                    help="exit 3 if the PQC-safe percentage is below PCT "
                         "(CI gate)")
    ps.add_argument("--allow-expired-waivers", action="store_true",
                    help="do not fail when an expired waiver still covers "
                         "live assets")
    ps.add_argument("--i-own-this-network", action="store_true",
                    help="authorize scanning endpoints that resolve to "
                         "private-range addresses")
    ps.set_defaults(fn=_cmd_scan)

    pd = sub.add_parser("diff", help="compare two runs (default: last two)")
    pd.add_argument("--from", dest="from_run", type=int, metavar="ID")
    pd.add_argument("--to", dest="to_run", type=int, metavar="ID")
    pd.add_argument("--json", action="store_true")
    pd.add_argument("--fail-on-new", choices=list(_LEVEL_RANK),
                    help="exit 3 if a NEW asset reaches this risk level "
                         "(CI gate that ignores known backlog)")
    pd.add_argument("--fail-on-regression", action="store_true",
                    help="exit 3 if a persisted asset went PQC-safe -> "
                         "quantum-vulnerable")
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
    pt.add_argument("--config", metavar="TOML",
                    help="scan config (default: qday.toml if present) - "
                         "milestones annotate the trend")
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

    pw = sub.add_parser("waivers",
                        help="list configured waivers and their status")
    pw.add_argument("--config", metavar="TOML",
                    help="scan config (default: qday.toml if present)")
    pw.set_defaults(fn=_cmd_waivers)

    pe = sub.add_parser("export",
                        help="export CycloneDX CBOM or static HTML report")
    pe.add_argument("--run", type=int, help="run id (default: latest)")
    pfmt = pe.add_mutually_exclusive_group()
    pfmt.add_argument("--html", action="store_true",
                      help="write a single-file HTML report instead of a CBOM "
                           "(default output: qday-report.html)")
    pfmt.add_argument("--md", action="store_true",
                      help="write a GitHub-flavored Markdown summary, sized "
                           "for PR comments (default output: qday-report.md)")
    pfmt.add_argument("--csv", action="store_true",
                      help="write a CSV report instead of a CBOM "
                           "(default output: qday-report.csv)")
    pfmt.add_argument("--sarif", action="store_true",
                      help="write a SARIF 2.1.0 report instead of a CBOM "
                           "(default output: qday.sarif)")
    pe.add_argument("-o", "--output", default="cbom.json",
                    help="output file, or - for stdout")
    pe.set_defaults(fn=_cmd_export)

    pt = sub.add_parser("tickets",
                        help="emit one migration ticket per finding, ready "
                             "to paste into Jira or Linear")
    pt.add_argument("--run", type=int, help="run id (default: latest)")
    pt.add_argument("--format", choices=("jira", "linear"), default="jira",
                    help="ticket body dialect (default: jira wiki markup)")
    pt.add_argument("--fail-on", choices=list(_LEVEL_RANK),
                    help="only file findings at or above this risk level")
    pt.add_argument("-o", "--output", default="-",
                    help="output file, or - for stdout")
    pt.set_defaults(fn=_cmd_tickets)

    pp = sub.add_parser("policy",
                        help="check the latest run against [policy] "
                             "allowed_algorithms")
    pp.add_argument("--run", type=int, help="run id (default: latest)")
    pp.add_argument("--config", metavar="TOML",
                    help="scan config (default: qday.toml if present)")
    pp.set_defaults(fn=_cmd_policy)

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
