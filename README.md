```
 ██████╗ ██████╗  █████╗ ██╗   ██╗
██╔═══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝
██║   ██║██║  ██║███████║ ╚████╔╝
██║▄▄ ██║██║  ██║██╔══██║  ╚██╔╝
╚██████╔╝██████╔╝██║  ██║   ██║
 ╚══▀▀═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝
                        a k r v s
```

> Q-Day is the day a quantum computer breaks RSA. Everything encrypted with it
> becomes readable — including traffic harvested years earlier. QDAY hunts every
> quantum-vulnerable cipher in your estate, ranks what dies first, and counts
> down your migration against the CNSA 2.0 / NIST deadlines. Scan. Rank.
> Migrate. Before the clock hits zero.

![status](https://img.shields.io/badge/status-ACTIVE-brightgreen)
![category](https://img.shields.io/badge/category-Security%20%2F%20PQC-9cf)
![difficulty](https://img.shields.io/badge/difficulty-Hard-red)
![python](https://img.shields.io/badge/python-3.12%2B-blue)
![tests](https://img.shields.io/badge/tests-73%20passing-brightgreen)
![deps](https://img.shields.io/badge/runtime%20deps-2-brightgreen)

```
┌─[ TARGET ]──────────────────────────────────────────────────┐
│ codename   : qday                                           │
│ category   : Security / PQC Migration                       │
│ difficulty : Hard                                           │
│ stack      : Python · cryptography · SQLite · CycloneDX 1.6 │
│ interfaces : CLI + dashboard + CBOM export                  │
│ flags      : user [inventory]   root [zero vulnerable]      │
│ status     : ACTIVE - live-fired against real TLS endpoints │
└─────────────────────────────────────────────────────────────┘
```

## [ Briefing ]

RSA, ECC/ECDSA, DH, DSA, EdDSA — all of it falls to Shor's algorithm the day a
cryptographically relevant quantum computer exists. Adversaries are recording
ciphertext *today* to decrypt *then* ("harvest now, decrypt later"), and the
regulators have already set the clock: new national-security systems go
PQC-only in **2027**, 112-bit-security algorithms are deprecated by **2030**,
and quantum-vulnerable crypto is disallowed by **2035**. Discovery alone takes
large orgs 12–24 months. QDAY is the discovery layer: a continuous scanner that
turns your estate into a **Cryptographic Bill of Materials** and a migration
scoreboard.

Every scan is a timestamped run in SQLite — cron it and the dashboard becomes a
live feed of your climb from 0% to 100% PQC-safe.

## [ Recon ] — what it finds

```
tls        live handshake: protocol version, cipher suite, negotiated
           key-exchange group (PQC hybrids like X25519MLKEM768 count as
           safe), served certificate (algorithm, key size, curve, expiry)
ssh        live banner + KEXINIT read: key-exchange list (hybrid PQC kex
           like sntrup761x25519 counts as safe) and host key algorithms
certs      X.509 certs and key material on disk: PEM/DER/OpenSSH,
           public + private keys, encrypted-key detection
code       crypto API calls with key sizes across Python / Java / Kotlin /
           Go / JS / TS, embedded private keys, openssl calls in scripts
deps       crypto libraries in dependency manifests — the transitive crypto
           first-party source never imports directly
discover   probe a host/CIDR + port list, TLS-scan whatever answers
agility    your own crypto-agility policy bindings (purpose -> suite)
```

| Scanner | Ground truth level | Lie detector |
|---|---|---|
| `--tls` / `--discover` | **Negotiated reality** | what the endpoint actually serves (full chain: leaf/intermediate/root), verification off — expired and self-signed included |
| `--ssh` | **Negotiated reality** | banner and cleartext KEXINIT — no authentication, no key exchange performed |
| `--certs` | **Artifact on disk**   | what's deployed and what's leaked into repos |
| `--code`  | **Heuristic**          | breadth over depth — `file:line` evidence for humans to triage, not CodeQL |
| `--deps`  | **Manifest**           | requirements.txt · package-lock.json · go.mod · Cargo.lock · pom.xml → known crypto libraries |
| `--agility` | **Policy**           | your own crypto-agility bindings (see [ Agility ]) — dogfooding the migration layer |

Rules and the dependency catalog are data, not code:
`qday/scanners/rules/*.yaml` — add a pattern or a package, gain coverage.

## [ Loadout ] — install

```sh
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
```

Two runtime dependencies (`cryptography`, `PyYAML`). Stdlib everything else —
the dashboard runs air-gapped.

## [ Engage ] — usage

```sh
# Scan any mix of targets; each scan appends a run.
# TLS endpoints scan in parallel and inventory the full served chain.
qday scan --tls api.example.com:443 --ssh bastion.example.com \
          --certs /etc/ssl --code ~/repos/backend --deps ~/repos/backend

# Discover what's actually listening, then TLS-scan the live ones
qday scan --discover 10.0.0.0/28:443,8443

# CI gate: exit 3 the moment anything reaches the threshold
qday scan --code . --deps . --fail-on critical

# Inventory for the latest run, ranked by risk (--json for machines),
# each vulnerable finding paired with a MIGRATE-TO target (also exported
# as a qday:remediation property in the CBOM)
qday report

# What changed between runs: +new, -resolved, persisting (--json for machines)
# CI gate that ignores known backlog: exit 3 only when NEW crypto appears
qday diff --fail-on-new high

# CycloneDX 1.6 CBOM — cryptographic-asset components, audit-ready
qday export -o cbom.json

# Same data as a single-file HTML report - the dashboard, no server needed
qday export --html -o report.html

# Merge estates scanned by other tools: any CycloneDX CBOM becomes a run,
# re-scored by the same risk model, visible on the same dashboard
qday import other-tool-cbom.json

# The scoreboard: % PQC-safe, deadline countdowns, risk breakdown, trend,
# and a burndown projection - the date you hit 100% PQC-safe at the current
# pace, meets/misses per regulatory deadline
qday serve --port 8080
```

Repeatable scans live in `qday.toml` (picked up automatically), which is also
where the humans feed the risk model what no scanner can discover:

```toml
[scan]
tls   = ["api.example.com:443", "vpn.example.com:8443"]
ssh   = ["bastion.example.com:22"]
certs = ["/etc/ssl"]
code  = ["../backend"]
deps  = ["../backend"]

[[annotate]]
match          = "api.example.com*"   # fnmatch against asset location
lifespan_years = 25                   # harvest-now-decrypt-later horizon
exposure       = "public"

[[waive]]
match  = "legacy.example.com*"        # accepted risk: gates skip it,
reason = "decommission scheduled Q3"  # the score stays on the books
until  = 2026-10-01                   # mandatory expiry: the finding
                                      # reactivates after this date
```

## [ Scoring ] — the risk model

`base severity × data-lifespan × exposure`, 0–10.

- **Base**: classically weak (RSA < 2048, DES) → 10 · quantum-vulnerable but
  sound today (RSA-2048+, all ECC, DH) → 8 · AES-128 → 3 ·
  AES-256 / ChaCha20 / ML-KEM / ML-DSA → 0
- **Lifespan** is the harvest-now-decrypt-later multiplier: secrets that must
  hold 15+ years burn ×1.25. No scanner can discover lifespan — it's
  human-supplied metadata, defaulting conservatively to 10 years.
- **Exposure**: public ×1.25 · internal ×1.0 · local ×0.85. Expired certs get
  a bump — unmanaged crypto migrates last.

## [ Agility ] — migrate without a rewrite

Discovery is half the job; the other half is being able to *act* on it. The
`qday.agility` library binds algorithm choice to config, so the eventual PQC
swap is a one-line edit — not a code change threaded through every call site.

```python
from qday.agility import CryptoPolicy

policy = CryptoPolicy.from_file("agility.toml")
priv, pub = policy.generate("firmware-signing")   # uses the CURRENT binding
sig = policy.sign(priv, firmware_bytes)           # dispatches on the key
assert policy.verify(pub, firmware_bytes, sig)
```

Application code names a **purpose**; the policy binds it to a **suite**. The
algorithm identity rides *with the key* (like a JOSE `alg` header), so `verify`
auto-routes and RSA and ML-DSA keys coexist during the transition.

```toml
[agility.purposes]
document-signing = "rsa-3072"
firmware-signing = "hybrid:ecdsa-p384+ml-dsa-65"   # CNSA 2.0-style hybrid

[agility.policy]
deprecated = ["rsa-2048", "ecdsa-p256"]            # generate() refuses these
```

- **Providers** are pluggable: RSA, ECDSA (P-256/384/521), Ed25519/Ed448 ship
  real (via `cryptography`); ML-DSA (FIPS 204) signatures and ML-KEM (FIPS
  203) key encapsulation (`policy.encapsulate`/`decapsulate`) are wired
  through the optional `oqs` backend — `pip install oqs` activates them with
  zero code change.
- **Hybrids** sign with both arms and require both to verify, so the signature
  is no weaker than its stronger arm.
- **Dogfooded**: `qday scan --agility agility.toml` inventories the policy
  itself, so a purpose still bound to vulnerable crypto shows up on the same
  dashboard as everything else.

## [ Intel ] — the clock

```
2027-01-01   CNSA 2.0 — new national-security systems PQC-only
2030-12-31   NIST IR 8547 — 112-bit-security algorithms deprecated
2035-12-31   NIST / CNSA 2.0 — quantum-vulnerable crypto disallowed
```
