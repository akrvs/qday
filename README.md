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
![tests](https://img.shields.io/badge/tests-15%20passing-brightgreen)
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
tls        live handshake: protocol version, cipher suite, key exchange,
           served certificate (algorithm, key size, curve, expiry)
certs      X.509 certs and key material on disk: PEM/DER/OpenSSH,
           public + private keys, encrypted-key detection
code       crypto API calls with key sizes across Python / Java / Kotlin /
           Go / JS / TS, embedded private keys, openssl calls in scripts
```

| Scanner | Ground truth level | Lie detector |
|---|---|---|
| `--tls`   | **Negotiated reality** | what the endpoint actually serves, verification off — expired and self-signed included |
| `--certs` | **Artifact on disk**   | what's deployed and what's leaked into repos |
| `--code`  | **Heuristic**          | breadth over depth — `file:line` evidence for humans to triage, not CodeQL |

Code rules are data, not code: `qday/scanners/rules/*.yaml` — add a pattern,
gain a language.

## [ Loadout ] — install

```sh
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
```

Two runtime dependencies (`cryptography`, `PyYAML`). Stdlib everything else —
the dashboard runs air-gapped.

## [ Engage ] — usage

```sh
# Scan any mix of targets; each scan appends a run
qday scan --tls api.example.com:443 --certs /etc/ssl --code ~/repos/backend

# Inventory for the latest run, ranked by risk (--json for machines)
qday report

# CycloneDX 1.6 CBOM — cryptographic-asset components, audit-ready
qday export -o cbom.json

# The scoreboard: % PQC-safe, deadline countdowns, risk breakdown, trend
qday serve --port 8080
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

## [ Intel ] — the clock

```
2027-01-01   CNSA 2.0 — new national-security systems PQC-only
2030-12-31   NIST IR 8547 — 112-bit-security algorithms deprecated
2035-12-31   NIST / CNSA 2.0 — quantum-vulnerable crypto disallowed
```

## [ Next Ops ]

- [ ] Full certificate chain + port-range endpoint discovery
- [ ] Lifespan/exposure annotations via config file instead of defaults
- [ ] Dependency-manifest scanning (lockfiles → known crypto libraries)
- [ ] Crypto-agility layer: algorithm choice behind config, so the eventual
      PQC swap is a config change, not a code rewrite
