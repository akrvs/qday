# CryptoMap

Continuous cryptographic inventory (CBOM) and post-quantum migration tracker.

Discovers quantum-vulnerable cryptography (RSA, ECC/ECDSA, DH, DSA, EdDSA)
across live TLS endpoints, certificate/key files, and source code; produces a
CycloneDX 1.6 Cryptographic Bill of Materials; risk-ranks every asset; and
tracks migration progress against the CNSA 2.0 / NIST post-quantum deadlines.

## Install

```sh
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
```

## Usage

```sh
# Scan any mix of targets; each scan is a timestamped run in sqlite
cryptomap scan --tls api.example.com:443 --certs /etc/ssl --code ~/repos/backend

# Inventory for the latest run, ranked by risk
cryptomap report            # add --json for machine output

# CycloneDX 1.6 CBOM (cryptographic-asset components)
cryptomap export -o cbom.json

# Migration dashboard: % PQC-safe, deadline countdowns, risk breakdown, trend
cryptomap serve --port 8080
```

"Continuous" in the MVP = re-run `cryptomap scan` on a schedule (cron/CI);
every run appends to the same database and the dashboard/trends update on
reload.

## How risk is scored

`base severity × data-lifespan multiplier × exposure multiplier`, 0–10.

- Base: classically weak (RSA < 2048, DES) = 10; quantum-vulnerable but sound
  today (RSA-2048+, all ECC, DH) = 8; AES-128 = 3; AES-256/ChaCha20/PQC = 0.
- Lifespan encodes harvest-now-decrypt-later: data that must stay secret for
  15+ years multiplies risk ×1.25. Lifespan is human-supplied metadata — no
  scanner can discover it — and defaults conservatively to 10 years.
- Exposure: public 1.25 / internal 1.0 / local 0.85.

## Scanners

| Scanner | Ground truth level | What it finds |
|---|---|---|
| `--tls`   | Negotiated reality | protocol version, cipher, key exchange, served cert chain leaf |
| `--certs` | Artifact on disk   | X.509 certs, private/public keys (PEM/DER/OpenSSH), expiry |
| `--code`  | Heuristic          | crypto API calls + key sizes (Python/Java/Kotlin/Go/JS/TS), embedded private keys, `openssl` invocations in scripts |

Code rules live in `cryptomap/scanners/rules/*.yaml` — add patterns without
touching Python.

## Roadmap

- Certificate chain (not just leaf) and full port-range endpoint discovery
- Data-lifespan/exposure annotations via config file instead of defaults
- Dependency-manifest scanning (lockfiles → known crypto libraries)
- Crypto-agility layer: algorithm choice behind config, so the eventual PQC
  swap is a config change, not a code rewrite
