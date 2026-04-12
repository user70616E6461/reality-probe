<h1 align="center">🐼 Reality Probe</h1>

<p align="center">
  <b>TLS Analyzer & VLESS Reality Configuration Tool</b><br/>
  <sub>Probe domains for TLS 1.3 · HTTP/2 ALPN · X25519 · CDN detection · Config generation</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0-00cfee?style=flat-square" />
  <img src="https://img.shields.io/badge/python-3.8+-00d47e?style=flat-square&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/license-MIT-e8a800?style=flat-square" />
</p>

---

## What is this?

**Reality Probe** is a TLS analysis tool that finds optimal SNI domains for [XTLS Reality](https://github.com/XTLS/Xray-core) protocol configuration. It probes domains for TLS 1.3 support, HTTP/2 ALPN negotiation, X25519 key exchange, and CDN characteristics — then generates ready-to-use configs for popular proxy platforms.

---

## Features

| Feature | Description |
|---------|-------------|
| **TLS 1.3 + H2 Detection** | Probes ALPN negotiation — the key parameter for Reality camouflage |
| **Multi-IP DNS Resolution** | Detects CDN-backed domains (multiple A records) |
| **Quality Scoring** | Rates domains: IDEAL → GOOD → FAIR → POOR based on TLS profile |
| **120+ Built-in Domains** | Works fully offline with a curated domain list |
| **Multi-Source Discovery** | Majestic Million, Cloudflare Radar, Certspotter, GitHub lists |
| **Smart Filtering** | Skips internal CDN infrastructure, staging domains, unsuitable targets |
| **Config Generation** | Ready configs for Xray, sing-box, Mihomo, NekoRay |
| **X25519 Key Generation** | Auto-generates private/public keys, UUID, short_ids |
| **TCP Pre-check** | Verifies port availability before TLS handshake |
| **Web Dashboard** | Clean web UI with real-time probing progress |
| **Quick Probe** | Check any domain instantly from the UI |
| **CSV/ZIP Export** | Export results for analysis |

---

## Quick Start

```bash
git clone https://github.com/user70616E6461/reality-probe.git
cd reality-probe
pip install -r requirements.txt
python reality_probe.py
```

Open **http://localhost:7890** in your browser.

---

## Scoring

The scoring system evaluates domains on multiple factors:

| Factor | Points | Why It Matters |
|--------|--------|----------------|
| TLS 1.3 | +30 | Required for Reality protocol |
| HTTP/2 (ALPN) | +25 | Legitimate H2 handshake profile |
| X25519 key exchange | +15 | Preferred key derivation for Reality |
| CDN-backed (multi-IP) | +10 | Higher reliability |
| Low RTT (<100ms) | +10 | Better performance |
| Valid certificate | +5 | Standard TLS behavior |
| Session tickets | +5 | Normal TLS extension |

**Status labels:**

- **IDEAL** (85+) — TLS 1.3 + H2 + X25519, perfect Reality target
- **Excellent** (70+) — Strong candidate
- **Good** (50+) — Usable
- **Poor** (<50) — Not recommended

---

## Config Generation

Select a domain → click **USE** → get ready configs:

- **Xray-core** — inbound + outbound JSON
- **sing-box** — inbound + outbound JSON
- **Mihomo** (Clash.Meta) — YAML proxy config
- **NekoRay** — JSON config
- **Share URI** — `vless://` link for mobile clients

All configs include auto-generated X25519 keys, UUID, short_ids, and recommended flow settings.

---

## Architecture

```
┌──────────────────┐
│  Domain Sources   │  Built-in list · Majestic · Radar · Certspotter · GitHub
└────────┬─────────┘
         │
┌────────▼─────────┐
│  Filter Engine    │  Infrastructure filter · CDN heuristics · Blocklist
└────────┬─────────┘
         │
┌────────▼─────────┐
│  TLS Prober       │  DNS → TCP check → TLS handshake → ALPN → KEX → Cert
└────────┬─────────┘
         │
┌────────▼─────────┐
│  Scoring Engine   │  TLS1.3 + H2 + X25519 + CDN + RTT → Score & Status
└────────┬─────────┘
         │
┌────────▼─────────┐
│  Config Builder   │  Xray · sing-box · Mihomo · NekoRay · Share URI
└──────────────────┘
```

---

## Docker

```bash
docker build -t reality-probe .
docker run -p 7890:7890 reality-probe
```

---

## System Requirements

- Python 3.8+
- `flask`, `cryptography`
- Works on Linux, macOS, Windows

If tkinter is missing (Ubuntu/Debian):
```bash
sudo apt install python3-tk
```

---

## Related Projects

- [XTLS/Xray-core](https://github.com/XTLS/Xray-core) — Reality protocol implementation
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box) — Universal proxy platform
- [XTLS/RealiTLScanner](https://github.com/XTLS/RealiTLScanner) — Official Reality TLS scanner

---

## License

MIT — see [LICENSE](LICENSE)
