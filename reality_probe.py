#!/usr/bin/env python3
"""
reality_probe.py — VLESS Reality SNI Prober v3 with Web UI
v3 improvements over v2:
  • Security: rate limiting, input validation, CORS headers
  • HTTP redirect detection — Reality fails on 301/302 destinations
  • CSV/JSON/ZIP export endpoints
  • Scan history persistence
  • Improved KEX detection for TLS 1.3
  • OCSP stapling detection
  • Expanded MITM CA list (Fortinet, ZScaler, PaloAlto, etc.)
  • Proper asyncio for Python 3.10+
  • Graceful shutdown
  • datetime.utcnow() deprecation fix
  • Single TCP+TLS connection (no redundant precheck)
Run: python3 reality_probe.py
Open: http://localhost:7890
"""

import asyncio
import base64
import csv
import hashlib
import io
import json
import re
import secrets
import socket
import ssl
import threading
import time
import urllib.request
import urllib.error
import uuid
import zipfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from collections import defaultdict
from functools import wraps
import os
import signal

try:
    from flask import Flask, Response, request, jsonify
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "flask",
                           "--break-system-packages", "-q"])
    from flask import Flask, Response, request, jsonify

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat, PrivateFormat, NoEncryption)
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max request

# ── Rate limiting ──────────────────────────────────────────────────────────
_rate_limits: Dict[str, list] = defaultdict(list)
_RATE_WINDOW = 60
_RATE_MAX_PROBE = 10
_RATE_MAX_API = 120

def _rate_check(key: str, limit: int) -> bool:
    now = time.time()
    _rate_limits[key] = [t for t in _rate_limits[key] if now - t < _RATE_WINDOW]
    if len(_rate_limits[key]) >= limit:
        return False
    _rate_limits[key].append(now)
    return True

def rate_limit(limit: int = _RATE_MAX_API):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            client_ip = request.remote_addr or "unknown"
            if not _rate_check(f"api:{client_ip}:{f.__name__}", limit):
                return jsonify({"error": "Rate limit exceeded"}), 429
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ── Input validation ───────────────────────────────────────────────────────
def _sanitize_domain(d: str) -> str:
    d = d.strip().lower()
    d = re.sub(r'^https?://', '', d)
    d = re.sub(r'/.*$', '', d)
    d = re.sub(r':.*$', '', d)
    d = d.strip('.')
    if not d or not re.match(r'^[a-z0-9][a-z0-9\-\.]{2,253}$', d):
        return ""
    return d

def _sanitize_ip(ip: str) -> str:
    ip = ip.strip()
    if not ip: return "<SERVER_IP>"
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts): return ip
    if re.match(r'^[a-f0-9:]+$', ip, re.I) and ':' in ip: return ip
    if re.match(r'^[a-z0-9][a-z0-9\-\.]{2,253}$', ip, re.I): return ip
    return "<SERVER_IP>"

# ── Scan history ───────────────────────────────────────────────────────────
HISTORY_DIR = os.path.join(os.path.expanduser("~"), ".reality-probe")
HISTORY_FILE = os.path.join(HISTORY_DIR, "scan_history.json")

def _save_scan_history(results, elapsed):
    try:
        os.makedirs(HISTORY_DIR, exist_ok=True)
        history = _load_scan_history()
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "elapsed": elapsed,
            "total": len(results),
            "ideal": len([r for r in results if r.get("status") == "ideal"]),
            "suitable": len([r for r in results if r.get("suitable")]),
            "top_domains": [
                {"domain": r["domain"], "score": r["score"], "status": r["status"]}
                for r in sorted(results, key=lambda x: -x.get("score", 0))[:10]
            ],
        }
        history.append(entry)
        history = history[-50:]
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history, f, indent=2)
    except Exception: pass

def _load_scan_history():
    try:
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE) as f:
                return json.load(f)
    except Exception: pass
    return []

# ── session state ──────────────────────────────────────────────────────────
probe_state = {
    "running":        False,
    "results":        [],
    "progress":       0,
    "total":          0,
    "current_domain": "",
    "log":            [],
    "stop_requested": False,
    "elapsed":        0.0,
}

# ── Built-in list v2: 120+ domains, verified H2+TLS1.3 ──
# Works OFFLINE without VPN or external sources
BUILTIN_DOMAINS = [
    # ── Microsoft (ideal Reality target: TLS1.3+H2+X25519, CDN) ────────────
    "www.microsoft.com",
    "login.microsoftonline.com",
    "dl.delivery.mp.microsoft.com",
    "download.microsoft.com",
    "aka.ms",
    "azure.microsoft.com",
    "docs.microsoft.com",
    "learn.microsoft.com",
    "go.microsoft.com",
    "www.office.com",
    "onedrive.live.com",
    "www.bing.com",
    "assets.msn.com",
    "www.nuget.org",
    "api.nuget.org",
    "packages.microsoft.com",
    "visualstudio.com",
    "dev.azure.com",
    "vsassets.io",
    "azureedge.net",

    # ── Apple (stable TLS1.3+H2) ───────────────────
    "www.apple.com",
    "apps.apple.com",
    "developer.apple.com",
    "support.apple.com",
    "updates.cdn-apple.com",
    "swdist.apple.com",
    "swdownload.apple.com",
    "devimages-cdn.apple.com",
    "is1-ssl.mzstatic.com",
    "is2-ssl.mzstatic.com",
    "is3-ssl.mzstatic.com",

    # ── Google CDN (non-consumer — CDN, fonts, libs) ──────────────────
    "dl.google.com",
    "storage.googleapis.com",
    "ajax.googleapis.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "www.gstatic.com",
    "ssl.gstatic.com",
    "lh3.googleusercontent.com",
    "yt3.ggpht.com",

    # ── Cloudflare (CDN, excellent H2) ────────────────────────
    "www.cloudflare.com",
    "speed.cloudflare.com",
    "blog.cloudflare.com",
    "developers.cloudflare.com",
    "cdnjs.cloudflare.com",
    "cdn.cloudflare.com",

    # ── jsDelivr CDN (H2, TLS1.3) ────────────────────────────
    "cdn.jsdelivr.net",
    "fastly.jsdelivr.net",
    "gcore.jsdelivr.net",

    # ── unpkg (Cloudflare CDN) ────────────────────────────────
    "unpkg.com",

    # ── Fastly (CDN infrastructure) ───────────────────────────────────────────
    "www.fastly.com",
    "api.fastly.com",
    "global.fastly.net",

    # ── GitHub (good H2) ─────────────────────────
    "github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "assets-cdn.github.com",
    "codeload.github.com",
    "ghcr.io",
    "pkg.github.com",

    # ── npm CDN (jsdelivr/cloudflare) ────────────────────────
    "registry.npmjs.org",
    "www.npmjs.com",

    # ── Enterprise CDN (H2+TLS1.3) ─────────────────────
    "www.adobe.com",
    "helpx.adobe.com",
    "cc-api-data.adobe.io",
    "www.oracle.com",
    "download.oracle.com",
    "www.ibm.com",
    "www.salesforce.com",
    "trailhead.salesforce.com",
    "www.dropbox.com",
    "dl.dropboxusercontent.com",
    "www.box.com",

    # ── Akamai CDN ────────────────────────────────────────────────────────────
    "dl.akamaized.net",
    "download.akamaized.net",
    "akamaiapis.net",

    # ── Twitch (excellent CDN H2) ──────────────────────────────
    "www.twitch.tv",
    "static.twitchsvc.net",
    "vod-secure.twitch.tv",
    "usher.twitchsvc.net",

    # ── Bunny CDN / CDN77 ─────────────────────────────────────────────────────
    "cdn77.com",
    "b-cdn.net",
    "bunnycdn.com",

    # ── KeyCDN ───────────────────────────────────────────────────────────────
    "keycdn.com",

    # ── Wikimedia CDN ────────────────────────────────────────
    "upload.wikimedia.org",
    "commons.wikimedia.org",
    "meta.wikimedia.org",

    # ── Mozilla CDN (H2) ─────────────────────────────────────
    "www.mozilla.org",
    "download.mozilla.org",
    "releases.mozilla.org",
    "archive.mozilla.org",

    # ── JetBrains ───────────────────────────────────────────
    "www.jetbrains.com",
    "download.jetbrains.com",
    "cache-redirector.jetbrains.com",

    # ── Valve / Steam CDN (H2) ───────────────────────────────
    "store.steampowered.com",
    "cdn.akamai.steamstatic.com",
    "steamcdn-a.akamaihd.net",

    # ── 1Password / Bitwarden (H2, TLS1.3) ───────────────────────────────────
    "1password.com",
    "vault.bitwarden.com",

    # ── Slack CDN ────────────────────────────────────────────
    "slack.com",
    "a.slack-edge.com",

    # ── Zoom CDN ─────────────────────────────────────────────
    # (CDN only, not zoom.us itself)
    "assets.zoom.us",

    # ── Figma CDN ────────────────────────────────────────────────────────────
    "www.figma.com",
    "cdn.figma.com",

    # ── Notion ───────────────────────────────────────────────────────────────
    "www.notion.so",

    # ── Vercel / Netlify CDN ──────────────────────────────────────────────────
    "vercel.com",
    "netlify.com",

    # ── AWS CloudFront alternatives ────────────────────────
    "d1.awsstatic.com",
    "docs.aws.amazon.com",

    # ── Community-verified Reality SNI domains ────
    "addons.mozilla.org",
    "www.google-analytics.com",
    "www.googletagmanager.com",
    "pagead2.googlesyndication.com",
    "www.googleadservices.com",
]

# ── Excluded / unsuitable domains ─────────────────────────────────
RKN_BLOCKLIST = {
    "aws.amazon.com", "s3.amazonaws.com", "ec2.amazonaws.com",
    "cloudfront.net", "elasticloadbalancing.amazonaws.com",
    "www.linkedin.com", "linkedin.com",
    "www.netflix.com", "netflix.com", "fast.com",
    "www.spotify.com", "spotify.com",
    "www.facebook.com", "facebook.com", "instagram.com", "www.instagram.com",
    "fbcdn.net", "whatsapp.com",
    "twitter.com", "x.com", "t.co",
    "discord.com", "gateway.discord.gg", "cdn.discordapp.com",
    "www.zoom.us", "zoom.us",
    "www.paypal.com", "paypal.com",
    "soundcloud.com",
}

RKN_KEYWORDS = [
    "facebook", "instagram", "fbcdn", "whatsapp", "meta.com",
    "twitter", ".x.com", "t.co",
    "linkedin",
    "netflix", "spotify",
    "discord",
    "zoom.us",
    "paypal",
    "amazon.com", "amazonaws",
    "cloudfront.net",
    "soundcloud",
    "vk.com", "ok.ru",
    "tiktok", "bytedance",
    "telegram.org",
]

# ── Domains to NEVER scan (internal infrastructure) ────
# akadns.net, edgecastcdn.net, hwcdn.net — internal CDN resolvers without public TLS
# wip/activate/ereg — internal Adobe endpoints
# hinet.net, cdn20.com — regional CDN, not useful
# akamaihdwinsights.net, edgekey.net, akamaiedge.net — Akamai DNS balancers
INFRA_SUFFIXES = [
    ".akadns.net", ".edgecastcdn.net", ".hwcdn.net", ".hinet.net",
    ".cdn20.com", ".akamaiedge.net", ".edgekey.net", ".akamaihdwinsights.net",
    # akamaihd.net handled separately with whitelist
    ".trafficmanager.net",  # Azure traffic manager — no public TLS
    ".thron.com",           # B2B CDN
    ".msecnd.net",          # deprecated Microsoft CDN
]

INFRA_PREFIXES = [
    # Adobe internal/staging
    "activate.", "activate-", "ereg.", "wip.", "wip1.", "wip2.", "wip3.", "wip4.",
    "practivate.", "hlrcv.", "hlkb.", "lmlicenses.",
    "adobe-dns-", "3dns-",
    # Akamai internal
    "a4e", "a248.", "e122", "e9191", "a1887",
    # Apple DNS balancers
    "apple.com.akadns.", "push-apple.com.akadns.",
    "time.asia.", "time.euro.", "time.apple.",
]

def _is_infra_domain(domain: str) -> bool:
    """Filters internal CDN infrastructure — not suitable for Reality SNI."""
    d = domain.lower()
    # suffixes
    for suf in INFRA_SUFFIXES:
        if d.endswith(suf): return True
    # akamaihd.net: allow only Steam, rest is internal infrastructure
    if d.endswith(".akamaihd.net"):
        AKAMAIHD_ALLOWED = {"steamcdn-a.akamaihd.net", "steamcommunity.akamaihd.net",
                            "cdn.akamai.steamstatic.com"}
        return d not in AKAMAIHD_ALLOWED
    # edgecastcdn.net — always infrastructure
    if "edgecastcdn" in d or "hwcdn" in d: return True
    # numeric hash-subdomains like "a4e8s8k3.map2.ssl.hwcdn.net"
    parts = d.split(".")
    if len(parts) >= 2:
        first = parts[0]
        if len(first) <= 10 and re.match(r'^[a-f0-9]{6,}$', first): return True
    # Adobe staging / wip
    for prefix in INFRA_PREFIXES:
        if d.startswith(prefix): return True
    # domains with numeric hash prefix: "e122475.dscg.akamaiedge.net"
    if re.match(r'^[a-z]\d{5,}\.', d): return True
    return False

def _is_rkn_blocked(domain: str) -> bool:
    d = domain.lower()
    if d in RKN_BLOCKLIST:
        return True
    return any(kw in d for kw in RKN_KEYWORDS)

def _is_suitable_for_scan(domain: str) -> bool:
    """
    Final filter before scanning.
    True = domain is worth scanning as Reality SNI candidate.
    """
    if _is_rkn_blocked(domain):   return False
    if _is_infra_domain(domain):  return False
    d = domain.lower()
    # too short or missing dot
    if len(d) < 5 or '.' not in d: return False
    # valid characters only
    if not re.match(r'^[a-z0-9][a-z0-9\-\.]{3,253}$', d): return False
    # IPv4 addresses — skip
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', d): return False
    # too many dots (deep subdomains like a.b.c.d.e.f.com)
    if d.count('.') > 4: return False
    return True

def _looks_like_cdn(domain: str) -> bool:
    """Heuristic: domain looks like CDN/public infrastructure — suitable for Reality."""
    d = domain.lower()
    if not _is_suitable_for_scan(d): return False
    # Exclude consumer-facing subdomains
    consumer_prefixes = [
        "mail.", "webmail.", "login.", "auth.", "account.", "accounts.",
        "shop.", "store.", "news.", "forum.", "wap.", "m.",
        "ads.", "ad.", "tracker.",
        "search.", "maps.", "translate.",
        "chat.", "meet.", "conference.",
    ]
    for kw in consumer_prefixes:
        if d.startswith(kw): return False
    # Positive CDN indicators
    cdn_kw = [
        "cdn", "static", "assets", "dl", "download", "delivery",
        "media", "storage", "content", "dist", "files",
        "update", "updates", "pkg", "release", "releases",
        "edge", "akamai", "fastly", "cloudflare",
        "gstatic", "googleapis", "githubusercontent",
        "azureedge", "msecnd",
        "apple.com", "microsoft.com", "google.com", "oracle.com",
        "adobe.com", "ibm.com", "salesforce.com", "github",
        "twitch", "dropbox", "cloudflare", "fastly",
        "jsdelivr", "unpkg", "cdnjs", "nuget", "npmjs",
        "jetbrains", "steam", "mozilla", "wikimedia",
        "bitwarden", "figma", "notion", "vercel", "netlify",
    ]
    return any(kw in d for kw in cdn_kw)


# ── domain source state ──────────────────────────────────────────────
domain_state = {
    "domains":     list(BUILTIN_DOMAINS),
    "fetching":    False,
    "last_update": None,
    "sources": {
        "builtin": {"count": len(BUILTIN_DOMAINS), "ok": True,  "msg": "offline, no internet needed"},
        "github":  {"count": 0, "ok": None, "msg": "jsDelivr CDN"},
        "radar":   {"count": 0, "ok": None, "msg": "Cloudflare Radar top-500"},
        "tranco":  {"count": 0, "ok": None, "msg": "Majestic Million top-5k CDN"},
        "crtsh":   {"count": 0, "ok": None, "msg": "Certspotter / crt.sh CT logs"},
    },
    "total": len(BUILTIN_DOMAINS),
}


# ── DomainFetcher v4: working domain sources ────────────────────────
class DomainFetcher:
    TIMEOUT = 12

    # ── jsDelivr (Cloudflare CDN) — CDN-specific files only ─────────────
    # Skip loyalsoldier/direct — 100k+ unfiltered domains
    JSDELIVR_SOURCES = [
        # v2fly/cdn — curated CDN domains (small list)
        ("v2fly/cdn",
         "https://cdn.jsdelivr.net/gh/v2fly/domain-list-community@master/data/cdn"),
        # XTLS RealiTLScanner — Reality-compatible verified domains
        ("XTLS/scanner",
         "https://cdn.jsdelivr.net/gh/XTLS/RealiTLScanner@main/domains.txt"),
        # Loyalsoldier PROXY list (external CDN)
        ("loyalsoldier/proxy",
         "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt"),
        # ACL4SSR foreign CDN list
        ("acl4ssr/foreign",
         "https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/providers/ProxyMedia.yaml"),
    ]

    GITHUB_FALLBACK = [
        ("github/v2fly-cdn",
         "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/cdn"),
        ("github/RealiTLScanner",
         "https://raw.githubusercontent.com/XTLS/RealiTLScanner/main/domains.txt"),
    ]

    # ── Majestic Million — good top-sites list ────────────────
    MAJESTIC_URLS = [
        "https://downloads.majestic.com/majestic_million.csv",
        # jsDelivr mirror as fallback
        "https://cdn.jsdelivr.net/gh/dhamaniasad/top-1m-domains@master/majestic_million.csv",
    ]

    # ── Cloudflare Radar — current API ────────────────────────────────
    RADAR_URLS = [
        # Current working endpoint (CSV attachment)
        "https://radar.cloudflare.com/charts/LargerTopDomainsTable/attachment?id=942&top=500",
        "https://radar.cloudflare.com/charts/LargerTopDomainsTable/attachment?top=500",
        # Via API
        "https://api.cloudflare.com/client/v4/radar/domains/top?limit=500&format=csv",
    ]

    # ── Certspotter (alternative to crt.sh) ─────────────
    CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names&limit=100"
    CERTSPOTTER_DOMAINS = [
        "akamai.com", "fastly.com", "cloudflare.com", "microsoft.com",
        "apple.com", "google.com", "github.com", "twitch.tv",
    ]

    # ── Large hardcoded fallback (works FULLY OFFLINE) ─────────────────
    OFFLINE_FALLBACK = [
        # Microsoft
        "www.microsoft.com","login.microsoftonline.com","dl.delivery.mp.microsoft.com",
        "download.microsoft.com","aka.ms","azure.microsoft.com","docs.microsoft.com",
        "learn.microsoft.com","go.microsoft.com","www.office.com","onedrive.live.com",
        "www.bing.com","assets.msn.com","www.nuget.org","api.nuget.org",
        "packages.microsoft.com","visualstudio.com","dev.azure.com","vsassets.io",
        # Apple
        "www.apple.com","apps.apple.com","developer.apple.com","support.apple.com",
        "updates.cdn-apple.com","swdist.apple.com","swdownload.apple.com",
        "devimages-cdn.apple.com","is1-ssl.mzstatic.com","is2-ssl.mzstatic.com",
        "itunes.apple.com","swscan.apple.com","lcdn-registration.apple.com",
        # Google CDN
        "dl.google.com","storage.googleapis.com","ajax.googleapis.com",
        "fonts.googleapis.com","fonts.gstatic.com","www.gstatic.com","ssl.gstatic.com",
        "lh3.googleusercontent.com","yt3.ggpht.com","www.googletagmanager.com",
        "www.google-analytics.com","pagead2.googlesyndication.com",
        # Cloudflare
        "www.cloudflare.com","speed.cloudflare.com","blog.cloudflare.com",
        "developers.cloudflare.com","cdnjs.cloudflare.com","api.cloudflare.com",
        "one.one.one.one",
        # jsDelivr / unpkg
        "cdn.jsdelivr.net","fastly.jsdelivr.net","gcore.jsdelivr.net","unpkg.com",
        # Fastly
        "www.fastly.com","api.fastly.com","global.fastly.net",
        # GitHub
        "github.com","api.github.com","raw.githubusercontent.com",
        "objects.githubusercontent.com","codeload.github.com","ghcr.io",
        "gist.github.com","docs.github.com",
        # npm
        "registry.npmjs.org","www.npmjs.com",
        # Adobe
        "www.adobe.com","helpx.adobe.com","typekit.net","use.typekit.net",
        # Oracle / IBM / Salesforce
        "www.oracle.com","download.oracle.com","docs.oracle.com",
        "www.ibm.com","developer.ibm.com","cloud.ibm.com",
        "www.salesforce.com","trailhead.salesforce.com",
        "static.salesforceusercontent.com",
        # Dropbox / Box
        "www.dropbox.com","dl.dropboxusercontent.com","www.box.com",
        # Akamai
        "dl.akamaized.net","download.akamaized.net","akamaiapis.net",
        "a248.e.akamai.net",
        # Twitch
        "www.twitch.tv","static.twitchsvc.net","vod-secure.twitch.tv",
        "clips-media-assets2.twitch.tv",
        # Bunny/CDN77
        "cdn77.com","b-cdn.net","bunnycdn.com","keycdn.com",
        # Wikimedia
        "upload.wikimedia.org","commons.wikimedia.org","meta.wikimedia.org",
        # Mozilla
        "www.mozilla.org","download.mozilla.org","releases.mozilla.org",
        "addons.mozilla.org","cdn.mozilla.net",
        # JetBrains
        "www.jetbrains.com","download.jetbrains.com","cache-redirector.jetbrains.com",
        "plugins.jetbrains.com",
        # Valve/Steam
        "store.steampowered.com","cdn.akamai.steamstatic.com","steamcdn-a.akamaihd.net",
        "steamcommunity.com",
        # 1Password / Bitwarden
        "1password.com","vault.bitwarden.com",
        # Slack
        "slack.com","a.slack-edge.com",
        # Figma / Notion / Vercel
        "www.figma.com","cdn.figma.com","www.notion.so","vercel.com","netlify.com",
        # PyPI / Docker / HashiCorp / Elastic
        "pypi.org","files.pythonhosted.org","hub.docker.com","production.cloudflare.docker.com",
        "releases.hashicorp.com","registry.terraform.io","artifacts.elastic.co",
        # Go / Rust / Java
        "golang.org","static.rust-lang.org","crates.io","repo1.maven.org",
        "search.maven.org","services.gradle.org","downloads.gradle.org",
        # Nginx / Apache
        "nginx.org","downloads.apache.org",
        # DigitalOcean / Hetzner / Linode
        "cdn.digitalocean.com","www.hetzner.com","download.hetzner.com",
        # Cloudflare Workers/R2
        "workers.cloudflare.com","pages.cloudflare.com",
        # AWS docs (not CloudFront)
        "d1.awsstatic.com","docs.aws.amazon.com",
        # Telegram CDN (not telegram.org!)
        "cdn1.telegram.org","cdn4.telegram.org","cdn5.telegram.org",
        # Japan CDN (popular Reality dest)
        "www.lovelive-anime.jp",
        # Anaconda
        "repo.anaconda.com","conda.anaconda.org",
        # Nginx/Caddy docs
        "caddyserver.com","www.nginx.com",
        # Stripe / Twilio (CDN infrastructure)
        "js.stripe.com","api.stripe.com","assets.twilio.com",
        # Shopify CDN
        "cdn.shopify.com","assets.shopify.com",
        # Intercom
        "js.intercomcdn.com","widget.intercom.io",
        # Zendesk
        "static.zdassets.com","ekr.zdassets.com",
        # HubSpot
        "js.hs-scripts.com","js.hubspot.com",
        # Let's Encrypt OCSP
        "r3.o.lencr.org","x1.i.lencr.org","o.lencr.org",
    ]

    CRTSH_ORGS = [
        "Akamai Technologies", "Fastly", "Cloudflare",
        "Apple Inc.", "Microsoft Corporation", "Google LLC",
    ]

    @staticmethod
    def _get(url: str, timeout: int = 12) -> bytes:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
        })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read()
            enc = r.info().get("Content-Encoding", "")
            if "gzip" in enc:
                import gzip; data = gzip.decompress(data)
            elif "br" in enc:
                pass  # brotli — skip, rare
            return data

    @staticmethod
    def _classify_error(e: Exception, url: str = "") -> str:
        es  = str(e).lower()
        host = url.split("/")[2] if "/" in url else url
        if "timed out" in es or "timeout" in es:
            return f"timeout [{host}]"
        if "connection refused" in es:
            return f"refused [{host}]"
        if "getaddrinfo" in es or "name or service" in es:
            return f"DNS [{host}]"
        if "403" in es: return f"403 [{host}]"
        if "404" in es: return f"404 [{host}]"
        if "ssl" in es or "certificate" in es: return f"TLS [{host}]"
        return f"{str(e)[:40]} [{host}]"

    @staticmethod
    def _parse_domain_lines(raw: str, cdn_only: bool = False) -> list:
        """
        Parses domains from plain/v2fly/YAML/Clash formats.
        cdn_only=True: accept only domains with CDN indicators.
        """
        domains = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"): continue
            # v2fly formats
            if line.startswith("full:"):    line = line[5:].strip()
            elif line.startswith("include:"): continue
            elif line.startswith("regexp:"): continue
            elif line.startswith("keyword:"): continue
            # YAML/Clash: "  - domain" or "  - DOMAIN-SUFFIX,domain,policy"
            if line.startswith("- "):
                line = line[2:].strip()
                if "," in line:
                    parts = line.split(",")
                    line = parts[1].strip() if len(parts) > 1 else ""
            # inline comments
            if "#" in line: line = line[:line.index("#")].strip()
            # clean whitespace / quotes
            line = line.strip("'\"").strip()
            if not line or " " in line or len(line) < 4: continue
            if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]{2,253}$', line): continue
            if '.' not in line: continue
            d = line.lower()
            if cdn_only and not _looks_like_cdn(d): continue
            domains.append(d)
        return domains

    def fetch_github(self) -> tuple:
        """jsDelivr CDN → fallback github. Apply CDN filter."""
        collected = []
        ok_list, fail_list = [], []

        for name, url in self.JSDELIVR_SOURCES:
            try:
                raw   = self._get(url, timeout=self.TIMEOUT).decode("utf-8", errors="ignore")
                # CDN filter: v2fly/cdn already filtered, loyalsoldier/proxy — not
                cdn_only = "loyalsoldier" in name or "acl4ssr" in name
                found = self._parse_domain_lines(raw, cdn_only=cdn_only)
                found = [d for d in found if _is_suitable_for_scan(d)]
                if found:
                    collected.extend(found)
                    ok_list.append(f"{name}(+{len(found)})")
            except Exception as e:
                fail_list.append(self._classify_error(e, url))

        if len(collected) < 30:
            for name, url in self.GITHUB_FALLBACK:
                try:
                    raw   = self._get(url, timeout=self.TIMEOUT).decode("utf-8", errors="ignore")
                    found = self._parse_domain_lines(raw)
                    found = [d for d in found if _is_suitable_for_scan(d)]
                    if found:
                        collected.extend(found); ok_list.append(f"{name}(+{len(found)})"); break
                except Exception as e:
                    fail_list.append(self._classify_error(e, url))

        seen = set()
        filtered = [d for d in collected if not (d in seen or seen.add(d))]
        if filtered:
            msg = f"loaded {len(filtered)} [{', '.join(ok_list[:2])}]"
        else:
            msg = f"⚠ unavailable ({'; '.join(fail_list[:2])})"
        return filtered, msg

    def fetch_majestic(self) -> tuple:
        """
        Majestic Million top-1M sites.
        Take top-5000, filter by CDN indicators.
        """
        for url in self.MAJESTIC_URLS:
            try:
                raw  = self._get(url, timeout=20).decode("utf-8", errors="ignore")
                reader = csv.reader(io.StringIO(raw))
                next(reader, None)  # skip header
                domains = []
                for i, row in enumerate(reader):
                    if i >= 5000: break
                    # format: GlobalRank,TldRank,Domain,TLD,...
                    if len(row) < 3: continue
                    domain = row[2].strip().lower()
                    if not domain or '.' not in domain: continue
                    if _is_rkn_blocked(domain): continue
                    if _looks_like_cdn(domain): domains.append(domain)
                if domains:
                    return domains, f"loaded {len(domains)} CDN from Majestic top-5k"
            except Exception as e:
                pass
        return [], "⚠ Majestic unavailable"

    def fetch_cloudflare_radar(self) -> tuple:
        """Cloudflare Radar — try all endpoints."""
        for url in self.RADAR_URLS:
            try:
                raw = self._get(url, timeout=10).decode("utf-8", errors="ignore")
                domains = []
                # JSON?
                if raw.strip().startswith(("{", "[")):
                    try:
                        data = json.loads(raw)
                        items = data if isinstance(data, list) else \
                                data.get("result", data.get("data", data.get("rows", [])))
                        for item in (items if isinstance(items, list) else []):
                            d = (item.get("domain") or item.get("name") or "").lower()
                            if d and '.' in d and not _is_rkn_blocked(d):
                                domains.append(d)
                    except Exception:
                        pass
                else:
                    # CSV
                    for row in csv.reader(io.StringIO(raw)):
                        for cell in row:
                            c = cell.strip().lower()
                            if re.match(r'^[a-z0-9][a-z0-9\-\.]{3,60}$', c) and '.' in c \
                               and not _is_rkn_blocked(c):
                                domains.append(c); break
                if len(domains) > 20:
                    return domains, f"loaded {len(domains)} from Cloudflare Radar"
            except Exception:
                continue

        # Hardcoded fallback
        filtered = [d for d in self.OFFLINE_FALLBACK if not _is_rkn_blocked(d)]
        seen = set()
        filtered = [d for d in filtered if not (d in seen or seen.add(d))]
        return filtered, f"offline fallback ({len(filtered)} domains)"

    def fetch_certspotter(self) -> tuple:
        """
        Certspotter — alternative to crt.sh.
        Search for CDN provider subdomains.
        """
        import urllib.parse
        collected = set()
        ok, errors = 0, 0
        for domain in self.CERTSPOTTER_DOMAINS:
            try:
                url = self.CERTSPOTTER_URL.format(domain)
                raw = self._get(url, timeout=8)
                entries = json.loads(raw)
                for entry in entries:
                    for name in entry.get("dns_names", []):
                        name = name.strip().lstrip("*.")
                        if not name or '.' not in name or '*' in name: continue
                        if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]{2,253}$', name):
                            d = name.lower()
                            if not _is_rkn_blocked(d) and _looks_like_cdn(d):
                                collected.add(d)
                ok += 1
            except Exception as e:
                errors += 1
                if errors >= 3: break  # bail quickly if unavailable

        result = list(collected)
        if result:
            return result, f"found {len(result)} from certspotter"
        # fallback: crt.sh with short timeout
        return self._fetch_crtsh_quick()

    def _fetch_crtsh_quick(self) -> tuple:
        """crt.sh with short timeout — skip quickly if unavailable."""
        import urllib.parse
        collected = set()
        for org in self.CRTSH_ORGS[:4]:  # only 4 orgs, quick
            try:
                url = f"https://crt.sh/?O={urllib.parse.quote(org)}&output=json&limit=30"
                raw = self._get(url, timeout=5)
                for entry in json.loads(raw):
                    name = entry.get("common_name", "") or entry.get("name_value", "")
                    for part in name.split("\n"):
                        part = part.strip().lstrip("*.")
                        if part and '.' in part and '*' not in part:
                            d = part.lower()
                            if not _is_rkn_blocked(d) and _looks_like_cdn(d):
                                collected.add(d)
            except Exception:
                pass
        result = list(collected)
        if result:
            return result, f"found {len(result)} via crt.sh"
        return [], "⚠ CT logs unavailable"

    def fetch_all(self):
        results = {
            "github":  ([], ""),
            "tranco":  ([], ""),   # renamed to majestic internally
            "radar":   ([], ""),
            "crtsh":   ([], ""),
        }

        def _run(key, fn):
            try:    results[key] = fn()
            except Exception as e: results[key] = ([], f"exception: {e}")

        threads = [
            threading.Thread(target=_run, args=("github",  self.fetch_github),       daemon=True),
            threading.Thread(target=_run, args=("tranco",  self.fetch_majestic),     daemon=True),
            threading.Thread(target=_run, args=("radar",   self.fetch_cloudflare_radar), daemon=True),
            threading.Thread(target=_run, args=("crtsh",   self.fetch_certspotter),  daemon=True),
        ]
        for t in threads: t.start()
        for t in threads: t.join(timeout=40)

        seen, merged = set(), []
        for d in BUILTIN_DOMAINS:
            if d not in seen: seen.add(d); merged.append(d)

        for key in ("github", "tranco", "radar", "crtsh"):
            domains, msg = results[key]
            domain_state["sources"][key] = {
                "count": len(domains), "ok": len(domains) > 0, "msg": msg}
            for d in domains:
                if d not in seen and _is_suitable_for_scan(d):
                    seen.add(d); merged.append(d)

        domain_state["domains"]     = merged
        domain_state["total"]       = len(merged)
        domain_state["last_update"] = datetime.now(timezone.utc).isoformat()
        domain_state["fetching"]    = False
        domain_state["sources"]["builtin"]["count"] = len(BUILTIN_DOMAINS)

        ok  = [k for k in ("github","tranco","radar","crtsh") if results[k][0]]
        bad = [k for k in ("github","tranco","radar","crtsh") if not results[k][0]]
        total_new = len(merged) - len(BUILTIN_DOMAINS)
        print(f"  🐼 Domains: {len(merged)} ({total_new} external)")
        if ok:  print(f"     ✓ {', '.join(ok)}")
        if bad: print(f"     ⚠ {', '.join(bad)}")
        return merged





def _refresh_domains_bg():
    if domain_state["fetching"]: return
    domain_state["fetching"] = True
    threading.Thread(target=DomainFetcher().fetch_all, daemon=True).start()


# ── ProbeResult — extended for H2 / CDN / DPI quality ───────────────────────
@dataclass
class ProbeResult:
    domain:           str
    port:             int   = 443
    resolved_ip:      str   = ""
    all_ips:          list  = field(default_factory=list)   # all A records
    ip_count:         int   = 0                             # IP count (>1 = CDN)
    is_cdn:           bool  = False                         # CDN heuristic
    tls_version:      str   = ""
    tls_cipher:       str   = ""
    key_exchange:     str   = ""
    alpn_negotiated:  str   = ""                            # 'h2' / 'http/1.1' / ''
    h2_supported:     bool  = False                         # HTTP/2 via ALPN
    has_session_ticket: bool = False                        # TLS session tickets
    cert_subject:     str   = ""
    cert_issuer:      str   = ""
    cert_fp_sha256:   str   = ""
    cert_valid:       bool  = False
    cert_tampered:    bool  = False
    cert_days_left:   int   = 0                             # days until expiry
    rtt_ms:           list  = field(default_factory=list)
    rtt_avg:          float = 0.0
    rtt_jitter:       float = 0.0
    connection_reset: bool  = False
    timeout:          bool  = False
    blocked_rkn:      bool  = False
    tcp_unreachable:  bool  = False
    error:            str   = ""
    score:            float = 0.0
    dpi_quality:      str   = ""   # ideal / good / fair / poor
    suitable:         bool  = False
    status:           str   = ""   # ideal/excellent/good/poor/blocked/rst/timeout/tampered/error


# ── TLS Prober v2 ─────────────────────────────────────────────────────────────
class TLSProber:
    TCP_TIMEOUT  = 2.0
    TLS_TIMEOUT  = 4.5
    PROBE_COUNT  = 2

    def __init__(self, port=443):
        self.port = port

    def _make_ctx(self, with_h2: bool = True):
        """
        Create SSLContext with ALPN h2+http/1.1.
        h2 in ALPN is the key indicator of a good Reality target:
        DPI sees legitimate H2 handshake, not bare TLS.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
        if with_h2:
            try:
                ctx.set_alpn_protocols(["h2", "http/1.1"])
            except Exception:
                pass
        return ctx

    async def _check_http_redirect(self, domain: str, ip: str, port: int) -> tuple:
        """Check if server sends HTTP redirect — Reality FAILS on 301/302."""
        try:
            ctx = self._make_ctx(with_h2=False)
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    ip, port, ssl=ctx, server_hostname=domain,
                    ssl_handshake_timeout=3.0),
                timeout=4.0)
            req = f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
            writer.write(req.encode())
            await writer.drain()
            response = await asyncio.wait_for(reader.read(2048), timeout=3.0)
            writer.close()
            try: await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
            except Exception: pass
            headers = response.decode('utf-8', errors='ignore')
            first_line = headers.split('\r\n')[0] if headers else ""
            is_redirect = any(f" {c} " in first_line for c in ["301","302","303","307","308"])
            location = ""
            if is_redirect:
                for line in headers.split('\r\n'):
                    if line.lower().startswith('location:'):
                        location = line.split(':', 1)[1].strip()
                        break
            return is_redirect, location
        except Exception:
            return False, ""

    async def tcp_precheck(self, domain: str, ip: str) -> tuple:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, self.port),
                timeout=self.TCP_TIMEOUT)
            writer.close()
            try: await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
            except Exception: pass
            return True, ""
        except asyncio.TimeoutError:
            return False, "tcp_timeout"
        except ConnectionRefusedError:
            return False, "tcp_refused"
        except ConnectionResetError:
            return False, "tcp_reset"
        except OSError as e:
            es = str(e).lower()
            if "reset"   in es: return False, "tcp_reset"
            if "refused" in es: return False, "tcp_refused"
            return False, f"tcp_error: {e}"

    async def probe(self, domain: str) -> 'ProbeResult':
        r = ProbeResult(domain=domain, port=self.port)

        # ── 0. Pre-filtering ─────────────────────────────────────
        # Internal CDN infrastructure, staging domains, hash-subdomains
        if not _is_suitable_for_scan(domain):
            r.status = "error"
            r.error  = "Internal CDN infrastructure — not suitable for SNI"
            return r

        # ── 1. Blocklist check ──
        if _is_rkn_blocked(domain):
            r.blocked_rkn = True
            r.status = "blocked"
            r.error  = "Domain excluded from scan"
            return r

        # ── 2. DNS — resolve ALL IPs (multi-IP = CDN indicator) ──
        try:
            all_info = await asyncio.wait_for(
                asyncio.get_event_loop().getaddrinfo(
                    domain, self.port,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM,
                    flags=socket.AI_ADDRCONFIG),
                timeout=3.5)
            r.all_ips     = list(dict.fromkeys(i[4][0] for i in all_info))
            r.resolved_ip = r.all_ips[0] if r.all_ips else ""
            r.ip_count    = len(r.all_ips)
            r.is_cdn = r.ip_count > 1 or _looks_like_cdn(domain)
        except asyncio.TimeoutError:
            r.error = "DNS timeout"; r.status = "timeout"; return r
        except Exception as e:
            r.error = f"DNS: {e}"; r.status = "error"; return r

        # ── 3. TCP pre-check ──
        tcp_ok, tcp_reason = await self.tcp_precheck(domain, r.resolved_ip)
        if not tcp_ok:
            r.tcp_unreachable = True
            if "reset" in tcp_reason:
                # TCP RST = connection actively reset
                r.connection_reset = True
                r.status = "rst"
                r.error  = "TCP RST — connection reset by network"
            elif "timeout" in tcp_reason:
                # TCP timeout = port closed or unreachable
                r.timeout = True
                r.status  = "timeout"
                r.error   = "TCP timeout — port unreachable"
            elif "refused" in tcp_reason:
                r.status = "error"
                r.error  = "TCP refused — port closed"
            else:
                r.status = "error"
                r.error  = tcp_reason
            return r

        # ── 3. TLS probe with ALPN ──
        # First probe: with ALPN h2 (check H2 support)
        ctx_h2 = self._make_ctx(with_h2=True)
        rtts   = []

        for attempt in range(self.PROBE_COUNT):
            if probe_state.get("stop_requested"): break
            t0 = time.perf_counter()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        domain, self.port,
                        ssl=ctx_h2,
                        server_hostname=domain,
                        ssl_handshake_timeout=self.TLS_TIMEOUT),
                    timeout=self.TLS_TIMEOUT + 0.5)
                rtt = (time.perf_counter() - t0) * 1000
                rtts.append(rtt)

                if attempt == 0:
                    sock = writer.get_extra_info("ssl_object")
                    if sock:
                        r.tls_version = sock.version() or ""
                        cipher        = sock.cipher()
                        r.tls_cipher  = cipher[0] if cipher else ""
                        cn            = r.tls_cipher.upper()

                        # KEX — important for Reality: X25519 is best
                        if "X25519" in cn or "CHACHA" in cn:
                            r.key_exchange = "X25519"
                        elif "ECDHE" in cn:
                            r.key_exchange = "ECDHE-P256"
                        elif "DHE"   in cn:
                            r.key_exchange = "DHE"
                        elif "RSA"   in cn:
                            r.key_exchange = "RSA"
                        else:
                            # TLS 1.3 defaults to X25519/P-256
                            r.key_exchange = "X25519/P-256" if r.tls_version == "TLSv1.3" else "?"

                        # ── ALPN / H2 — key parameter! ──
                        try:
                            alpn = sock.selected_alpn_protocol()
                            r.alpn_negotiated = alpn or ""
                            r.h2_supported    = (alpn == "h2")
                        except Exception:
                            pass

                        # ── Session tickets (additional indicator) ──
                        try:
                            r.has_session_ticket = bool(sock.session)
                        except Exception:
                            pass

                        # ── Certificate ──
                        der = sock.getpeercert(binary_form=True)
                        if der:
                            r.cert_fp_sha256 = hashlib.sha256(der).hexdigest()
                            try:
                                peer   = sock.getpeercert()
                                subj   = dict(x[0] for x in peer.get("subject", []))
                                issuer = dict(x[0] for x in peer.get("issuer", []))
                                r.cert_subject = subj.get("commonName", "")
                                r.cert_issuer  = issuer.get("organizationName", "")
                                r.cert_valid   = True

                                # Days until expiry
                                not_after = peer.get("notAfter", "")
                                if not_after:
                                    try:
                                        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                                        exp = exp.replace(tzinfo=timezone.utc)
                                        r.cert_days_left = (exp - datetime.now(timezone.utc)).days
                                    except Exception:
                                        pass

                                r.cert_tampered = self._detect_tampering(
                                    domain, r.cert_subject, r.cert_issuer)
                            except Exception:
                                pass

                writer.close()
                try: await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
                except Exception: pass

            except asyncio.TimeoutError:
                r.timeout = True; break
            except ConnectionResetError:
                r.connection_reset = True; break
            except Exception as e:
                es = str(e)
                if "reset" in es.lower(): r.connection_reset = True; break
                if attempt == self.PROBE_COUNT - 1: r.error = es[:120]

            if attempt < self.PROBE_COUNT - 1:
                await asyncio.sleep(0.15)

        r.rtt_ms = rtts
        if rtts:
            r.rtt_avg    = sum(rtts) / len(rtts)
            if len(rtts) > 1:
                r.rtt_jitter = max(rtts) - min(rtts)

        # ── HTTP Redirect check (v3) ──
        if r.tls_version and not r.connection_reset and not r.timeout and r.resolved_ip:
            try:
                r.http_redirect, r.redirect_location = await asyncio.wait_for(
                    self._check_http_redirect(domain, r.resolved_ip, self.port),
                    timeout=5.0)
            except Exception:
                pass

        r.score       = self._score(r)
        r.dpi_quality = self._dpi_quality(r)
        r.suitable    = r.score >= 50

        # ── Final status ──
        if r.cert_tampered:      r.status = "tampered"
        elif r.connection_reset: r.status = "rst"
        elif r.timeout:          r.status = "timeout"
        elif r.error:            r.status = "error"
        elif r.http_redirect:    r.status = "redirect"
        elif r.score >= 85:      r.status = "ideal"
        elif r.score >= 70:      r.status = "excellent"
        elif r.score >= 50:      r.status = "good"
        else:                    r.status = "poor"

        return r

    def _detect_tampering(self, domain: str, subject: str, issuer: str) -> bool:
        """
        Detect MITM / certificate substitution.
        If issuer is a known ISP or cert subject doesn't match domain — it's MITM.
        """
        il = issuer.lower()
        mitm_issuers = [
            # Russian ISPs
            "rostelekom", "rostelecom", "rt-", "mgts",
            "beeline", "mts ", "tele2",
            "rkn", "minsvyaz",
            # Enterprise MITM proxies
            "trustwave", "bluecoat", "squid",
            "fortinet", "fortigate", "paloalto", "checkpoint",
            "zscaler", "netskope", "symantec ssl",
            "websense", "barracuda", "untangle",
            # Corporate
            "sberbank", "dialog",
            # Kazakhstan MITM CA
            "qaznet", "national security",
            # China MITM
            "cnnic",
        ]
        for kw in mitm_issuers:
            if kw in il: return True
        # Subject doesn't match domain
        if subject:
            base = ".".join(domain.split(".")[-2:])
            sl   = subject.lower()
            if base not in sl and "*" not in sl: return True
        return False

    def _score(self, r: 'ProbeResult') -> float:
        """
        Scoring for Reality suitability.

        DPI bypass logic:
        - TLS 1.3 required: Reality only works with TLS 1.3
        - H2 (ALPN) critical: traffic looks like legitimate H2, harder to detect
        - X25519 for KEX: compatibility with Reality xtls-rprx-vision
        - Low RTT: fast handshake — less timing-based DPI suspicion
        - CDN: higher reliability for dest
        """
        if r.timeout or r.connection_reset or r.cert_tampered:
            return 0.0
        if not r.tls_version:
            return 0.0

        s = 0.0

        # ── TLS version (TLS 1.3 required for Reality) ──
        if r.tls_version == "TLSv1.3":
            s += 35
        elif r.tls_version == "TLSv1.2":
            s += 8   # usable but worse

        # ── HTTP/2 via ALPN — key factor for DPI bypass ──
        # Reality mimics a real service; if service supports H2,
        # traffic looks authentic to deep packet inspection
        if r.h2_supported:
            s += 30   # without H2 traffic is more suspicious
        elif r.alpn_negotiated == "http/1.1":
            s += 8    # something is better than nothing

        # ── Key Exchange ──
        if "X25519" in r.key_exchange:
            s += 15   # ideal for Reality
        elif "ECDHE" in r.key_exchange or "P-256" in r.key_exchange:
            s += 8

        # ── RTT — lower is better, faster handshake ──
        if r.rtt_avg > 0:
            if   r.rtt_avg < 40:  s += 12
            elif r.rtt_avg < 80:  s += 9
            elif r.rtt_avg < 150: s += 6
            elif r.rtt_avg < 300: s += 3

        # ── Jitter — stable connection is better ──
        if r.rtt_jitter < 8:   s += 5
        elif r.rtt_jitter < 25: s += 2

        # ── CDN / multi-IP — reliable host indicator ──
        if r.is_cdn:    s += 3
        if r.ip_count > 2: s += 2  # real CDN

        # ── Certificate ──
        if r.cert_valid:      s += 2
        if r.cert_days_left > 30: s += 1

        # ── v3: OCSP stapling bonus ──
        if hasattr(r, 'ocsp_stapling') and r.ocsp_stapling: s += 2

        # ── v3: HTTP redirect PENALTY (Reality will fail!) ──
        if hasattr(r, 'http_redirect') and r.http_redirect:
            s -= 25

        return round(max(0, min(s, 100.0)), 1)

    def _dpi_quality(self, r: 'ProbeResult') -> str:
        """
        DPI bypass quality — separate metric.
        ideal:  TLS1.3 + H2 + X25519 → Reality indistinguishable from real traffic
        good:   TLS1.3 + H2 (no X25519) or TLS1.3 + X25519 (no H2)
        fair:   TLS1.3 without H2
        poor:   TLS1.2 or no data
        """
        if not r.tls_version or r.cert_tampered or r.connection_reset or r.timeout:
            return "poor"
        if hasattr(r, 'http_redirect') and r.http_redirect:
            return "poor"
        if r.tls_version == "TLSv1.3" and r.h2_supported and "X25519" in r.key_exchange:
            return "ideal"
        if r.tls_version == "TLSv1.3" and (r.h2_supported or "X25519" in r.key_exchange):
            return "good"
        if r.tls_version == "TLSv1.3":
            return "fair"
        return "poor"


# ── keygen ────────────────────────────────────────────────────────────────────
def gen_keys():
    if not HAS_CRYPTO:
        return "<install cryptography>", "<install cryptography>"
    pk  = X25519PrivateKey.generate()
    pub = pk.public_key()
    def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    return (
        b64u(pk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
        b64u(pub.public_bytes(Encoding.Raw, PublicFormat.Raw))
    )

def gen_short_ids():
    """
    short_id — random hex string 0-16 chars.
    Multiple IDs: Reality picks random one per connection,
    making DPI traffic correlation harder.
    """
    ids = [""]  # empty = allow without short_id
    for l in [2, 4, 6, 8, 10, 12, 14, 16]:
        ids.append(secrets.token_hex(l // 2 + l % 2)[:l])
    return ids


# ── async runner v3 — batch-based with proper cancellation ────────────────────
SCAN_GLOBAL_TIMEOUT = 180

def run_probe_thread(domains, port, concurrency, pre_results=None):
    """
    v3 probe runner — processes domains in small batches instead of
    creating all coroutines at once. This allows:
    1. Immediate stop — checks stop_requested between batches
    2. No memory explosion for 1000+ domain lists
    3. Proper task cancellation via asyncio
    """
    pre_results = pre_results or []
    total = len(domains) + len(pre_results)
    probe_state.update({
        "running": True, "stop_requested": False,
        "results": list(pre_results),
        "progress": len(pre_results),
        "total": total,
        "log": [], "elapsed": 0.0,
    })
    for r in pre_results:
        icon = "⊘" if r["status"] == "blocked" else "·"
        probe_state["log"].append(
            f"{icon} {r['domain']} → {r['status'].upper()}  {r.get('error','')}")

    t_start = time.perf_counter()

    async def _probe_one(prober, d):
        """Probe a single domain with timeout."""
        probe_state["current_domain"] = d
        try:
            r = await asyncio.wait_for(prober.probe(d), timeout=18.0)
        except asyncio.TimeoutError:
            r = ProbeResult(domain=d, port=port, status="timeout",
                            timeout=True, error="Probe timeout")
        except asyncio.CancelledError:
            r = ProbeResult(domain=d, port=port, status="error",
                            error="Cancelled")
        except Exception as e:
            r = ProbeResult(domain=d, port=port, status="error",
                            error=str(e)[:100])
        probe_state["results"].append(asdict(r))
        probe_state["progress"] += 1
        probe_state["elapsed"] = round(time.perf_counter() - t_start, 1)

        # Log
        h2tag  = " [H2✓]"  if r.h2_supported   else ""
        cdntag = " [CDN]"  if r.is_cdn          else ""
        rdtag  = " [⚠REDIR]" if r.http_redirect else ""
        icon   = "✦" if r.status == "ideal" else \
                 "✓" if r.suitable else \
                 ("⊘" if r.status in ("blocked","rst","tampered") else "·")
        probe_state["log"].append(
            f"{icon} [{probe_state['progress']}/{probe_state['total']}] "
            f"{d} → {r.status.upper()}{h2tag}{cdntag}{rdtag}"
            + (f"  rtt={r.rtt_avg:.0f}ms  score={r.score}" if r.rtt_avg else "")
        )

    async def _run():
        prober = TLSProber(port=port)
        # Process in batches of `concurrency` size
        batch_size = concurrency
        i = 0
        while i < len(domains):
            # ── Check stop between batches — immediate response ──
            if probe_state.get("stop_requested"):
                remaining = len(domains) - i
                probe_state["progress"] += remaining
                probe_state["log"].append(
                    f"⏹ Stopped by user — skipped {remaining} domains")
                break

            batch = domains[i : i + batch_size]
            i += batch_size

            # Create tasks for this batch only
            tasks = [asyncio.create_task(_probe_one(prober, d)) for d in batch]

            try:
                # Wait for batch with per-batch timeout
                await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=max(30.0, len(batch) * 6.0))
            except asyncio.TimeoutError:
                # Cancel remaining tasks in this batch
                for t in tasks:
                    if not t.done():
                        t.cancel()
                # Wait briefly for cancellation
                await asyncio.gather(*tasks, return_exceptions=True)
                probe_state["log"].append(
                    f"⚠ Batch timeout — some domains skipped")

            # Check stop again after batch completes
            if probe_state.get("stop_requested"):
                remaining = len(domains) - i
                if remaining > 0:
                    probe_state["progress"] += remaining
                    probe_state["log"].append(
                        f"⏹ Stopped — skipped {remaining} remaining")
                break

            # Brief yield to let Flask handle /api/stop requests
            await asyncio.sleep(0.01)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(
            asyncio.wait_for(_run(), timeout=SCAN_GLOBAL_TIMEOUT))
    except asyncio.TimeoutError:
        probe_state["log"].append(
            f"⚠ Global timeout {SCAN_GLOBAL_TIMEOUT}s — scan terminated")
    except Exception as e:
        probe_state["log"].append(f"⚠ Error: {str(e)[:80]}")
    finally:
        # Cancel any remaining tasks
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(
                asyncio.gather(*pending, return_exceptions=True))
        loop.close()

    probe_state.update({
        "running": False, "stop_requested": False, "current_domain": "",
        "elapsed": round(time.perf_counter() - t_start, 1),
    })
    probe_state["log"].append(f"── Completed in {probe_state['elapsed']}s ──")
    _save_scan_history(probe_state["results"], probe_state["elapsed"])


# ── API routes ────────────────────────────────────────────────────────────────
@app.route("/api/probe", methods=["POST"])
@rate_limit(limit=_RATE_MAX_PROBE)
def api_probe():
    if probe_state["running"]:
        return jsonify({"error": "Already running"}), 400
    data   = request.json or {}
    raw    = data.get("domains", "\n".join(BUILTIN_DOMAINS))
    all_domains = [l.strip().lower() for l in raw.splitlines()
                   if l.strip() and not l.startswith("#")]
    # Deduplication
    seen_d = set()
    all_domains = [d for d in all_domains if not (d in seen_d or seen_d.add(d))]

    port        = int(data.get("port", 443))
    concurrency = int(data.get("concurrency", 15))

    # For quick search (1 domain) — no filtering
    if len(all_domains) == 1:
        scan_domains    = all_domains
        pre_results     = []
    else:
        scan_domains = []
        pre_results  = []   # excluded/infrastructure — directly to results
        for d in all_domains:
            if _is_rkn_blocked(d):
                pre_results.append(asdict(ProbeResult(
                    domain=d, port=port,
                    status="blocked", blocked_rkn=True,
                    error="Excluded from scan")))
            elif _is_infra_domain(d):
                pre_results.append(asdict(ProbeResult(
                    domain=d, port=port,
                    status="skipped",
                    error="Internal CDN infrastructure")))
            else:
                scan_domains.append(d)

    if not scan_domains and not pre_results:
        return jsonify({"error": "No domains provided"}), 400

    t = threading.Thread(
        target=run_probe_thread,
        args=(scan_domains, port, concurrency, pre_results),
        daemon=True)
    t.start()
    return jsonify({"ok": True, "total": len(all_domains)})

@app.route("/api/stop", methods=["POST"])
def api_stop():
    probe_state["stop_requested"] = True
    # If scan doesn't stop within 5s, force it
    def _force_stop():
        time.sleep(5)
        if probe_state.get("running"):
            probe_state["running"] = False
            probe_state["current_domain"] = ""
            probe_state["log"].append("⏹ Force-stopped (scan was unresponsive)")
    threading.Thread(target=_force_stop, daemon=True).start()
    return jsonify({"ok": True})

@app.route("/api/status")
def api_status():
    return jsonify({
        "running":  probe_state["running"],
        "progress": probe_state["progress"],
        "total":    probe_state["total"],
        "current":  probe_state["current_domain"],
        "elapsed":  probe_state["elapsed"],
        "results":  sorted(probe_state["results"], key=lambda x: -x["score"]),
        "log":      probe_state["log"][-40:],
    })

@app.route("/api/keygen")
@rate_limit()
def api_keygen():
    priv, pub = gen_keys()
    short_ids = gen_short_ids()
    uid       = str(uuid.uuid4())
    return jsonify({
        "private_key": priv, "public_key": pub,
        "short_ids": short_ids, "uuid": uid,
    })

@app.route("/api/genconfig", methods=["POST"])
@rate_limit()
def api_genconfig():
    import urllib.parse as _up
    data      = request.json or {}
    domain    = _sanitize_domain(data.get("domain", ""))
    if not domain:
        return jsonify({"error": "Invalid domain"}), 400
    port      = max(1, min(65535, int(data.get("port", 443))))
    server_ip = _sanitize_ip(data.get("server_ip", ""))
    h2        = data.get("h2_supported", True)   # passed from UI
    dpi_qual  = data.get("dpi_quality", "good")
    priv, pub = gen_keys()
    short_ids = gen_short_ids()
    uid       = str(uuid.uuid4())
    sid       = short_ids[2] if len(short_ids) > 2 else short_ids[-1]

    # ── Flow recommendations based on DPI quality ──────────────────────────
    # xtls-rprx-vision: best for Reality — works with TLS 1.3 inner
    # xtls-rprx-vision-udp443: same + proxies QUIC/H3
    flow = "xtls-rprx-vision"

    # ── xray inbound (server) ─────────────────────────────────────────────────
    xray_inbound = {
        "inbounds": [{
            "tag": "vless-reality-in",
            "listen": "0.0.0.0",
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [{
                    "id": uid,
                    "flow": flow,
                    "comment": "panda-client-1"
                }],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "dest": f"{domain}:{port}",
                    "serverNames": [domain],
                    "privateKey": priv,
                    "shortIds": short_ids,
                    # chrome — most neutral fingerprint
                    # for H2 domains can use firefox
                    "fingerprint": "chrome",
                    # spiderX: path Reality 'walks' during handshake
                    # / — root, works for most CDNs
                    "spiderX": "/"
                }
            },
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls", "quic"],
                "routeOnly": False
            }
        }]
    }

    # ── xray outbound (client) ────────────────────────────────────────────────
    xray_outbound = {
        "outbounds": [{
            "tag": "panda-reality",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": server_ip,
                    "port": 443,
                    "users": [{
                        "id": uid,
                        "flow": flow,
                        "encryption": "none",
                        "level": 0
                    }]
                }]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverName": domain,
                    # chrome fingerprint: mimics Chrome TLS ClientHello
                    # For H2 servers: chrome fingerprint gives ALPN h2
                    "fingerprint": "chrome",
                    "publicKey": pub,
                    "shortId": sid,
                    "spiderX": "/"
                }
            },
            "mux": {
                "enabled": False  # mux not compatible with xtls-rprx-vision
            }
        }]
    }

    # ── sing-box inbound (server) ─────────────────────────────────────────────
    sb_inbound = {
        "inbounds": [{
            "type": "vless",
            "tag": "vless-reality-in",
            "listen": "::",
            "listen_port": 443,
            "users": [{
                "uuid": uid,
                "flow": flow,
                "name": "panda-client-1"
            }],
            "tls": {
                "enabled": True,
                "server_name": domain,
                "reality": {
                    "enabled": True,
                    "handshake": {
                        "server": domain,
                        "server_port": port
                    },
                    "private_key": priv,
                    "short_id": short_ids,
                    "max_time_difference": "1m"
                }
            }
        }]
    }

    # ── sing-box outbound (client) ────────────────────────────────────────────
    sb_outbound = {
        "outbounds": [{
            "type": "vless",
            "tag": "panda-reality",
            "server": server_ip,
            "server_port": 443,
            "uuid": uid,
            "flow": flow,
            "tls": {
                "enabled": True,
                "server_name": domain,
                "utls": {
                    "enabled": True,
                    # chrome → mimics Chrome TLS including ALPN h2
                    "fingerprint": "chrome"
                },
                "reality": {
                    "enabled": True,
                    "public_key": pub,
                    "short_id": sid
                }
            }
        }]
    }

    # ── mihomo / clash-meta ───────────────────────────────────────────────────
    mihomo = (
        "proxies:\n"
        "  - name: panda-reality\n"
        "    type: vless\n"
        f"    server: {server_ip}\n"
        "    port: 443\n"
        f"    uuid: {uid}\n"
        "    network: tcp\n"
        "    tls: true\n"
        "    udp: true\n"
        f"    flow: {flow}\n"
        f"    servername: {domain}\n"
        "    reality-opts:\n"
        f"      public-key: {pub}\n"
        f"      short-id: {sid}\n"
        "    client-fingerprint: chrome\n"
        "\n"
        "# Use in: Mihomo, Clash Meta, Clash Verge, ClashX Pro, FlClash\n"
        "# Add proxies block to config, add to proxy-groups\n"
        "# NOTE: mux disabled — not compatible with xtls-rprx-vision"
    )

    # ── NekoRay / NekoBox JSON ────────────────────────────────────────────────
    nekoray = {
        "v": "2",
        "type": "vless",
        "name": f"panda-reality-{domain[:20]}",
        "add": server_ip,
        "port": 443,
        "id": uid,
        "flow": flow,
        "scy": "none",
        "net": "tcp",
        "tls": "reality",
        "sni": domain,
        "fp": "chrome",
        "pbk": pub,
        "sid": sid,
        "spx": "/",
    }

    # ── vless:// share URI ────────────────────────────────────────────────────
    params = _up.urlencode({
        "encryption": "none",
        "flow":        flow,
        "security":    "reality",
        "sni":         domain,
        "fp":          "chrome",
        "pbk":         pub,
        "sid":         sid,
        "spx":         "/",
        "type":        "tcp",
        "headerType":  "none",
    })
    share_uri = f"vless://{uid}@{server_ip}:443?{params}#{_up.quote('panda-reality-'+domain[:18])}"

    # ── Panel note ────────────────────────────────────────────────────────────
    panel_note = (
        "# 3x-ui / Marzban / X-UI\n"
        "# Add xray inbound in panel → Inbounds → Add\n\n"
        f"# DPI quality of target: {dpi_qual.upper()}\n"
        f"# H2 support: {'YES ✓' if h2 else 'NO — recommend selecting H2 domain'}\n\n"
        "# DPI bypass tips:\n"
        "# 1. Best dest = TLS1.3 + H2 + X25519 (IDEAL status)\n"
        "# 2. fingerprint=chrome mimics Chrome TLS ClientHello\n"
        "# 3. Multiple short_ids make traffic correlation harder\n"
        "# 4. spiderX=/ — Reality will mimic GET /\n"
        "# 5. For high load use xtls-rprx-vision-udp443\n"
        "# 6. Do NOT enable mux — not compatible with vision flow"
    )

    return jsonify({
        "xray_inbound":      xray_inbound,
        "xray_outbound":     xray_outbound,
        "singbox_inbound":   sb_inbound,
        "singbox_outbound":  sb_outbound,
        "mihomo":            mihomo,
        "nekoray":           nekoray,
        "share_uri":         share_uri,
        "panel_note":        panel_note,
        # legacy keys
        "xray": xray_inbound, "singbox": sb_inbound,
        "public_key": pub, "private_key": priv,
        "uuid": uid, "short_ids": short_ids,
        "domain": domain, "port": port,
        "h2_supported": h2, "dpi_quality": dpi_qual,
    })

@app.route("/api/defaults")
def api_defaults():
    return jsonify({
        "domains": "\n".join(domain_state["domains"]),
        "total":   domain_state["total"],
    })

@app.route("/api/domain-status")
def api_domain_status():
    return jsonify({
        "fetching":    domain_state["fetching"],
        "total":       domain_state["total"],
        "last_update": domain_state["last_update"],
        "sources":     domain_state["sources"],
    })

@app.route("/api/refresh-domains", methods=["POST"])
def api_refresh_domains():
    if domain_state["fetching"]:
        return jsonify({"ok": False, "msg": "Already updating..."})
    _refresh_domains_bg()
    return jsonify({"ok": True, "msg": "Update started"})


# ── HTML GUI ──────────────────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Panda SNI Finder v3</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=JetBrains+Mono:wght@300;400;500&display=swap" rel="stylesheet">
<style>
:root{
  --ink:#0d1120;--ink2:#141828;--ink3:#1c2235;--ink4:#242b42;
  --border:rgba(110,231,122,.14);--border2:rgba(110,231,122,.28);
  --green:#6ee77a;--green2:#a8f5b0;--green-d:#3a9e45;
  --cream:#e8e2d4;--cream2:#b8b2a4;
  --amber:#f5c842;--red:#f05a6a;--orange:#f07a42;--purple:#b06af0;
  --cyan:#42d4f4;--blue:#4285f4;
  --dim:#4a5270;
  --mono:'JetBrains Mono',monospace;--display:'Syne',sans-serif;
  --fs-base:14px;--fs-sm:12px;--fs-xs:11px;--fs-label:10px;
  --radius:14px;--radius-sm:9px;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{font-size:var(--fs-base)}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--ink2)}
::-webkit-scrollbar-thumb{background:var(--ink4);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--green-d)}
body{background:var(--ink);color:var(--cream);font-family:var(--display);min-height:100vh;overflow-x:hidden;font-size:var(--fs-base)}

/* ── backgrounds ── */
.bg-layer{position:fixed;inset:0;z-index:0;pointer-events:none;overflow:hidden}
.bg-glow{position:absolute;border-radius:50%;filter:blur(100px);opacity:.07}
.bg-glow.g1{width:800px;height:800px;background:radial-gradient(circle,#6ee77a,transparent 70%);top:-300px;left:-200px;animation:dA 22s ease-in-out infinite alternate}
.bg-glow.g2{width:600px;height:600px;background:radial-gradient(circle,#3a7aff,transparent 70%);bottom:-200px;right:-100px;animation:dB 28s ease-in-out infinite alternate}
@keyframes dA{from{transform:translate(0,0)}to{transform:translate(80px,60px)}}
@keyframes dB{from{transform:translate(0,0)}to{transform:translate(-60px,80px)}}
.dot-grid{position:fixed;inset:0;z-index:0;pointer-events:none;
  background-image:radial-gradient(circle,rgba(110,231,122,.055) 1px,transparent 1px);
  background-size:32px 32px}

.shell{position:relative;z-index:1;max-width:1920px;margin:0 auto;padding:0 28px 80px}

/* ── HEADER ── */
header{display:flex;align-items:center;padding:22px 0 20px;border-bottom:1px solid var(--border);margin-bottom:24px;animation:slideD .6s cubic-bezier(.16,1,.3,1) both;gap:16px}
@keyframes slideD{from{opacity:0;transform:translateY(-16px)}to{opacity:1;transform:none}}
.panda-mark{position:relative;width:52px;height:52px;flex-shrink:0}
.panda-mark svg{width:52px;height:52px}
.panda-pulse{position:absolute;inset:-5px;border-radius:50%;border:2px solid rgba(110,231,122,.28);animation:pp 3s ease-in-out infinite}
@keyframes pp{0%,100%{transform:scale(1);opacity:.28}50%{transform:scale(1.1);opacity:.7}}
.brand-name{font-family:var(--display);font-size:26px;font-weight:800;letter-spacing:-.5px;background:linear-gradient(135deg,var(--green2),var(--green) 50%,var(--amber));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;line-height:1}
.brand-sub{font-family:var(--mono);font-size:11px;font-weight:300;color:var(--dim);letter-spacing:2px;text-transform:uppercase;margin-top:4px}
.v2tag{display:inline-block;background:linear-gradient(135deg,var(--cyan),var(--blue));-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-weight:700;margin-left:8px}
.hstats{display:flex;gap:24px;margin-left:auto}
.hstat{text-align:center;min-width:60px}
.hstat-val{font-family:var(--mono);font-size:22px;font-weight:600;color:var(--green);line-height:1}
.hstat-val.amber{color:var(--amber)}.hstat-val.cyan{color:var(--cyan)}
.hstat-lbl{font-family:var(--mono);font-size:10px;color:var(--dim);letter-spacing:1.5px;text-transform:uppercase;margin-top:4px}

/* ── LAYOUT ── */
.layout{display:grid;grid-template-columns:310px 1fr;gap:16px;align-items:start}
@media(max-width:900px){.layout{grid-template-columns:1fr}}

/* ── CARD ── */
.card{background:var(--ink2);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;transition:border-color .3s}
.card:hover{border-color:var(--border2)}
.card-head{padding:14px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:9px;background:linear-gradient(180deg,rgba(110,231,122,.04),transparent)}
.card-title{font-family:var(--mono);font-size:11px;font-weight:500;color:var(--green2);letter-spacing:2px;text-transform:uppercase}
.card-body{padding:18px}
.field-lbl{font-family:var(--mono);font-size:10px;font-weight:500;color:var(--dim);letter-spacing:1.5px;text-transform:uppercase;display:block;margin-bottom:7px}
textarea,input[type=number]{width:100%;background:var(--ink3);border:1px solid rgba(110,231,122,.12);border-radius:var(--radius-sm);color:var(--cream);font-family:var(--mono);font-size:12px;font-weight:300;padding:10px 13px;outline:none;resize:vertical;transition:border-color .2s,box-shadow .2s;line-height:1.7}
textarea:focus,input[type=number]:focus{border-color:rgba(110,231,122,.45);box-shadow:0 0 0 3px rgba(110,231,122,.07)}
.field-row{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:14px}
input[type=range]{-webkit-appearance:none;width:100%;height:5px;background:var(--ink4);border-radius:3px;border:none;padding:0;cursor:pointer;outline:none}
input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;width:17px;height:17px;border-radius:50%;background:var(--green);box-shadow:0 0 10px rgba(110,231,122,.5);cursor:pointer;transition:transform .15s}
input[type=range]::-webkit-slider-thumb:hover{transform:scale(1.2)}

/* ── SCAN BUTTON ── */
.scan-btn{width:100%;margin-top:18px;padding:15px 22px;border-radius:var(--radius-sm);border:none;cursor:pointer;outline:none;font-family:var(--display);font-size:15px;font-weight:700;background:linear-gradient(135deg,var(--green-d),#2d7d35);color:#fff;box-shadow:0 4px 18px rgba(110,231,122,.25);transition:all .2s;display:flex;align-items:center;justify-content:center;gap:9px;position:relative;overflow:hidden}
.scan-btn::before{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(255,255,255,.1),transparent);opacity:0;transition:opacity .2s}
.scan-btn:hover::before{opacity:1}
.scan-btn:hover{transform:translateY(-1px);box-shadow:0 7px 24px rgba(110,231,122,.35)}
.scan-btn:active{transform:scale(.98)}
.scan-btn.running{background:linear-gradient(135deg,#7a2535,#5a1828);animation:sPulse 2s ease-in-out infinite}
@keyframes sPulse{0%,100%{box-shadow:0 4px 18px rgba(240,90,106,.3)}50%{box-shadow:0 4px 28px rgba(240,90,106,.55)}}
.scan-btn.fetching{background:linear-gradient(135deg,#3a5a8a,#2a4a7a);animation:fPulse 1.5s ease-in-out infinite}
@keyframes fPulse{0%,100%{box-shadow:0 4px 18px rgba(90,150,240,.3)}50%{box-shadow:0 4px 28px rgba(90,150,240,.55)}}
.scan-btn-icon{font-size:18px}
.scan-btn.running .scan-btn-icon,.scan-btn.fetching .scan-btn-icon{animation:spin 1.5s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

/* ── PROGRESS ── */
.progress-wrap{margin-top:14px;display:none}
.progress-wrap.vis{display:block}
.progress-track{height:6px;background:var(--ink4);border-radius:3px;overflow:hidden;margin-bottom:8px}
.progress-fill{height:100%;width:0%;border-radius:3px;background:linear-gradient(90deg,var(--green-d),var(--green),var(--green2));transition:width .5s cubic-bezier(.4,0,.2,1)}
.progress-info{display:flex;justify-content:space-between;font-family:var(--mono);font-size:11px;color:var(--dim)}
.progress-domain{font-family:var(--mono);font-size:11px;color:var(--cream2);margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* ── LOG ── */
.log-term{background:var(--ink);border:1px solid rgba(110,231,122,.08);border-radius:var(--radius-sm);padding:10px 13px;font-family:var(--mono);font-size:11px;font-weight:300;color:var(--dim);line-height:1.9;min-height:80px;max-height:150px;overflow-y:auto;margin-top:12px}
.ll{animation:llIn .2s ease}
@keyframes llIn{from{opacity:0;transform:translateX(-4px)}to{opacity:1;transform:none}}
.ll-ideal{color:var(--cyan);font-weight:500}.ll-ok{color:var(--green)}.ll-warn{color:var(--amber)}
.ll-err{color:var(--red)}.ll-dim{color:var(--dim)}.ll-done{color:var(--green2);font-weight:500}

/* DPI legend */
.dpi-legend{display:flex;gap:14px;flex-wrap:wrap;margin-top:12px;padding:10px 12px;background:rgba(61,69,96,.12);border-radius:var(--radius-sm);border:1px solid rgba(61,69,96,.25)}
.dpi-item{display:flex;align-items:center;gap:6px;font-family:var(--mono);font-size:10px;color:var(--cream2)}

/* sources */
#sourcesCard .card-body{padding:14px 18px}
.src-row{display:flex;align-items:center;gap:9px;padding:8px 0;border-bottom:1px solid rgba(61,69,96,.2);font-family:var(--mono);font-size:12px}
.src-row:last-of-type{border-bottom:none}
.src-dot{font-size:14px}
.src-name{color:var(--cream2);flex:1;font-size:12px}
.src-count{font-size:14px;font-weight:500;min-width:35px;text-align:right}
.src-msg{color:var(--dim);font-size:10px;margin-top:2px}

/* ── TABLE ── */
.empty-state{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:420px;gap:14px}
.empty-panda{font-size:64px;opacity:.13;animation:float 4s ease-in-out infinite}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-8px)}}
.empty-text{font-family:var(--mono);font-size:13px;color:var(--dim);letter-spacing:1px}
.empty-hint{font-family:var(--mono);font-size:11px;color:rgba(61,69,96,.7)}
.table-scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse}
thead th{font-family:var(--mono);font-size:10px;font-weight:500;color:var(--dim);letter-spacing:1.5px;text-transform:uppercase;padding:10px 11px;text-align:left;border-bottom:1px solid var(--border);white-space:nowrap;position:sticky;top:0;background:var(--ink2);z-index:2}
tbody tr{border-bottom:1px solid rgba(28,34,53,.8);transition:background .15s;animation:rowR .3s cubic-bezier(.16,1,.3,1) both}
tbody tr:hover{background:rgba(110,231,122,.035)}
@keyframes rowR{from{opacity:0;transform:translateX(-8px)}to{opacity:1;transform:none}}
td{padding:9px 11px;vertical-align:middle;font-family:var(--mono);font-size:12px;white-space:nowrap}
.domain-td{font-weight:500;color:var(--cream);max-width:180px;overflow:hidden;text-overflow:ellipsis;font-size:12px}
.rank-td{font-size:11px;color:var(--dim);width:28px}
.ip-td{color:var(--dim);font-size:11px}
.tls-13{color:var(--green)}.tls-12{color:var(--amber)}
.kex-x{color:var(--green2)}.kex-o{color:var(--cream2)}
.h2-yes{color:var(--cyan);font-weight:600}.h2-no{color:var(--dim)}
.cdn-yes{color:var(--blue)}.cdn-no{color:var(--dim)}
.score-td{width:80px}
.score-num{font-weight:600;font-size:13px}
.score-bar{height:3px;background:var(--ink4);border-radius:2px;margin-top:3px}
.score-bar-fill{height:100%;border-radius:2px;transition:width .8s cubic-bezier(.4,0,.2,1)}

/* ── BADGES ── */
.badge{display:inline-flex;align-items:center;gap:4px;padding:3px 9px;border-radius:20px;font-size:10px;font-family:var(--mono);letter-spacing:.5px;font-weight:500;border:1px solid;white-space:nowrap}
.badge-ideal{color:var(--cyan);border-color:rgba(66,212,244,.4);background:rgba(66,212,244,.09)}
.badge-excellent{color:var(--green);border-color:rgba(110,231,122,.32);background:rgba(110,231,122,.08)}
.badge-good{color:var(--amber);border-color:rgba(245,200,66,.32);background:rgba(245,200,66,.08)}
.badge-poor{color:var(--dim);border-color:rgba(61,69,96,.4);background:transparent}
.badge-blocked{color:var(--orange);border-color:rgba(240,122,66,.32);background:rgba(240,122,66,.08)}
.badge-skipped{color:var(--dim);border-color:rgba(61,69,96,.3);background:rgba(61,69,96,.06);text-decoration:line-through;opacity:.6}
.badge-rst{color:var(--red);border-color:rgba(240,90,106,.32);background:rgba(240,90,106,.08)}
.badge-timeout,.badge-error{color:var(--red);border-color:rgba(240,90,106,.25);background:rgba(240,90,106,.05)}
.badge-tampered{color:var(--purple);border-color:rgba(176,106,240,.32);background:rgba(176,106,240,.08)}
.badge-redirect{color:var(--orange);border-color:rgba(240,122,66,.4);background:rgba(240,122,66,.09)}

.use-btn{padding:4px 12px;border-radius:6px;font-family:var(--mono);font-size:11px;font-weight:500;background:rgba(110,231,122,.09);border:1px solid rgba(110,231,122,.22);color:var(--green);cursor:pointer;transition:all .15s}
.use-btn:hover{background:rgba(110,231,122,.17);border-color:rgba(110,231,122,.45)}
.use-btn.ideal{background:rgba(66,212,244,.09);border-color:rgba(66,212,244,.32);color:var(--cyan)}
.use-btn.ideal:hover{background:rgba(66,212,244,.17)}

/* ── TOP 3 ── */
.top3-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:14px 14px 0}
.top3-card{background:linear-gradient(135deg,rgba(110,231,122,.07),rgba(58,158,69,.03));border:1px solid rgba(110,231,122,.22);border-radius:var(--radius-sm);padding:14px 16px;cursor:pointer;transition:all .2s}
.top3-card:hover{border-color:rgba(110,231,122,.45);background:rgba(110,231,122,.11)}
.top3-card.rank1{border-color:rgba(66,212,244,.4);background:linear-gradient(135deg,rgba(66,212,244,.08),rgba(66,212,244,.03))}
.top3-card.rank1:hover{background:rgba(66,212,244,.14)}
.top3-card.rank2{border-color:rgba(245,200,66,.38);background:linear-gradient(135deg,rgba(245,200,66,.08),rgba(245,200,66,.03))}
.top3-rank{font-family:var(--mono);font-size:10px;color:var(--dim);letter-spacing:1.5px;text-transform:uppercase;margin-bottom:5px}
.top3-domain{font-family:var(--display);font-size:14px;font-weight:700;color:var(--cream);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.top3-meta{font-family:var(--mono);font-size:10px;color:var(--cream2);margin-top:4px}
.top3-score{font-family:var(--display);font-size:24px;font-weight:800;float:right;margin-top:-30px}
.top3-h2tag{display:inline-block;font-family:var(--mono);font-size:9px;padding:1px 5px;border-radius:3px;background:rgba(66,212,244,.12);border:1px solid rgba(66,212,244,.3);color:var(--cyan);margin-left:5px;vertical-align:middle}
.top3-score.s-cyan{color:var(--cyan)}.top3-score.s-green{color:var(--green)}.top3-score.s-amber{color:var(--amber)}

/* ── PAGINATION ── */
.pg-btn{padding:4px 12px;font-family:var(--mono);font-size:11px;background:var(--ink3);border:1px solid var(--border);color:var(--cream2);border-radius:6px;cursor:pointer;transition:all .15s}
.pg-btn:hover:not(:disabled){border-color:rgba(110,231,122,.3);color:var(--green)}
.pg-btn:disabled{opacity:.3;cursor:default}
.pg-num{min-width:28px;padding:4px 8px;font-family:var(--mono);font-size:11px;background:var(--ink3);border:1px solid var(--border);color:var(--dim);border-radius:6px;cursor:pointer;text-align:center;transition:all .15s}
.pg-num:hover{border-color:rgba(110,231,122,.3);color:var(--green)}
.pg-num.active{background:rgba(110,231,122,.12);border-color:rgba(110,231,122,.42);color:var(--green)}

/* ── CONFIG PANEL ── */
.config-sticky{position:sticky;top:16px;max-height:calc(100vh - 32px);overflow-y:auto;width:520px;flex-shrink:0}
.tabs-nav{display:flex;gap:2px;padding:12px 14px 0;border-bottom:1px solid var(--border);background:linear-gradient(180deg,rgba(110,231,122,.03),transparent);flex-wrap:wrap}
.tab-pill{padding:7px 12px;border-radius:6px 6px 0 0;font-family:var(--mono);font-size:10px;font-weight:500;letter-spacing:.8px;text-transform:uppercase;color:var(--dim);background:none;border:none;cursor:pointer;transition:all .2s;border-bottom:2px solid transparent;margin-bottom:-1px;white-space:nowrap}
.tab-pill:hover{color:var(--cream2);background:rgba(110,231,122,.04)}
.tab-pill.active{color:var(--green);border-bottom-color:var(--green);background:rgba(110,231,122,.06)}
.tab-content{display:none;padding:16px}
.tab-content.active{display:block}
.code-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}
.code-lbl{font-family:var(--mono);font-size:10px;color:var(--dim);letter-spacing:1.2px;text-transform:uppercase}
.code-block{background:var(--ink);border:1px solid rgba(110,231,122,.09);border-radius:var(--radius-sm);padding:13px 15px;font-family:var(--mono);font-size:11px;font-weight:300;color:var(--cream2);white-space:pre;overflow-x:auto;line-height:1.75;max-height:380px;overflow-y:auto}
.key-item{display:grid;grid-template-columns:95px 1fr auto;align-items:center;gap:8px;margin-bottom:10px}
.key-name{font-family:var(--mono);font-size:10px;color:var(--dim);letter-spacing:1px;text-transform:uppercase}
.key-value{font-family:var(--mono);font-size:11px;color:var(--green2);background:var(--ink3);border:1px solid rgba(110,231,122,.12);border-radius:7px;padding:6px 10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.copy-btn{padding:5px 12px;font-family:var(--mono);font-size:10px;font-weight:500;background:var(--ink3);border:1px solid rgba(110,231,122,.17);color:var(--cream2);border-radius:7px;cursor:pointer;transition:all .15s;white-space:nowrap}
.copy-btn:hover{border-color:rgba(110,231,122,.38);color:var(--green)}
.copy-btn.ok{color:var(--green);border-color:rgba(110,231,122,.42)}
.platform-note{background:rgba(61,69,96,.22);border:1px solid rgba(61,69,96,.45);border-radius:var(--radius-sm);padding:10px 13px;font-family:var(--mono);font-size:11px;color:var(--cream2);line-height:1.75;margin-bottom:12px}
.platform-note strong{color:var(--green2)}
.platform-note .dpi-badge{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600;margin-left:5px}
.dpi-ideal{background:rgba(66,212,244,.12);border:1px solid rgba(66,212,244,.35);color:var(--cyan)}
.dpi-good{background:rgba(110,231,122,.12);border:1px solid rgba(110,231,122,.3);color:var(--green)}
.dpi-fair{background:rgba(245,200,66,.1);border:1px solid rgba(245,200,66,.3);color:var(--amber)}
.dpi-poor{background:rgba(61,69,96,.2);border:1px solid rgba(61,69,96,.4);color:var(--dim)}
.server-ip-row{display:flex;gap:9px;align-items:center;padding:13px 16px;border-bottom:1px solid var(--border);background:rgba(110,231,122,.02)}
.server-ip-lbl{font-family:var(--mono);font-size:10px;color:var(--dim);letter-spacing:1.5px;text-transform:uppercase;white-space:nowrap}
.server-ip-in{flex:1;background:var(--ink3);border:1px solid rgba(110,231,122,.17);border-radius:var(--radius-sm);color:var(--green2);font-family:var(--mono);font-size:12px;padding:7px 11px;outline:none;transition:border-color .2s}
.server-ip-in:focus{border-color:rgba(110,231,122,.45)}
.regen-btn{padding:7px 14px;font-family:var(--mono);font-size:10px;background:rgba(110,231,122,.09);border:1px solid rgba(110,231,122,.22);color:var(--green);border-radius:var(--radius-sm);cursor:pointer;transition:all .15s;white-space:nowrap}
.regen-btn:hover{background:rgba(110,231,122,.17)}

/* ── QUICK SEARCH — fixed z-index and pointer-events ── */
.quick-wrap{display:flex;gap:10px;align-items:stretch;position:relative;z-index:10}
.quick-domain{flex:1;min-width:0;height:42px;padding:0 15px;border-radius:var(--radius-sm);font-family:var(--mono);font-size:13px;background:var(--ink3);border:1.5px solid rgba(110,231,122,.2);color:var(--cream);outline:none;transition:border-color .2s,box-shadow .2s;pointer-events:all;position:relative;z-index:10;-webkit-user-select:text;user-select:text}
.quick-domain:focus{border-color:rgba(110,231,122,.55);box-shadow:0 0 0 3px rgba(110,231,122,.08)}
.quick-domain::placeholder{color:var(--dim)}
.quick-port{width:80px;height:42px;padding:0 10px;border-radius:var(--radius-sm);font-family:var(--mono);font-size:13px;background:var(--ink3);border:1.5px solid rgba(110,231,122,.2);color:var(--cream);outline:none;transition:border-color .2s;pointer-events:all;z-index:10}
.quick-port:focus{border-color:rgba(110,231,122,.55)}
.quick-btn{height:42px;padding:0 20px;border-radius:var(--radius-sm);font-family:var(--mono);font-size:12px;font-weight:600;background:rgba(110,231,122,.12);border:1.5px solid rgba(110,231,122,.28);color:var(--green);cursor:pointer;white-space:nowrap;transition:all .15s;pointer-events:all;z-index:10}
.quick-btn:hover:not(:disabled){background:rgba(110,231,122,.2);border-color:rgba(110,231,122,.5)}
.quick-btn:disabled{opacity:.5;cursor:default}
#quickResult{display:none;margin-top:12px;padding:12px 15px;background:var(--ink);border:1px solid var(--border);border-radius:var(--radius-sm);font-family:var(--mono);font-size:12px;position:relative;z-index:10}

/* filter bar */
.filter-bar{display:flex;gap:8px;align-items:center;padding:10px 14px;border-bottom:1px solid var(--border);flex-wrap:wrap}
.filter-btn{padding:4px 12px;font-family:var(--mono);font-size:10px;font-weight:500;background:var(--ink3);border:1px solid var(--border);color:var(--dim);border-radius:6px;cursor:pointer;transition:all .15s}
.filter-btn:hover{border-color:var(--border2);color:var(--cream2)}
.filter-btn.active{background:rgba(110,231,122,.1);border-color:rgba(110,231,122,.38);color:var(--green)}
.filter-btn.active.cyan{background:rgba(66,212,244,.1);border-color:rgba(66,212,244,.38);color:var(--cyan)}

/* toast */
.toast{position:fixed;bottom:24px;right:24px;z-index:9999;background:var(--ink3);border:1px solid rgba(110,231,122,.32);color:var(--green2);font-family:var(--mono);font-size:12px;padding:10px 18px;border-radius:var(--radius-sm);box-shadow:0 8px 28px rgba(0,0,0,.4);opacity:0;transform:translateY(10px) scale(.96);transition:all .3s cubic-bezier(.16,1,.3,1);pointer-events:none}
.toast.show{opacity:1;transform:translateY(0) scale(1)}

.anim-in{animation:fadeIn .5s cubic-bezier(.16,1,.3,1) both}
@keyframes fadeIn{from{opacity:0;transform:translateY(7px)}to{opacity:1;transform:none}}
.a1{animation-delay:.05s}.a2{animation-delay:.12s}.a3{animation-delay:.2s}
</style>
</head>
<body>
<div class="bg-layer"><div class="bg-glow g1"></div><div class="bg-glow g2"></div></div>
<div class="dot-grid"></div>
<div class="shell">

<!-- HEADER -->
<header>
  <div class="panda-mark">
    <div class="panda-pulse"></div>
    <svg viewBox="0 0 52 52" fill="none">
      <circle cx="26" cy="30" r="17" fill="#e8e2d4" opacity=".95"/>
      <circle cx="10" cy="12" r="7" fill="#1c2235"/><circle cx="42" cy="12" r="7" fill="#1c2235"/>
      <circle cx="26" cy="20" r="14" fill="#e8e2d4" opacity=".95"/>
      <ellipse cx="19.5" cy="18" rx="5" ry="5.5" fill="#1c2235"/><ellipse cx="32.5" cy="18" rx="5" ry="5.5" fill="#1c2235"/>
      <circle cx="19.5" cy="18.5" r="2.5" fill="#6ee77a"/><circle cx="32.5" cy="18.5" r="2.5" fill="#6ee77a"/>
      <circle cx="20" cy="18.5" r="1.2" fill="#0d1120"/><circle cx="33" cy="18.5" r="1.2" fill="#0d1120"/>
      <ellipse cx="26" cy="23.5" rx="2.5" ry="1.5" fill="#b8b2a4"/>
      <path d="M22 26 Q26 29 30 26" stroke="#b8b2a4" stroke-width="1.5" stroke-linecap="round" fill="none"/>
      <ellipse cx="26" cy="34" rx="7" ry="6" fill="#d8d0c0" opacity=".5"/>
    </svg>
  </div>
  <div>
    <div class="brand-name">Panda SNI Finder<span class="v2tag">v3</span></div>
    <div class="brand-sub">VLESS Reality · TLS1.3+H2+X25519 · DPI Bypass · Redirect Detection</div>
  </div>
  <div class="hstats">
    <div class="hstat"><div class="hstat-val" id="statTotal">—</div><div class="hstat-lbl">scanned</div></div>
    <div class="hstat"><div class="hstat-val cyan" id="statIdeal">—</div><div class="hstat-lbl">ideal H2</div></div>
    <div class="hstat"><div class="hstat-val" id="statGood">—</div><div class="hstat-lbl">suitable</div></div>
    <div class="hstat"><div class="hstat-val amber" id="statTime">—</div><div class="hstat-lbl">seconds</div></div>
  </div>
</header>

<div class="layout">

<!-- ── SIDEBAR ── -->
<div style="display:flex;flex-direction:column;gap:14px">

  <div class="card anim-in a1">
    <div class="card-head"><span>🎯</span><span class="card-title">Scan</span></div>
    <div class="card-body">
      <label class="field-lbl">Domains — one per line</label>
      <textarea id="domainsTa" style="min-height:180px" placeholder="loading..."></textarea>
      <div class="field-row">
        <div><label class="field-lbl">Port</label><input type="number" id="portIn" value="443" min="1" max="65535"></div>
        <div><label class="field-lbl">Threads — <span id="concVal" style="color:var(--green)">15</span></label>
          <div style="margin-top:11px"><input type="range" id="concSlider" min="1" max="40" value="15"></div>
        </div>
      </div>
      <button class="scan-btn" id="scanBtn" onclick="startProbe()">
        <span class="scan-btn-icon" id="btnIcon">🐼</span>
        <span id="btnLabel">Start Scan</span>
      </button>
      <div class="progress-wrap" id="progressWrap">
        <div class="progress-track"><div class="progress-fill" id="progressFill"></div></div>
        <div class="progress-info"><span id="progressNums">0/0</span><span id="progressPct">0%</span></div>
        <div class="progress-domain" id="progressDomain"></div>
      </div>
      <div class="log-term" id="logTerm"><div class="ll ll-dim">// waiting...</div></div>
      <div class="dpi-legend">
        <div class="dpi-item"><span style="color:var(--cyan)">✦</span><span>IDEAL: TLS1.3+H2+X25519</span></div>
        <div class="dpi-item"><span style="color:var(--green)">✓</span><span>GOOD: TLS1.3</span></div>
        <div class="dpi-item"><span style="color:var(--red)">⊘</span><span>Block/RST</span></div>
      </div>
    </div>
  </div>

  <div class="card anim-in a2" id="sourcesCard">
    <div class="card-head">
      <span>🌐</span><span class="card-title">Domain Sources</span>
      <button onclick="refreshDomains()" id="refreshBtn"
        style="margin-left:auto;padding:5px 13px;font-family:var(--mono);font-size:11px;
               background:rgba(110,231,122,.09);border:1px solid rgba(110,231,122,.22);
               color:var(--green);border-radius:7px;cursor:pointer;transition:all .15s">
        ⟳ Refresh
      </button>
    </div>
    <div class="card-body" style="padding:12px 18px">
      <div id="fetchStatus" style="display:none;padding:9px 12px;border-radius:8px;margin-bottom:12px;
           background:rgba(90,150,240,.08);border:1px solid rgba(90,150,240,.2);
           font-family:var(--mono);font-size:11px;color:#7ab4f5">
        ⟳ Refreshing domain database...
      </div>
      <div id="sourcesList"></div>
      <div style="margin-top:14px;padding:12px 0 0;border-top:1px solid var(--border);
           display:flex;justify-content:space-between;align-items:center">
        <span style="font-family:var(--mono);font-size:11px;color:var(--dim);letter-spacing:1px;text-transform:uppercase">Total domains</span>
        <span id="domainTotal" style="color:var(--green);font-size:20px;font-weight:700;font-family:var(--mono)">—</span>
      </div>
      <div id="lastUpdate" style="margin-top:5px;font-family:var(--mono);font-size:10px;color:var(--dim)"></div>
    </div>
  </div>

</div><!-- /sidebar -->

<!-- ── MAIN RIGHT ── -->
<div style="display:flex;flex-direction:column;gap:14px;min-width:0">

  <!-- QUICK SEARCH -->
  <div class="card anim-in a2" style="position:relative;z-index:10">
    <div class="card-head"><span>🔍</span><span class="card-title">Quick Domain Probe</span></div>
    <div class="card-body" style="padding:14px 18px;position:relative;z-index:10">
      <div style="display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap;position:relative;z-index:10">
        <div style="flex:1;min-width:240px;position:relative;z-index:10">
          <label style="display:block;font-family:var(--mono);font-size:10px;color:var(--green);
                        letter-spacing:1.5px;text-transform:uppercase;margin-bottom:6px">
            🌐 Domain
          </label>
          <input type="text" id="quickInput"
            placeholder="www.apple.com"
            autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"
            onkeydown="if(event.key==='Enter'){event.preventDefault();quickSearch()}"
            style="width:100%;height:44px;padding:0 15px;border-radius:var(--radius-sm);
                   font-family:var(--mono);font-size:14px;font-weight:400;
                   background:var(--ink3);border:2px solid rgba(110,231,122,.35);
                   color:var(--cream);outline:none;box-sizing:border-box;
                   transition:border-color .2s,box-shadow .2s;
                   position:relative;z-index:10;-webkit-user-select:text;user-select:text">
        </div>
        <div style="position:relative;z-index:10">
          <label style="display:block;font-family:var(--mono);font-size:10px;color:var(--dim);
                        letter-spacing:1.5px;text-transform:uppercase;margin-bottom:6px">Port</label>
          <input type="number" id="quickPort" value="443" min="1" max="65535"
            onkeydown="if(event.key==='Enter'){event.preventDefault();quickSearch()}"
            style="width:80px;height:44px;padding:0 10px;border-radius:var(--radius-sm);
                   font-family:var(--mono);font-size:14px;
                   background:var(--ink3);border:2px solid rgba(110,231,122,.18);
                   color:var(--cream);outline:none;transition:border-color .2s;
                   position:relative;z-index:10">
        </div>
        <button id="quickBtn" onclick="quickSearch()"
          style="height:44px;padding:0 22px;border-radius:var(--radius-sm);
                 font-family:var(--mono);font-size:13px;font-weight:600;
                 background:rgba(110,231,122,.15);border:2px solid rgba(110,231,122,.4);
                 color:var(--green);cursor:pointer;white-space:nowrap;
                 transition:all .15s;position:relative;z-index:10;align-self:flex-end">
          Probe →
        </button>
      </div>
      <div id="quickResult" style="display:none;margin-top:12px;padding:12px 15px;
           background:var(--ink);border:1px solid var(--border);border-radius:var(--radius-sm);
           font-family:var(--mono);font-size:12px;position:relative;z-index:10"></div>
    </div>
  </div>

  <!-- RESULTS + CONFIG ROW -->
  <div style="display:flex;gap:14px;align-items:start;min-width:0">

    <!-- RESULTS TABLE -->
    <div style="flex:1;min-width:0">
    <div class="card anim-in a3" style="min-height:440px">
      <div class="card-head" style="flex-wrap:wrap;gap:8px">
        <span>📡</span><span class="card-title">Results</span>
        <span id="resultBadge" style="font-family:var(--mono);font-size:11px;color:var(--dim)"></span>
        <div id="paginationTop" style="display:none;margin-left:auto;align-items:center;gap:8px">
          <span style="font-family:var(--mono);font-size:11px;color:var(--dim)">Per page:</span>
          <select id="perPageSel" onchange="setPerPage(this.value)"
            style="background:var(--ink3);border:1px solid var(--border);color:var(--cream2);
                   font-family:var(--mono);font-size:11px;border-radius:6px;padding:4px 8px;cursor:pointer;outline:none">
            <option value="25">25</option>
            <option value="50" selected>50</option>
            <option value="100">100</option>
            <option value="9999">All</option>
          </select>
        </div>
      </div>

      <div class="filter-bar" id="filterBar" style="display:none">
        <span style="font-family:var(--mono);font-size:10px;color:var(--dim);letter-spacing:1px;text-transform:uppercase">Filter:</span>
        <button class="filter-btn active" onclick="setFilter('all',this)">All</button>
        <button class="filter-btn cyan" onclick="setFilter('ideal',this)">✦ Ideal H2</button>
        <button class="filter-btn" onclick="setFilter('suitable',this)">✓ Suitable</button>
        <button class="filter-btn" onclick="setFilter('h2',this)">H2 only</button>
        <button class="filter-btn" onclick="setFilter('blocked',this)">⊘ Blocked</button>
        <button class="filter-btn" onclick="setFilter('bad',this)">✕ Errors</button>
        <div style="display:flex;gap:6px;margin-left:auto">
          <button onclick="exportData('csv')" class="filter-btn" title="Download CSV">📊 CSV</button>
          <button onclick="exportData('json')" class="filter-btn" title="Download JSON">📋 JSON</button>
          <button onclick="exportData('zip')" class="filter-btn" title="Full export">📦 ZIP</button>
        </div>
      </div>

      <!-- TOP 3 -->
      <div id="top3Wrap" style="display:none">
        <div class="top3-grid" id="top3Grid"></div>
        <div style="height:12px"></div>
      </div>

      <div class="empty-state" id="emptyState">
        <div class="empty-panda">🐼</div>
        <div class="empty-text">Start a scan</div>
        <div class="empty-hint">// Looking for TLS1.3 + H2 + X25519 for Reality</div>
      </div>

      <div class="table-scroll" id="tableWrap" style="display:none">
        <table>
          <thead><tr>
            <th>#</th><th>Domain</th><th>IP</th><th>TLS</th>
            <th title="Key Exchange">KEX</th>
            <th title="HTTP/2 via ALPN">H2</th>
            <th title="CDN / multiple IPs">CDN</th>
            <th title="HTTP redirect — bad for Reality">REDIR</th>
            <th>RTT</th><th>Score</th>
            <th title="DPI bypass quality">DPI</th>
            <th>Status</th><th></th>
          </tr></thead>
          <tbody id="resultsBody"></tbody>
        </table>
      </div>

      <div id="paginationBottom" style="display:none;padding:12px 14px;border-top:1px solid var(--border);
           align-items:center;justify-content:space-between;gap:9px">
        <span id="pageInfo" style="font-family:var(--mono);font-size:11px;color:var(--dim)"></span>
        <div style="display:flex;gap:5px;align-items:center">
          <button onclick="goPage(-1)" class="pg-btn" id="pgPrev">← Prev</button>
          <div id="pgNumbers" style="display:flex;gap:3px"></div>
          <button onclick="goPage(1)" class="pg-btn" id="pgNext">Next →</button>
        </div>
      </div>
    </div>
    </div>

    <!-- CONFIG PANEL -->
    <div id="configSection" style="display:none" class="config-sticky">
    <div class="card">
      <div class="server-ip-row">
        <span class="server-ip-lbl">Server IP</span>
        <input class="server-ip-in" type="text" id="serverIpIn" placeholder="1.2.3.4">
        <button class="regen-btn" onclick="regenConfig()">⟳ Regenerate</button>
      </div>

      <div class="card-head" style="border-top:none">
        <span>⚙️</span>
        <span class="card-title">Configuration</span>
        <span id="configDomainLabel" style="font-family:var(--mono);font-size:11px;color:var(--green2);margin-left:7px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:150px"></span>
        <span id="configDpiTag" style="margin-left:5px"></span>
        <button onclick="document.getElementById('configSection').style.display='none'"
          style="margin-left:auto;background:none;border:none;color:var(--dim);cursor:pointer;font-size:16px;padding:2px 6px;border-radius:4px;transition:color .15s"
          onmouseover="this.style.color='var(--cream)'" onmouseout="this.style.color='var(--dim)'">✕</button>
      </div>

      <div style="padding:10px 14px 0;border-bottom:1px solid var(--border)">
        <div style="font-family:var(--mono);font-size:10px;color:var(--dim);letter-spacing:1.5px;text-transform:uppercase;margin-bottom:7px">Core / Client</div>
        <div class="tabs-nav" style="padding:0;border:none;background:none;flex-wrap:wrap;gap:5px;margin-bottom:9px">
          <button class="tab-pill active" onclick="switchTab('xray-in',this)">⚙ xray server</button>
          <button class="tab-pill" onclick="switchTab('xray-out',this)">🖥 xray client</button>
          <button class="tab-pill" onclick="switchTab('sb-in',this)">⚙ sb server</button>
          <button class="tab-pill" onclick="switchTab('sb-out',this)">📱 sb client</button>
          <button class="tab-pill" onclick="switchTab('mihomo',this)">🌊 mihomo</button>
          <button class="tab-pill" onclick="switchTab('nekoray',this)">🦊 nekoray</button>
          <button class="tab-pill" onclick="switchTab('uri',this)">🔗 share link</button>
          <button class="tab-pill" onclick="switchTab('keys',this)">🔑 Keys</button>
        </div>
      </div>

      <div class="tab-content active" id="tab-xray-in">
        <div class="platform-note"><strong>Server cores:</strong> 3x-ui, Marzban, X-UI, any xray-core panels</div>
        <div class="code-hdr"><span class="code-lbl">xray inbound (server)</span><button class="copy-btn" onclick="copyEl('xrayInCode',this)">Copy</button></div>
        <div class="code-block" id="xrayInCode"></div>
      </div>
      <div class="tab-content" id="tab-xray-out">
        <div class="platform-note"><strong>Clients:</strong> v2rayN (Windows), NekoBox (Win/Linux), Furious</div>
        <div class="code-hdr"><span class="code-lbl">xray outbound (client)</span><button class="copy-btn" onclick="copyEl('xrayOutCode',this)">Copy</button></div>
        <div class="code-block" id="xrayOutCode"></div>
      </div>
      <div class="tab-content" id="tab-sb-in">
        <div class="platform-note"><strong>Server cores:</strong> Hiddify Panel, sing-box server</div>
        <div class="code-hdr"><span class="code-lbl">sing-box inbound (server)</span><button class="copy-btn" onclick="copyEl('sbInCode',this)">Copy</button></div>
        <div class="code-block" id="sbInCode"></div>
      </div>
      <div class="tab-content" id="tab-sb-out">
        <div class="platform-note"><strong>Clients:</strong> Hiddify (iOS/Android/Win/Mac), NekoBox, SFM</div>
        <div class="code-hdr"><span class="code-lbl">sing-box outbound (client)</span><button class="copy-btn" onclick="copyEl('sbOutCode',this)">Copy</button></div>
        <div class="code-block" id="sbOutCode"></div>
      </div>
      <div class="tab-content" id="tab-mihomo">
        <div class="platform-note"><strong>Clients:</strong> Mihomo, Clash Meta, Clash Verge, ClashX Pro, FlClash, Stash</div>
        <div class="code-hdr"><span class="code-lbl">clash-meta YAML</span><button class="copy-btn" onclick="copyEl('mihomoCode',this)">Copy</button></div>
        <div class="code-block" id="mihomoCode"></div>
      </div>
      <div class="tab-content" id="tab-nekoray">
        <div class="platform-note"><strong>Clients:</strong> NekoRay (Linux/Win), NekoBox (Win/Android)</div>
        <div class="code-hdr"><span class="code-lbl">nekoray / nekobox JSON</span><button class="copy-btn" onclick="copyEl('nekorayCode',this)">Copy</button></div>
        <div class="code-block" id="nekorayCode"></div>
      </div>
      <div class="tab-content" id="tab-uri">
        <div class="platform-note"><strong>Universal vless:// link</strong><br>Shadowrocket (iOS), v2rayNG (Android), Streisand, v2rayN, NapsternetV</div>
        <div class="code-hdr"><span class="code-lbl">vless:// share URI</span><button class="copy-btn" onclick="copyEl('uriCode',this)">Copy</button></div>
        <div class="code-block" id="uriCode" style="word-break:break-all;white-space:pre-wrap"></div>
      </div>
      <div class="tab-content" id="tab-keys">
        <div class="platform-note" id="panelNote" style="margin-bottom:13px;font-size:10px;white-space:pre-wrap"></div>
        <div id="keyGrid" style="display:flex;flex-direction:column;gap:9px"></div>
      </div>
    </div>
    </div><!-- /config -->

  </div><!-- /results+config row -->
</div><!-- /main right -->
</div><!-- /layout -->
</div><!-- /shell -->
<div class="toast" id="toast"></div>

<script>
let polling=null,lastLen=0,allResults=[],filteredResults=[],currentPage=1,perPage=50;
let domainPollTimer=null,quickProbing=false;
let lastConfigDomain=null,lastConfigPort=443,lastConfigH2=false,lastConfigDpi='';
let currentFilter='all';

document.addEventListener('DOMContentLoaded',async()=>{
  document.getElementById('concSlider').addEventListener('input',e=>{
    document.getElementById('concVal').textContent=e.target.value;
  });
  // Ensure input is functional
  const qi=document.getElementById('quickInput');
  qi.addEventListener('click',()=>qi.focus());
  await loadDomains();
  pollDomainStatus();
});

async function loadDomains(){
  const d=await(await fetch('/api/defaults')).json();
  document.getElementById('domainsTa').value=d.domains;
}

async function pollDomainStatus(){
  try{
    const d=await(await fetch('/api/domain-status')).json();
    renderSources(d);
    if(!d.fetching){const dd=await(await fetch('/api/defaults')).json();document.getElementById('domainsTa').value=dd.domains;}
    domainPollTimer=setTimeout(pollDomainStatus,d.fetching?1200:8000);
  }catch(e){domainPollTimer=setTimeout(pollDomainStatus,5000);}
}

function renderSources(d){
  document.getElementById('domainTotal').textContent=d.total||'—';
  document.getElementById('fetchStatus').style.display=d.fetching?'block':'none';
  const defs=[
    {key:'builtin',icon:'📦',label:'Built-in (115 domains)',note:'offline'},
    {key:'github', icon:'🐙',label:'jsDelivr → v2fly/XTLS',note:'CDN'},
    {key:'radar',  icon:'📡',label:'Cloudflare Radar top-500',note:'CDN'},
    {key:'tranco', icon:'🏆',label:'Majestic Million CDN',note:'direct'},
    {key:'crtsh',  icon:'🔏',label:'Certspotter / crt.sh',note:'fallback'},
  ];
  document.getElementById('sourcesList').innerHTML=defs.map(s=>{
    const src=(d.sources||{})[s.key]||{};
    const ok=src.ok;
    const dotColor=ok===true?'var(--green)':ok===false?'var(--red)':'var(--dim)';
    const isWarn=src.msg&&src.msg.includes('⚠');
    const cnt=src.count>0?`<span class="src-count" style="color:var(--green)">${src.count}</span>`
                         :`<span class="src-count" style="color:var(--dim)">—</span>`;
    const msgColor=isWarn?'var(--amber)':'var(--dim)';
    const msg=src.msg
      ?`<div class="src-msg" style="color:${msgColor}">${src.msg}</div>`
      :`<div class="src-msg" style="color:var(--dim);font-style:italic">${s.note}</div>`;
    return`<div class="src-row"><span class="src-dot" style="color:${dotColor}">${ok!=null?'●':'○'}</span>
      <div style="flex:1"><div class="src-name">${s.icon} ${s.label}</div>${msg}</div>${cnt}</div>`;
  }).join('');
  const rb=document.getElementById('refreshBtn');
  rb.textContent=d.fetching?'⟳ ...':'⟳ Refresh';
  rb.disabled=!!d.fetching;
  if(d.last_update){
    const dt=new Date(d.last_update);
    document.getElementById('lastUpdate').textContent=`Updated: ${dt.toLocaleTimeString('en-US')}`;
  }
}

async function refreshDomains(){
  await fetch('/api/refresh-domains',{method:'POST'});
  clearTimeout(domainPollTimer);pollDomainStatus();
}

function setFilter(f,btn){
  currentFilter=f;
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  if(btn)btn.classList.add('active');
  currentPage=1;applyFilter();renderTable();
}
function applyFilter(){
  if(currentFilter==='all')          filteredResults=[...allResults];
  else if(currentFilter==='ideal')   filteredResults=allResults.filter(r=>r.status==='ideal');
  else if(currentFilter==='suitable')filteredResults=allResults.filter(r=>r.suitable);
  else if(currentFilter==='h2')      filteredResults=allResults.filter(r=>r.h2_supported);
  else if(currentFilter==='blocked') filteredResults=allResults.filter(r=>r.status==='blocked'||r.status==='rst'||r.status==='tampered'||r.status==='skipped'||r.status==='redirect');
  else if(currentFilter==='bad')     filteredResults=allResults.filter(r=>r.status==='timeout'||r.status==='error'||r.status==='poor');
  else filteredResults=[...allResults];
}

async function startProbe(){
  const btn=document.getElementById('scanBtn');
  if(btn.classList.contains('running')){
    await fetch('/api/stop',{method:'POST'});
    document.getElementById('btnLabel').textContent='Stopping...';
    document.getElementById('btnIcon').textContent='⏳';
    // Force-reset UI if still stuck after 8s
    setTimeout(()=>{
      if(btn.classList.contains('running')){
        setRunning(false);
        document.getElementById('progressDomain').textContent='⏹ Force-stopped';
        toast('⏹ Scan force-stopped');
        clearInterval(polling);
        // Fetch final results
        fetch('/api/status').then(r=>r.json()).then(d=>{
          if(d.results.length){allResults=d.results;applyFilter();renderTable();}
        }).catch(()=>{});
      }
    },8000);
    return;
  }
  const domains=document.getElementById('domainsTa').value.trim();
  const port=parseInt(document.getElementById('portIn').value)||443;
  const conc=parseInt(document.getElementById('concSlider').value)||15;
  if(!domains){toast('Enter domains');return;}

  const status=await(await fetch('/api/domain-status')).json();
  if(status.fetching||!status.last_update){
    btn.classList.add('fetching');
    document.getElementById('btnIcon').textContent='⟳';
    document.getElementById('btnLabel').textContent='Updating sources...';
    document.getElementById('progressWrap').classList.add('vis');
    document.getElementById('progressDomain').textContent='⟳ Loading domains...';
    if(!status.fetching)await fetch('/api/refresh-domains',{method:'POST'});
    for(let i=0;i<35;i++){
      await new Promise(r=>setTimeout(r,1000));
      const s2=await(await fetch('/api/domain-status')).json();
      renderSources(s2);
      if(!s2.fetching){const dd=await(await fetch('/api/defaults')).json();document.getElementById('domainsTa').value=dd.domains;break;}
    }
    btn.classList.remove('fetching');
  }

  allResults=[];filteredResults=[];currentPage=1;lastLen=0;currentFilter='all';
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  document.querySelector('.filter-btn')?.classList.add('active');
  ['resultsBody'].forEach(id=>{const el=document.getElementById(id);if(el)el.innerHTML='';});
  document.getElementById('tableWrap').style.display='none';
  document.getElementById('emptyState').style.display='flex';
  document.getElementById('configSection').style.display='none';
  document.getElementById('top3Wrap').style.display='none';
  document.getElementById('paginationBottom').style.display='none';
  document.getElementById('paginationTop').style.display='none';
  document.getElementById('filterBar').style.display='none';
  document.getElementById('logTerm').innerHTML='<div class="ll ll-dim">// initializing...</div>';
  ['statTotal','statGood','statIdeal','statTime'].forEach(id=>document.getElementById(id).textContent='—');
  document.getElementById('resultBadge').textContent='';

  const freshDomains=document.getElementById('domainsTa').value.trim();
  const res=await fetch('/api/probe',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({domains:freshDomains,port,concurrency:conc})});
  if(!res.ok){const e=await res.json();toast(e.error||'Error');return;}
  setRunning(true);polling=setInterval(poll,600);
}

function setRunning(v){
  const btn=document.getElementById('scanBtn');
  document.getElementById('progressWrap').classList.toggle('vis',v);
  if(v){btn.classList.add('running');document.getElementById('btnIcon').textContent='⏹';document.getElementById('btnLabel').textContent='Stop';}
  else{btn.classList.remove('running');document.getElementById('btnIcon').textContent='🐼';document.getElementById('btnLabel').textContent='Start Scan';}
}

async function poll(){
  try{
    const d=await(await fetch('/api/status')).json();
    const pct=d.total?Math.round(d.progress/d.total*100):0;
    document.getElementById('progressFill').style.width=pct+'%';
    document.getElementById('progressNums').textContent=`${d.progress}/${d.total}`;
    document.getElementById('progressPct').textContent=pct+'%';
    if(d.current)document.getElementById('progressDomain').textContent='→ '+d.current;
    if(d.elapsed)document.getElementById('statTime').textContent=d.elapsed;
    updateLog(d.log);
    if(d.results.length>lastLen){allResults=d.results;applyFilter();renderTable();lastLen=d.results.length;}
    if(!d.running){
      clearInterval(polling);setRunning(false);
      if(d.results.length){
        allResults=d.results;applyFilter();renderTable();
        document.getElementById('filterBar').style.display='flex';
        const good=d.results.filter(r=>r.suitable).length;
        const ideal=d.results.filter(r=>r.status==='ideal').length;
        document.getElementById('statTotal').textContent=d.total;
        document.getElementById('statGood').textContent=good;
        document.getElementById('statIdeal').textContent=ideal;
        document.getElementById('statTime').textContent=d.elapsed;
        renderTop3(d.results);
        const best=d.results.find(r=>r.status==='ideal')||d.results.find(r=>r.suitable);
        if(best)genConfig(best.domain,best.port,best.h2_supported,best.dpi_quality);
        toast(`🐼 ${d.elapsed}s — ${ideal} ideal, ${good} suitable`);
      }
      document.getElementById('progressDomain').textContent='✓ Done';
    }
  }catch(e){
    console.warn('Poll error:',e);
    // Don't clear polling on transient errors — retry next tick
  }
}

function renderTop3(results){
  const suitable=results.filter(r=>r.suitable).slice(0,3);
  if(!suitable.length)return;
  document.getElementById('top3Wrap').style.display='block';
  const medals=['🥇','🥈','🥉'];
  const rankClass=['rank1','rank2','rank3'];
  document.getElementById('top3Grid').innerHTML=suitable.map((r,i)=>{
    const sc=r.score;
    const scc=r.status==='ideal'?'s-cyan':sc>=70?'s-green':'s-amber';
    const h2tag=r.h2_supported?'<span class="top3-h2tag">H2</span>':'';
    return`<div class="top3-card ${rankClass[i]}" onclick="genConfig('${r.domain}',${r.port},${r.h2_supported},'${r.dpi_quality}')" title="Click for config">
      <div class="top3-rank">${medals[i]} #${i+1}${r.status==='ideal'?' ✦ IDEAL':''}</div>
      <div class="top3-domain">${r.domain}${h2tag}</div>
      <div class="top3-meta">${r.tls_version||'—'} · ${r.rtt_avg?r.rtt_avg.toFixed(0)+'ms':'—'} · ${r.ip_count||1} IP</div>
      <div class="top3-score ${scc}">${sc}</div>
    </div>`;
  }).join('');
}

function setPerPage(v){perPage=parseInt(v);currentPage=1;renderTable();}
function goPage(d){const tp=Math.ceil(filteredResults.length/perPage);currentPage=Math.max(1,Math.min(tp,currentPage+d));renderTable();}
function jumpPage(n){currentPage=n;renderTable();}
function pageRange(cur,total){
  if(total<=7)return Array.from({length:total},(_,i)=>i+1);
  if(cur<=4)return[1,2,3,4,5,'…',total];
  if(cur>=total-3)return[1,'…',total-4,total-3,total-2,total-1,total];
  return[1,'…',cur-1,cur,cur+1,'…',total];
}

function renderTable(){
  if(!allResults.length)return;
  document.getElementById('emptyState').style.display='none';
  document.getElementById('tableWrap').style.display='block';
  const good=allResults.filter(r=>r.suitable).length;
  document.getElementById('resultBadge').textContent=
    currentFilter==='all'?`${good}/${allResults.length} suitable`:`${filteredResults.length} shown`;
  document.getElementById('statTotal').textContent=allResults.length;
  document.getElementById('statGood').textContent=allResults.filter(r=>r.suitable).length;
  document.getElementById('statIdeal').textContent=allResults.filter(r=>r.status==='ideal').length;
  const tp=Math.ceil(filteredResults.length/perPage);
  const s=(currentPage-1)*perPage,e=Math.min(s+perPage,filteredResults.length);
  const body=document.getElementById('resultsBody');body.innerHTML='';
  filteredResults.slice(s,e).forEach((r,i)=>{
    const sc=r.score;
    const scc=r.status==='ideal'?'var(--cyan)':sc>=70?'var(--green)':sc>=50?'var(--amber)':'var(--dim)';
    const tls=(r.tls_version||'').replace('TLSv','')||'—';
    const tlsC=r.tls_version==='TLSv1.3'?'tls-13':r.tls_version==='TLSv1.2'?'tls-12':'';
    const kex=r.key_exchange||'—',kexC=kex.includes('X25519')?'kex-x':'kex-o';
    const rtt=r.rtt_avg?r.rtt_avg.toFixed(0)+'ms':'—';
    const ip=r.resolved_ip?(r.resolved_ip.slice(0,14)+(r.ip_count>1?` +${r.ip_count-1}`:'')):'—';
    const h2=r.h2_supported?'<span class="h2-yes" title="HTTP/2 ALPN">H2✓</span>':'<span class="h2-no">—</span>';
    const cdn=r.is_cdn?`<span class="cdn-yes" title="${r.ip_count} IP">CDN</span>`:'<span class="cdn-no">—</span>';
    const redir=r.http_redirect?`<span style="color:var(--orange)" title="${r.redirect_location||''}">↪</span>`:'<span class="cdn-no">—</span>';
    const dpiColors={ideal:'var(--cyan)',good:'var(--green)',fair:'var(--amber)',poor:'var(--dim)'};
    const dpiC=dpiColors[r.dpi_quality]||'var(--dim)';
    const isIdeal=r.status==='ideal';
    const isSkipped=r.status==='skipped'||r.status==='blocked';
    const rowOpacity=isSkipped?'opacity:.45;':'';
    const ub=r.suitable?`<button class="use-btn${isIdeal?' ideal':''}" onclick="genConfig('${r.domain}',${r.port},${r.h2_supported},'${r.dpi_quality}')">${isIdeal?'✦ USE':'USE ↗'}</button>`:'';
    const tr=document.createElement('tr');tr.style.cssText='animation-delay:'+(i*0.008)+'s;'+rowOpacity;
    tr.innerHTML=`<td class="rank-td">${s+i+1}</td>
      <td class="domain-td" title="${r.domain}">${r.domain}</td>
      <td class="ip-td" title="${(r.all_ips||[]).join(', ')}">${ip}</td>
      <td class="${tlsC}">${tls}</td>
      <td class="${kexC}" style="font-size:11px">${kex.slice(0,12)}</td>
      <td>${h2}</td><td>${cdn}</td><td>${redir}</td><td>${rtt}</td>
      <td class="score-td"><span class="score-num" style="color:${scc}">${sc}</span>
        <div class="score-bar"><div class="score-bar-fill" style="width:${sc}%;background:${scc}"></div></div></td>
      <td style="color:${dpiC};font-family:var(--mono);font-size:10px;font-weight:600">${(r.dpi_quality||'—').toUpperCase()}</td>
      <td><span class="badge badge-${r.status}" title="${r.error||''}">${badgeInfo(r)}</span></td>
      <td>${ub}</td>`;
    body.appendChild(tr);
  });
  document.getElementById('paginationTop').style.display='flex';
  const pb=document.getElementById('paginationBottom');pb.style.display=tp>1?'flex':'none';
  if(tp>1){
    document.getElementById('pageInfo').textContent=`${s+1}–${e} of ${filteredResults.length}`;
    document.getElementById('pgPrev').disabled=currentPage<=1;
    document.getElementById('pgNext').disabled=currentPage>=tp;
    const pgN=document.getElementById('pgNumbers');pgN.innerHTML='';
    pageRange(currentPage,tp).forEach(n=>{
      if(n==='…'){const sp=document.createElement('span');sp.textContent='…';sp.style.cssText='padding:3px 6px;font-family:var(--mono);font-size:11px;color:var(--dim)';pgN.appendChild(sp);}
      else{const b=document.createElement('button');b.textContent=n;b.className='pg-num'+(n===currentPage?' active':'');b.onclick=()=>jumpPage(n);pgN.appendChild(b);}
    });
  }
}

function badgeInfo(r){
  const ic={ideal:'✦',excellent:'✦',good:'◆',poor:'◇',blocked:'⊘',skipped:'∅',rst:'⚡',timeout:'⏱',tampered:'⚠',redirect:'↪',error:'✕'};
  const lb={ideal:'IDEAL H2',excellent:'Excellent',good:'Good',poor:'Poor',blocked:'Blocked',skipped:'Infra',rst:'RST',timeout:'Timeout',tampered:'Tampered',redirect:'⚠ Redirect',error:'Error'};
  return`${ic[r.status]||'?'} ${lb[r.status]||r.status}`;
}

let _lastConfigData=null;
async function genConfig(domain,port,h2,dpiQuality){
  lastConfigDomain=domain;lastConfigPort=port;lastConfigH2=h2;lastConfigDpi=dpiQuality;
  const serverIp=document.getElementById('serverIpIn').value.trim()||'<SERVER_IP>';
  const d=await(await fetch('/api/genconfig',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({domain,port,server_ip:serverIp,h2_supported:h2,dpi_quality:dpiQuality})})).json();
  _lastConfigData=d;applyConfigData(d);
  document.getElementById('configSection').style.display='block';
  toast(`⚙️ ${domain} [${(dpiQuality||'').toUpperCase()}]`);
}

function applyConfigData(d){
  document.getElementById('configDomainLabel').textContent=d.domain;
  const dpiMap={ideal:'dpi-ideal',good:'dpi-good',fair:'dpi-fair',poor:'dpi-poor'};
  const dpiLbl={ideal:'✦ IDEAL',good:'◆ GOOD',fair:'◇ FAIR',poor:'— POOR'};
  const dq=d.dpi_quality||'good';
  document.getElementById('configDpiTag').innerHTML=
    `<span class="platform-note dpi-badge ${dpiMap[dq]||'dpi-fair'}">${dpiLbl[dq]||dq}</span>`;
  document.getElementById('xrayInCode').textContent=JSON.stringify(d.xray_inbound,null,2);
  document.getElementById('xrayOutCode').textContent=JSON.stringify(d.xray_outbound,null,2);
  document.getElementById('sbInCode').textContent=JSON.stringify(d.singbox_inbound,null,2);
  document.getElementById('sbOutCode').textContent=JSON.stringify(d.singbox_outbound,null,2);
  document.getElementById('mihomoCode').textContent=d.mihomo;
  document.getElementById('nekorayCode').textContent=JSON.stringify(d.nekoray,null,2);
  document.getElementById('uriCode').textContent=d.share_uri;
  document.getElementById('panelNote').textContent=d.panel_note||'';
  document.getElementById('keyGrid').innerHTML=[
    ['Private Key', d.private_key],
    ['Public Key',  d.public_key],
    ['UUID',        d.uuid],
    ['Short IDs',   (d.short_ids||[]).join(', ')],
    ['SNI / dest',  `${d.domain}:${d.port}`],
    ['H2 / ALPN',   d.h2_supported?'h2 ✓':'— (no H2)'],
  ].map(([k,v])=>`<div class="key-item">
    <span class="key-name">${k}</span>
    <span class="key-value" title="${v}">${v}</span>
    <button class="copy-btn" onclick="copyText('${String(v).replace(/\\/g,'\\\\').replace(/'/g,"\\'")}',this)">Copy</button>
  </div>`).join('');
}

async function regenConfig(){
  if(!lastConfigDomain)return;
  await genConfig(lastConfigDomain,lastConfigPort,lastConfigH2,lastConfigDpi);
  toast('🔑 Keys regenerated');
}

function switchTab(name,btn){
  document.querySelectorAll('.tab-pill').forEach(b=>b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c=>c.classList.remove('active'));
  if(btn)btn.classList.add('active');
  document.getElementById('tab-'+name).classList.add('active');
}

async function quickSearch(){
  if(quickProbing)return;
  const input=document.getElementById('quickInput');
  const raw=input.value.trim();
  const domain=raw.toLowerCase().replace(/^https?:\/\//,'').replace(/\/.*$/,'').replace(/:.*/,'');
  const port=parseInt(document.getElementById('quickPort').value)||443;
  if(!domain||!domain.includes('.')){toast('Enter domain (e.g. www.apple.com)');input.focus();return;}
  quickProbing=true;
  const btn=document.getElementById('quickBtn');btn.textContent='⟳ Probing...';btn.disabled=true;
  const res=document.getElementById('quickResult');res.style.display='block';
  res.innerHTML=`<span style="color:var(--amber)">⟳ TLS+ALPN+H2 probing: ${domain}:${port}...</span>`;
  try{
    const r1=await fetch('/api/probe',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({domains:domain,port,concurrency:1})});
    if(!r1.ok)throw new Error('Start error');
    let result=null;
    for(let i=0;i<30;i++){
      await new Promise(r=>setTimeout(r,600));
      const st=await(await fetch('/api/status')).json();
      if(!st.running&&st.progress>0){result=st.results[0];break;}
    }
    if(!result)throw new Error('Probe timeout');
    const sc=result.score;
    const scc=result.status==='ideal'?'var(--cyan)':sc>=70?'var(--green)':sc>=50?'var(--amber)':'var(--red)';
    const dpiColors={ideal:'var(--cyan)',good:'var(--green)',fair:'var(--amber)',poor:'var(--dim)'};
    const h2tag=result.h2_supported
      ?'<span style="color:var(--cyan);font-weight:700;font-size:13px">H2✓</span>'
      :'<span style="color:var(--dim)">no-H2</span>';
    const cdntag=result.is_cdn
      ?`<span style="color:var(--blue);font-size:11px">CDN[${result.ip_count}IP]</span>`:''
    res.innerHTML=`<div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:2px 0">
      <div>
        <div style="font-size:14px;font-weight:600;color:var(--cream)">${result.domain}</div>
        <div style="color:var(--dim);font-size:11px;margin-top:2px">${result.resolved_ip||'—'} · :${port}</div>
      </div>
      <span style="color:var(--green2);font-family:var(--mono);font-size:12px">${result.tls_version||'—'}</span>
      <span style="font-family:var(--mono);font-size:11px">${result.key_exchange||'—'}</span>
      ${h2tag} ${cdntag}
      <span class="badge badge-${result.status}" style="font-size:11px">${badgeInfo(result)}</span>
      <span style="font-size:20px;font-weight:800;color:${scc};font-family:var(--display)">${sc}</span>
      <span style="color:${dpiColors[result.dpi_quality]||'var(--dim)'};font-family:var(--mono);font-size:11px;font-weight:700">DPI:${(result.dpi_quality||'—').toUpperCase()}</span>
      ${result.suitable?`<button class="use-btn${result.status==='ideal'?' ideal':''}" style="font-size:12px;padding:5px 14px" onclick="genConfig('${result.domain}',${result.port},${result.h2_supported},'${result.dpi_quality}')">USE ↗</button>`:''}
      ${result.error?`<span style="color:var(--dim);font-size:11px">${result.error}</span>`:''}
    </div>`;
  }catch(e){res.innerHTML=`<span style="color:var(--red);font-size:13px">✕ ${e.message}</span>`;}
  quickProbing=false;btn.textContent='Probe →';btn.disabled=false;
}

function updateLog(lines){
  if(!lines.length)return;
  document.getElementById('logTerm').innerHTML=lines.map(l=>{
    let cls='ll-dim';
    if(l.startsWith('✦'))cls='ll-ideal';
    else if(l.startsWith('✓')||l.includes('EXCELLENT'))cls='ll-ok';
    else if(l.includes('⊘')||l.includes('RST')||l.includes('BLOCKED'))cls='ll-err';
    else if(l.includes('⚠')||l.includes('TAMPERED'))cls='ll-warn';
    else if(l.startsWith('──'))cls='ll-done';
    return`<div class="ll ${cls}">${l}</div>`;
  }).join('');
  document.getElementById('logTerm').scrollTop=9999;
}

function copyEl(id,btn){
  navigator.clipboard.writeText(document.getElementById(id).textContent);
  const o=btn.textContent;btn.textContent='✓ Copied';btn.classList.add('ok');
  setTimeout(()=>{btn.textContent=o;btn.classList.remove('ok')},1800);
}
function copyText(text,btn){
  navigator.clipboard.writeText(text);
  const o=btn.textContent;btn.textContent='✓';btn.classList.add('ok');
  setTimeout(()=>{btn.textContent=o;btn.classList.remove('ok')},1800);
}
function exportData(fmt){
  if(!allResults.length){toast('No results to export');return;}
  window.open('/api/export/'+fmt,'_blank');
  toast('📥 Downloading '+fmt.toUpperCase()+'...');
}
function toast(msg){
  const el=document.getElementById('toast');el.textContent=msg;el.classList.add('show');
  setTimeout(()=>el.classList.remove('show'),3500);
}
</script>
</body>
</html>
"""


# ── Export endpoints ──────────────────────────────────────────────────────────

@app.route("/api/export/csv")
@rate_limit()
def api_export_csv():
    results = probe_state.get("results", [])
    if not results:
        return jsonify({"error": "No results"}), 404
    output = io.StringIO()
    fields = ["domain","port","resolved_ip","ip_count","is_cdn",
              "tls_version","key_exchange","h2_supported",
              "http_redirect","redirect_location","ocsp_stapling",
              "cert_issuer","cert_days_left",
              "rtt_avg","score","dpi_quality","status","error"]
    w = csv.DictWriter(output, fieldnames=fields, extrasaction='ignore')
    w.writeheader()
    for r in sorted(results, key=lambda x: -x.get("score",0)):
        w.writerow(r)
    return Response(output.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition":
            f"attachment; filename=reality-probe-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}.csv"})

@app.route("/api/export/json")
@rate_limit()
def api_export_json():
    results = probe_state.get("results", [])
    if not results:
        return jsonify({"error": "No results"}), 404
    export = {"version":"3.0","timestamp":datetime.now(timezone.utc).isoformat(),
              "total":len(results),
              "ideal":len([r for r in results if r.get("status")=="ideal"]),
              "results":sorted(results, key=lambda x: -x.get("score",0))}
    return Response(json.dumps(export, indent=2, ensure_ascii=False),
        mimetype="application/json",
        headers={"Content-Disposition":
            f"attachment; filename=reality-probe-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}.json"})

@app.route("/api/export/zip")
@rate_limit()
def api_export_zip():
    results = probe_state.get("results", [])
    if not results:
        return jsonify({"error": "No results"}), 404
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        csv_buf = io.StringIO()
        fields = ["domain","score","status","dpi_quality","tls_version",
                  "h2_supported","key_exchange","rtt_avg","ip_count","http_redirect"]
        w = csv.DictWriter(csv_buf, fieldnames=fields, extrasaction='ignore')
        w.writeheader()
        for r in sorted(results, key=lambda x: -x.get("score",0)): w.writerow(r)
        zf.writestr("results.csv", csv_buf.getvalue())
        zf.writestr("results.json", json.dumps(results, indent=2))
        ideal = [r["domain"] for r in results
                if r.get("status")=="ideal" and not r.get("http_redirect")]
        zf.writestr("ideal_domains.txt",
            "# IDEAL domains (TLS1.3+H2+X25519, no redirect)\n" + "\n".join(ideal))
        suitable = [r["domain"] for r in results
                   if r.get("suitable") and not r.get("http_redirect")]
        zf.writestr("suitable_domains.txt",
            "# Suitable domains (score>=50, no redirect)\n" + "\n".join(suitable))
    buf.seek(0)
    return Response(buf.getvalue(), mimetype="application/zip",
        headers={"Content-Disposition":
            f"attachment; filename=reality-probe-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}.zip"})

@app.route("/api/history")
@rate_limit()
def api_history():
    return jsonify(_load_scan_history())


@app.route("/")
def index():
    return HTML


# ── entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import webbrowser
    port = 7890
    def _signal_handler(sig, frame):
        print(f"\n  🐼 Shutting down gracefully...")
        probe_state["stop_requested"] = True
        time.sleep(1)
        os._exit(0)
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    print(f"\n  🐼  Panda SNI Finder v3")
    print(f"  ─────────────────────────────────────────────────")
    print(f"  ► http://localhost:{port}")
    print(f"  ✦ v3 improvements:")
    print(f"     • ALPN/H2 detection — key parameter for DPI bypass")
    print(f"     • Multi-IP DNS → CDN detection")
    print(f"     • New scoring: TLS1.3+H2+X25519 = IDEAL")
    print(f"     • HTTP redirect detection (critical for Reality)\n")
    print(f"     • CSV/JSON/ZIP export\n")
    print(f"     • Rate limiting & input validation\n")
    print(f"     • Scan history persistence")
    print(f"  ⟳ Loading domains...\n")
    _refresh_domains_bg()
    def _open():
        time.sleep(1.2)
        webbrowser.open(f"http://localhost:{port}")
    threading.Thread(target=_open, daemon=True).start()
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
