# VPN Finder

<pre>
 __     ______  _   _   _____ _           _
 \ \   / /  _ \| \ | | |  ___(_)_ __   __| | ___ _ __
  \ \ / /| |_) |  \| | | |_  | | '_ \ / _` |/ _ \ '__|
   \ V / |  __/| |\  | |  _| | | | | | (_| |  __/ |
    \_/  |_|   |_| \_| |_|   |_|_| |_|\__,_|\___|_|
</pre>

**Version:** 2.1
**Created by:** Cyphernova1337, VoidSec-Hub

VPN Finder discovers **and fingerprints** the VPN / remote-access gateways
exposed by a target organisation. It doesn't just guess "this might be a VPN"
— it identifies the actual product (FortiGate, GlobalProtect, Cisco ASA,
Pulse/Ivanti, Citrix, SonicWall, F5 APM, and more), assigns a confidence
score with the evidence behind it, and flags the known CVEs relevant to each
product so you know where to look next.

**When the target hides behind a CDN/WAF (Cloudflare, CloudFront, Akamai,
Fastly, Imperva, Sucuri, …), VPN Finder works to recover the real origin IP
address** — through non-proxied subdomain leaks, historical/passive DNS, mail
(MX/SPF) infrastructure, TLS-certificate and favicon pivoting, and direct
origin verification — so the edge IP is never the end of the trail.

## 📜 Why this tool

Most subdomain tools stop at "here's a list of hosts." VPN Finder is built for
the specific job of locating remote-access infrastructure and telling you
*exactly what it is*:

* **Product identification, not keyword guessing.** A dedicated fingerprint
  engine matches TLS certificates, login-portal paths, response bodies,
  headers, cookies, and titles against a database of real VPN appliances.
* **Confidence scoring.** Every host gets a `0–100` score derived from
  multiple corroborating signals and a verdict: `CONFIRMED`, `LIKELY`,
  `POSSIBLE`, or none.
* **CVE context.** When a product is identified, the tool lists the notable
  CVEs for that product line (e.g. FortiOS `CVE-2024-21762`, Citrix Bleed
  `CVE-2023-4966`, Ivanti `CVE-2024-21887`) so you can prioritise. *Always
  verify the actual running version — these are pointers, not confirmations.*
* **CDN-bypass origin discovery.** Detects the fronting CDN/WAF and then hunts
  the true origin IP behind it by every passive/active means, verifying each
  candidate by a direct SNI + Host-header request and TLS/content match.
* **No hard external dependencies.** Subdomain brute-forcing, port scanning,
  and even DNS (a built-in resolver with UDP → TCP → DNS-over-HTTPS fallback)
  are implemented natively in Python — `ffuf` and `nmap` are **optional**
  enrichment, not requirements.
* **Broad passive enumeration.** Pulls subdomains from multiple free, key-less
  sources concurrently (crt.sh, CertSpotter, HackerTarget, RapidDNS,
  AlienVault OTX, Anubis, Wayback) and keeps going if any source is down.
* **Machine-readable output.** Colorized terminal report plus `--output`
  JSON and CSV for pipelines and reporting.

---

## ⚠️ Disclaimer

**For authorized security testing and bug-bounty engagements ONLY.**

* Always obtain explicit, written permission before scanning any target.
* Unauthorized scanning is illegal and unethical.
* The authors accept no liability for misuse. Use responsibly.

---

## ✨ What it does

| Stage | Description |
|-------|-------------|
| **Passive enumeration** | Concurrent lookups across 7 free public sources; fully key-less. |
| **Active DNS brute-force** | Native async-style resolver over a VPN-focused wordlist (no `ffuf` needed). |
| **Resolution** | Resolves every candidate to IPv4/IPv6, with reverse DNS. |
| **Port scan** | Native threaded TCP connect scan of common VPN ports; strong-signal ports (IKE, OpenVPN, WireGuard, etc.) weighted higher. |
| **Fingerprinting** | TLS certificate inspection + HTTP login-portal probing matched against the product database. |
| **CDN detection** | Identifies the fronting CDN/WAF via CNAME chains, headers, and ASN. |
| **Origin discovery** | Recovers the real IP behind the CDN and verifies it directly (see below). |
| **Scoring & verdict** | Combines all signals into a confidence score and a human-readable verdict. |
| **Reporting** | Colorized terminal output, ranked findings, JSON + CSV export. |

### Products fingerprinted

Fortinet FortiGate · Palo Alto GlobalProtect · Cisco ASA/AnyConnect ·
Ivanti Connect Secure / Pulse Secure · Citrix Gateway/NetScaler ·
SonicWall SMA/NSA · F5 BIG-IP APM · Check Point Mobile Access ·
Sophos · WatchGuard · Barracuda · OpenVPN Access Server · Array Networks ·
Microsoft RD Web / RD Gateway.

---

## 🛠️ Prerequisites

1. **Python 3.8+**
2. Python packages (see below): `requests` (required), `cryptography` (recommended — enables full TLS certificate parsing including SANs and issuer).
3. **Optional** external tools for extra enrichment:
   * `nmap` — pass `--nmap` for service/version banners on open ports.
   * `ffuf` — pass `--ffuf` for additional HTTP subdomain fuzzing.

The tool runs fully without `nmap`/`ffuf`; they only add depth when present.

---

## 🚀 Setup

```bash
git clone https://github.com/cyphernova1337/VPN_Finder.git
cd VPN_Finder
pip install -r requirements.txt
chmod +x vpn-finder.py
```

---

## ⚙️ Usage

```bash
# Basic — full discovery + fingerprinting
python3 vpn-finder.py company.com

# Thorough — fingerprint every resolved host, not just VPN-named ones,
# enrich with nmap, and export reports
python3 vpn-finder.py company.com --all --nmap -o results/company

# Fast passive-only pass (no brute-force, no port scan)
python3 vpn-finder.py company.com --skip-brute --skip-ports

# Custom wordlist and higher concurrency
python3 vpn-finder.py company.com -w my_vpn_words.txt -t 80
```

### Options

| Flag | Description |
|------|-------------|
| `-w, --wordlist` | Custom subdomain wordlist for DNS brute-force. |
| `-t, --threads` | Concurrency for resolution/scanning (default: 40). |
| `--timeout` | Per-connection timeout in seconds (default: 6). |
| `--all` | Fingerprint every resolved host, not just VPN-named candidates. |
| `--skip-passive` | Skip passive subdomain enumeration. |
| `--skip-brute` | Skip active DNS brute-force. |
| `--skip-ports` | Skip TCP port scanning (fingerprint over 443 only). |
| `--nmap` | Enrich open ports with `nmap -sV` (if installed). |
| `--ffuf` | Also run `ffuf` HTTP fuzzing (if installed). |
| `--ffuf-options` | Extra options passed through to `ffuf`. |
| `--no-origin` | Disable origin-IP discovery for CDN-fronted hosts. |
| `--force-origin` | Hunt for an origin IP even when no CDN is detected. |
| `--asn-sweep` | Sweep the ASN/netblock around confirmed origins (heavier). |
| `--sweep-cap` | Max IPs to sweep from a single CIDR (default: 1024). |
| `-o, --output` | Base path for output files (`.json`, `.csv`, `.origins.csv`). |
| `--min-confidence` | Only report hosts at/above this score (default: 20). |
| `--no-color` | Disable coloured output (also honours `NO_COLOR`). |

---

## 🕵️ CDN-bypass: finding the real origin IP

When a host is fronted by a CDN/WAF, its resolved IP is just the edge. VPN
Finder automatically detects this (via CNAME chains, response headers, and
Team Cymru ASN mapping) and launches an origin hunt that gathers candidate IPs
from every angle, then **verifies** each one by connecting directly to it with
the target's SNI and `Host:` header and comparing the TLS certificate and page
content to the real site:

| Technique | What it exploits |
|-----------|------------------|
| Non-proxied subdomains | `mail.`, `dev.`, `direct.`, `origin.`, `cpanel.` etc. often point at the origin, outside the CDN. |
| Historical / passive DNS | A-records that predate the CDN (AlienVault OTX, HackerTarget, SecurityTrails). |
| Mail infrastructure | MX hosts and SPF `ip4:` blocks usually live on the origin network. |
| TLS-certificate pivoting | Find IPs serving the same certificate (Censys / Shodan). |
| Favicon pivoting | Shodan-compatible murmur3 favicon hash to find matching hosts. |
| ASN / netblock sweep | `--asn-sweep` verifies neighbours in the origin's CIDR. |

A candidate is reported as a **CONFIRMED ORIGIN** when its certificate or served
page matches the target — that's the real IP behind the CDN.

### Optional API keys (set as environment variables)

The keyless techniques work out of the box. Setting any of these unlocks
additional pivoting sources:

* `SHODAN_API_KEY` — certificate/hostname and favicon-hash pivoting.
* `CENSYS_API_ID` + `CENSYS_API_SECRET` — certificate-name host search.
* `SECURITYTRAILS_API_KEY` — historical DNS A-records.

---

## 📊 Example output

```
=== sslvpn.company.com ===  [CONFIRMED VPN | 100/100]
  IPs           : 203.0.113.10
  Network       : AS64500 Example Telecom (203.0.113.0/24 US)
  Product       : Fortinet FortiGate SSL-VPN (Fortinet)
  Open TCP ports: 443, 10443
  TLS cert CN   : FGT60F-support
  Evidence      :
    - TLS cert matches /FortiGate/
    - body matches //remote/fgt_lang/ (HTTP 200)
    - cookie matches /SVPNCOOKIE/
  Known CVEs for this product (verify version!):
    ! CVE-2018-13379 (pre-auth arbitrary file read)
    ! CVE-2024-21762 (pre-auth RCE)

## 🌍 Environment variables

* `NO_COLOR` — disable colorized output.
* `TMPDIR` — location for temporary files (defaults to `/tmp`).
* `SHODAN_API_KEY`, `CENSYS_API_ID`, `CENSYS_API_SECRET`,
  `SECURITYTRAILS_API_KEY` — optional origin-discovery pivots (see above).
