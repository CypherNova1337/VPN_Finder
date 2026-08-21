#!/usr/bin/env python3
"""
VPN Finder - Automated VPN endpoint discovery and fingerprinting.

Discovers VPN/remote-access gateways for a target domain and identifies the
underlying product (FortiGate, GlobalProtect, Cisco ASA, Pulse/Ivanti,
Citrix, SonicWall, and more) with a confidence score and known-CVE context.

Created by: Cyphernova1337, VoidSec-Hub
"""

import argparse
import concurrent.futures
import csv
import json
import os
import re
import base64
import functools
import hashlib
import ipaddress
import random
import shutil
import socket
import ssl
import struct
import subprocess
import sys
from datetime import datetime, timezone

import requests
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.retry import Retry
except Exception:  # pragma: no cover - extremely old urllib3
    Retry = None

# Optional: richer TLS certificate parsing. The tool degrades gracefully
# to raw-certificate string matching if this is not installed.
def _try_import_cryptography():
    # A broken native backend can panic and write directly to fd 2, and can
    # raise a low-level PanicException (not an Exception). Silence fd 2 for the
    # duration of the attempt and catch BaseException so import stays quiet.
    saved_fd = None
    try:
        saved_fd = os.dup(2)
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, 2)
        os.close(devnull)
    except Exception:
        saved_fd = None
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.x509.oid import ExtensionOID, NameOID
        globals().update(x509=x509, default_backend=default_backend,
                         ExtensionOID=ExtensionOID, NameOID=NameOID)
        return True
    except BaseException:
        return False
    finally:
        if saved_fd is not None:
            os.dup2(saved_fd, 2)
            os.close(saved_fd)


_HAS_CRYPTO = _try_import_cryptography()

# Silence the InsecureRequestWarning; scanning appliances with self-signed
# certs is expected and intentional here.
try:
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except Exception:
    pass

SCRIPT_VERSION = "2.1"
SCRIPT_AUTHORS = "Cyphernova1337, VoidSec-Hub"
DEFAULT_USER_AGENT = f"Mozilla/5.0 (compatible; VPNFinder/{SCRIPT_VERSION})"


# --------------------------------------------------------------------------- #
#  Terminal colours
# --------------------------------------------------------------------------- #
class C:
    PURPLE = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    DIM = "\033[2m"

    @classmethod
    def disable(cls):
        for attr in ("PURPLE", "BLUE", "CYAN", "GREEN", "YELLOW", "RED",
                     "ENDC", "BOLD", "UNDERLINE", "DIM"):
            setattr(cls, attr, "")


if os.getenv("NO_COLOR") or not sys.stdout.isatty():
    C.disable()


def info(msg):
    print(f"{C.BLUE}[*]{C.ENDC} {msg}")


def good(msg):
    print(f"{C.GREEN}[+]{C.ENDC} {msg}")


def warn(msg):
    print(f"{C.YELLOW}[!]{C.ENDC} {msg}")


def err(msg):
    print(f"{C.RED}[ERROR]{C.ENDC} {msg}", file=sys.stderr)


# --------------------------------------------------------------------------- #
#  Wordlist (native DNS brute-force - no external fuzzer needed)
# --------------------------------------------------------------------------- #
VPN_WORDLIST = [
    "vpn", "vpn1", "vpn2", "vpn01", "vpn02", "vpn-gw", "vpngw", "vpn-gateway",
    "remote", "remoteaccess", "remote-access", "access", "secureaccess",
    "secure-access", "sslvpn", "ssl-vpn", "sslaccess", "webvpn", "web-vpn",
    "portal", "gateway", "gw", "securegw", "secure-gw", "connect", "client",
    "secure", "login", "auth", "sso", "adfs", "okta", "openvpn", "ovpn",
    "anyconnect", "asa", "cisco", "forti", "fortinet", "fortigate", "pulse",
    "pulsesecure", "ivanti", "connectsecure", "globalprotect", "gp", "gpvpn",
    "prisma", "internal", "corp", "corporate", "employee", "employeevpn",
    "staff", "staffvpn", "myvpn", "dialin", "telework", "wfh", "workfromhome",
    "extranet", "intranet", "work", "desktop", "vdi", "vpn-int", "vpnint",
    "citrix", "citrixgateway", "netscaler", "ns", "cag", "netextender",
    "sonicwall", "watchguard", "sophos", "utm", "barracuda", "checkpoint",
    "cp", "f5", "bigip", "apm", "array", "zscaler", "zpa", "ztna", "wireguard",
    "wg", "tunnel", "ras", "rdp", "rdgateway", "rdweb", "gateway1", "vpn-us",
    "vpn-eu", "vpn-asia", "east", "west", "emea", "apac", "hq", "dc", "edge",
    "fw", "firewall", "perimeter", "dmz",
]


# --------------------------------------------------------------------------- #
#  Port intelligence
# --------------------------------------------------------------------------- #
# Ports where a TLS handshake is worth attempting for HTTP(S) fingerprinting.
TLS_PORTS = [443, 4443, 4433, 8443, 10443, 943, 9443, 7443]
# Full TCP set scanned by the native scanner / passed to nmap.
COMMON_VPN_PORTS_TCP = sorted(set(
    [22, 443, 500, 636, 1194, 1723, 3389, 4443, 4433, 8080, 8443, 9443,
     10000, 10443, 943, 7443, 992, 4500]
))
COMMON_VPN_PORTS_UDP = [500, 1194, 4500, 1701, 51820, 1723]

# Ports that, when open, are a strong standalone VPN signal (weighted higher
# than 443/80 which are ambiguous).
STRONG_PORT_SIGNAL = {
    500: ("IKE / IPsec", 25),
    4500: ("IPsec NAT-T", 25),
    1194: ("OpenVPN", 30),
    1701: ("L2TP", 20),
    1723: ("PPTP", 15),
    51820: ("WireGuard", 30),
    10443: ("SSL-VPN (Fortinet/others)", 20),
    943: ("OpenVPN Access Server admin", 25),
}


# --------------------------------------------------------------------------- #
#  VPN fingerprint database  --  the core intelligence of the tool.
#
#  Each entry describes how to positively identify a specific remote-access
#  product from its login portal, TLS certificate, response headers/cookies,
#  and default ports. Regexes are matched case-insensitively.
# --------------------------------------------------------------------------- #
VPN_FINGERPRINTS = [
    {
        "name": "Fortinet FortiGate SSL-VPN",
        "vendor": "Fortinet",
        "paths": ["/remote/login", "/remote/login?lang=en"],
        "body": [r"/remote/fgt_lang", r"logincheck", r"fgt_lang", r"sslvpn",
                 r"/remote/login"],
        "title": [r"please login", r"fortinet"],
        "headers": {"server": [r"^xxxxxxxx"]},
        "cookies": [r"SVPNCOOKIE", r"SVPNNETWORKCOOKIE", r"APSCOOKIE"],
        "cert": [r"FortiGate", r"Fortinet", r"fortinet\.com", r"FGT[0-9A-Z]+"],
        "ports": [443, 10443, 4433],
        "cve": ["CVE-2018-13379 (pre-auth arbitrary file read)",
                "CVE-2022-40684 (auth bypass)",
                "CVE-2023-27997 / XORtigate (pre-auth heap overflow RCE)",
                "CVE-2024-21762 (pre-auth RCE)"],
    },
    {
        "name": "Palo Alto GlobalProtect",
        "vendor": "Palo Alto Networks",
        "paths": ["/global-protect/login.esp", "/global-protect/prelogin.esp",
                  "/ssl-vpn/login.esp", "/php/login.php"],
        "body": [r"global-protect", r"globalprotect", r"pan_?global",
                 r"gp-?portal", r"prelogin", r"clientVer"],
        "title": [r"globalprotect"],
        "headers": {},
        "cookies": [r"PHPSESSID"],
        "cert": [r"PAN-OS", r"Palo Alto", r"GlobalProtect", r"paloaltonetworks"],
        "ports": [443],
        "cve": ["CVE-2019-1579 (pre-auth RCE)",
                "CVE-2024-3400 (pre-auth command injection, actively exploited)"],
    },
    {
        "name": "Cisco ASA / AnyConnect WebVPN",
        "vendor": "Cisco",
        "paths": ["/+CSCOE+/logon.html", "/+webvpn+/index.html",
                  "/+CSCOE+/logon.html?fcadbadd=1"],
        "body": [r"\+CSCOE\+", r"webvpn", r"CSCOE", r"SSL VPN Service",
                 r"anyconnect", r"/\+CSCOU\+/"],
        "title": [r"ssl vpn service", r"anyconnect"],
        "headers": {},
        "cookies": [r"webvpn", r"webvpnlogin", r"webvpnc"],
        "cert": [r"Cisco", r"ASA", r"AnyConnect"],
        "ports": [443],
        "cve": ["CVE-2018-0101 (pre-auth RCE)",
                "CVE-2020-3452 (path traversal / file read)",
                "CVE-2023-20269 (unauthorized VPN access via brute force)"],
    },
    {
        "name": "Ivanti Connect Secure / Pulse Secure",
        "vendor": "Ivanti (formerly Pulse Secure / Juniper)",
        "paths": ["/dana-na/auth/url_default/welcome.cgi", "/dana-na/",
                  "/dana-na/auth/url_admin/welcome.cgi"],
        "body": [r"dana-na", r"welcome\.cgi", r"pulse secure", r"ivanti",
                 r"DSIDFormDataStr", r"Neoteris"],
        "title": [r"pulse", r"ivanti", r"connect secure"],
        "headers": {},
        "cookies": [r"DSID", r"DSSignInURL", r"DSLastAccess"],
        "cert": [r"Pulse Secure", r"Ivanti", r"Juniper"],
        "ports": [443],
        "cve": ["CVE-2019-11510 (pre-auth arbitrary file read)",
                "CVE-2021-22893 (pre-auth RCE)",
                "CVE-2023-46805 + CVE-2024-21887 (auth bypass + command injection chain)",
                "CVE-2025-0282 (pre-auth stack overflow RCE)"],
    },
    {
        "name": "Citrix Gateway / NetScaler (ADC)",
        "vendor": "Citrix",
        "paths": ["/vpn/index.html", "/logon/LogonPoint/tmindex.html",
                  "/vpn/tmindex.html", "/citrix/"],
        "body": [r"citrix", r"netscaler", r"_ctxs", r"vpn/js/gateway",
                 r"nsg-x1", r"logonpoint"],
        "title": [r"citrix", r"netscaler", r"gateway"],
        "headers": {"via": [r"NS-CACHE"]},
        "cookies": [r"NSC_", r"NSC_AAAC", r"citrix_ns_id", r"pwcount"],
        "cert": [r"Citrix", r"NetScaler"],
        "ports": [443],
        "cve": ["CVE-2019-19781 (path traversal RCE 'Shitrix')",
                "CVE-2023-3519 (pre-auth RCE)",
                "CVE-2023-4966 'Citrix Bleed' (session token disclosure)"],
    },
    {
        "name": "SonicWall SSL-VPN (SMA / NSA)",
        "vendor": "SonicWall",
        "paths": ["/cgi-bin/welcome", "/auth.html", "/sslvpn",
                  "/__api__/v1/logon"],
        "body": [r"sonicwall", r"netextender", r"mobile connect",
                 r"virtualassist", r"SonicWALL SSL-VPN"],
        "title": [r"sonicwall", r"virtual office"],
        "headers": {"server": [r"SonicWALL"]},
        "cookies": [r"swap", r"EPCVersion"],
        "cert": [r"SonicWALL", r"SonicWall"],
        "ports": [443, 4433],
        "cve": ["CVE-2021-20016 (SQLi -> credential access)",
                "CVE-2021-20038 (SMA100 pre-auth RCE)",
                "CVE-2024-40766 (improper access control)"],
    },
    {
        "name": "F5 BIG-IP APM (Access Policy Manager)",
        "vendor": "F5",
        "paths": ["/my.policy", "/vdesk/hangup.php3", "/tmui/login.jsp"],
        "body": [r"my\.policy", r"F5 Networks", r"BIG-?IP", r"APM",
                 r"vdesk", r"maximum number of concurrent"],
        "title": [r"big-?ip", r"f5"],
        "headers": {"server": [r"BigIP", r"BIG-IP"]},
        "cookies": [r"MRHSession", r"LastMRH_Session", r"F5_ST",
                    r"BIGipServer", r"TIN", r"F5_fullWT"],
        "cert": [r"F5 Networks", r"BIG-?IP"],
        "ports": [443],
        "cve": ["CVE-2020-5902 (TMUI pre-auth RCE)",
                "CVE-2022-1388 (iControl REST auth bypass RCE)",
                "CVE-2023-46747 (config utility auth bypass RCE)"],
    },
    {
        "name": "Check Point Mobile Access / Connectra",
        "vendor": "Check Point",
        "paths": ["/sslvpn/Login/Login", "/Login/Login", "/sslvpn/Portal/Main"],
        "body": [r"check point", r"mobile access", r"connectra",
                 r"cvpn", r"Login/Login"],
        "title": [r"check point", r"mobile access"],
        "headers": {"server": [r"Check Point"]},
        "cookies": [r"CPCVPN", r"selfServiceUserId"],
        "cert": [r"Check Point", r"checkpoint"],
        "ports": [443],
        "cve": ["CVE-2024-24919 (pre-auth information / arbitrary file read)"],
    },
    {
        "name": "Sophos Firewall / UTM User Portal",
        "vendor": "Sophos",
        "paths": ["/userportal/webpages/myaccount/login.jsp", "/userportal/",
                  "/webconsole/webpages/login.jsp"],
        "body": [r"sophos", r"user portal", r"userportal", r"myaccount"],
        "title": [r"sophos", r"user portal"],
        "headers": {},
        "cookies": [r"JSESSIONID"],
        "cert": [r"Sophos"],
        "ports": [443, 4443],
        "cve": ["CVE-2020-12271 (SQLi, asset compromise)",
                "CVE-2022-1040 (auth bypass RCE)",
                "CVE-2022-3236 (code injection RCE)"],
    },
    {
        "name": "WatchGuard Firebox SSL-VPN",
        "vendor": "WatchGuard",
        "paths": ["/", "/sslvpn.html", "/auth/login"],
        "body": [r"watchguard", r"firebox", r"authpoint", r"sslvpn_logon"],
        "title": [r"watchguard", r"firebox"],
        "headers": {},
        "cookies": [],
        "cert": [r"WatchGuard", r"Firebox"],
        "ports": [443, 4100],
        "cve": ["CVE-2022-26318 (pre-auth RCE)",
                "CVE-2022-31789 (authentication bypass)"],
    },
    {
        "name": "Barracuda SSL VPN",
        "vendor": "Barracuda",
        "paths": ["/default/showLogin.do", "/"],
        "body": [r"barracuda", r"showLogin", r"ssl vpn"],
        "title": [r"barracuda"],
        "headers": {},
        "cookies": [],
        "cert": [r"Barracuda"],
        "ports": [443],
        "cve": ["CVE-2023-2868 (ESG command injection, actively exploited)"],
    },
    {
        "name": "OpenVPN Access Server",
        "vendor": "OpenVPN",
        "paths": ["/", "/__session_start__/", "/admin/"],
        "body": [r"openvpn", r"OpenVPN Access Server", r"pyovpn",
                 r"Connect to Access Server"],
        "title": [r"openvpn"],
        "headers": {"server": [r"OpenVPN-AS"]},
        "cookies": [r"openvpn_sess"],
        "cert": [r"OpenVPN"],
        "ports": [443, 943],
        "cve": [],
    },
    {
        "name": "Array Networks AG / SSL-VPN",
        "vendor": "Array Networks",
        "paths": ["/prx/000/http/localhost/login", "/"],
        "body": [r"array networks", r"arraynetworks", r"ag series", r"an_util"],
        "title": [r"array networks"],
        "headers": {},
        "cookies": [],
        "cert": [r"Array Networks"],
        "ports": [443],
        "cve": ["CVE-2023-28461 (pre-auth RCE, actively exploited)"],
    },
    {
        "name": "Microsoft RD Web / RD Gateway",
        "vendor": "Microsoft",
        "paths": ["/RDWeb/Pages/en-US/login.aspx", "/RDWeb/", "/rpc/"],
        "body": [r"rd web access", r"rdweb", r"remote desktop",
                 r"work resources", r"RDGClientPort"],
        "title": [r"remote desktop", r"rd web access", r"work resources"],
        "headers": {"server": [r"Microsoft-IIS"]},
        "cookies": [r"TSWAAuthCookie"],
        "cert": [],
        "ports": [443, 3389],
        "cve": ["CVE-2020-0609 / CVE-2020-0610 (RD Gateway pre-auth RCE)"],
    },
]

# Pre-compile all regexes for speed.
for _fp in VPN_FINGERPRINTS:
    _fp["_body"] = [re.compile(p, re.I) for p in _fp.get("body", [])]
    _fp["_title"] = [re.compile(p, re.I) for p in _fp.get("title", [])]
    _fp["_cookies"] = [re.compile(p, re.I) for p in _fp.get("cookies", [])]
    _fp["_cert"] = [re.compile(p, re.I) for p in _fp.get("cert", [])]
    _fp["_headers"] = {h: [re.compile(p, re.I) for p in pats]
                       for h, pats in _fp.get("headers", {}).items()}

# Hostname keywords hinting at VPN/remote access, used for prioritisation.
_HOSTNAME_HINT = re.compile(
    r"(vpn|sslvpn|webvpn|remote|access|portal|gateway|gw|connect|anyconnect|"
    r"globalprotect|forti|pulse|ivanti|citrix|netscaler|sonicwall|"
    r"secure|extranet|dialin|telework|rdweb|rdgateway|ztna)", re.I)


def hostname_looks_like_vpn(host):
    return bool(_HOSTNAME_HINT.search(host))


# --------------------------------------------------------------------------- #
#  HTTP session
# --------------------------------------------------------------------------- #
def build_session():
    s = requests.Session()
    s.headers.update({"User-Agent": DEFAULT_USER_AGENT,
                      "Accept": "*/*", "Connection": "close"})
    if Retry is not None:
        retry = Retry(total=1, backoff_factor=0.3,
                      status_forcelist=(502, 503, 504))
        adapter = HTTPAdapter(max_retries=retry, pool_connections=50,
                              pool_maxsize=50)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
    return s


# --------------------------------------------------------------------------- #
#  Passive subdomain enumeration (multiple free, key-less sources)
# --------------------------------------------------------------------------- #
def _clean_subs(names, target_domain):
    out = set()
    suffix = "." + target_domain
    for n in names:
        if not n:
            continue
        n = n.strip().lower().lstrip("*.")
        n = n.split("@")[-1]  # strip emails sometimes present in cert data
        if n == target_domain or n.endswith(suffix):
            if re.match(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)+$", n):
                out.add(n)
    return out


def source_crtsh(session, domain):
    r = session.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30)
    r.raise_for_status()
    data = r.json()
    names = []
    for entry in data:
        val = entry.get("name_value", "") or ""
        names.extend(val.split("\n"))
        cn = entry.get("common_name")
        if cn:
            names.append(cn)
    return names


def source_certspotter(session, domain):
    url = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
           f"&include_subdomains=true&expand=dns_names")
    r = session.get(url, timeout=30)
    r.raise_for_status()
    names = []
    for entry in r.json():
        names.extend(entry.get("dns_names", []))
    return names


def source_hackertarget(session, domain):
    r = session.get(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                    timeout=30)
    r.raise_for_status()
    if "API count exceeded" in r.text or "error" in r.text.lower():
        return []
    return [line.split(",")[0] for line in r.text.splitlines() if "," in line]


def source_rapiddns(session, domain):
    r = session.get(f"https://rapiddns.io/subdomain/{domain}?full=1",
                    timeout=30)
    r.raise_for_status()
    return re.findall(r"<td>([a-zA-Z0-9_.-]+\." + re.escape(domain) + r")</td>",
                      r.text)


def source_alienvault(session, domain):
    url = (f"https://otx.alienvault.com/api/v1/indicators/domain/"
           f"{domain}/passive_dns")
    r = session.get(url, timeout=30)
    r.raise_for_status()
    return [rec.get("hostname", "") for rec in r.json().get("passive_dns", [])]


def source_anubis(session, domain):
    r = session.get(f"https://jldc.me/anubis/subdomains/{domain}", timeout=30)
    r.raise_for_status()
    return r.json()


def source_wayback(session, domain):
    url = (f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
           f"&output=text&fl=original&collapse=urlkey&limit=5000")
    r = session.get(url, timeout=30)
    r.raise_for_status()
    hosts = []
    for line in r.text.splitlines():
        m = re.search(r"https?://([a-zA-Z0-9_.-]+)", line)
        if m:
            hosts.append(m.group(1).split(":")[0])
    return hosts


PASSIVE_SOURCES = [
    ("crt.sh", source_crtsh),
    ("certspotter", source_certspotter),
    ("hackertarget", source_hackertarget),
    ("rapiddns", source_rapiddns),
    ("alienvault-otx", source_alienvault),
    ("anubis", source_anubis),
    ("wayback", source_wayback),
]


def passive_enumeration(session, domain, threads):
    info(f"Passive enumeration across {len(PASSIVE_SOURCES)} sources for "
         f"{C.CYAN}{domain}{C.ENDC}")
    found = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(PASSIVE_SOURCES)) as ex:
        fut_map = {ex.submit(fn, session, domain): name
                   for name, fn in PASSIVE_SOURCES}
        for fut in concurrent.futures.as_completed(fut_map):
            name = fut_map[fut]
            try:
                subs = _clean_subs(fut.result(), domain)
                if subs:
                    good(f"{name}: {C.BOLD}{len(subs)}{C.ENDC} subdomains")
                    found |= subs
                else:
                    info(f"{name}: no results")
            except Exception as e:
                warn(f"{name} failed: {C.DIM}{e}{C.ENDC}")
    return found


# --------------------------------------------------------------------------- #
#  Active DNS brute-force (native - no ffuf dependency)
# --------------------------------------------------------------------------- #
def resolve_host(host):
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({i[4][0] for i in infos})
        return ips or None
    except socket.gaierror:
        return None
    except Exception:
        return None


def dns_bruteforce(domain, wordlist, threads):
    info(f"DNS brute-force with {C.BOLD}{len(wordlist)}{C.ENDC} candidates "
         f"({C.BOLD}{threads}{C.ENDC} threads)")
    candidates = [f"{w}.{domain}" for w in wordlist]
    resolved = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        fut_map = {ex.submit(resolve_host, c): c for c in candidates}
        for fut in concurrent.futures.as_completed(fut_map):
            host = fut_map[fut]
            ips = fut.result()
            if ips:
                resolved[host] = ips
                good(f"DNS: {C.GREEN}{host}{C.ENDC} -> {C.CYAN}{', '.join(ips)}{C.ENDC}")
    return resolved


# --------------------------------------------------------------------------- #
#  Optional ffuf integration (HTTP fuzzing) for users who want it
# --------------------------------------------------------------------------- #
def fuzz_with_ffuf(domain, wordlist_path, extra_opts, ffuf_bin="ffuf"):
    if shutil.which(ffuf_bin) is None:
        warn("ffuf not found in PATH; skipping HTTP fuzzing.")
        return set()
    info("Running ffuf HTTP fuzzing (optional module)...")
    out_file = os.path.join(
        os.getenv("TMPDIR", "/tmp"),
        f"vpnfinder_ffuf_{domain.replace('.', '_')}_{os.getpid()}.json")
    found = set()
    for scheme in ("https", "http"):
        cmd = (f'ffuf -w {wordlist_path} -u {scheme}://FUZZ.{domain} '
               f'-mc 200,204,301,302,307,401,403,500 -fs 0 '
               f'-o {out_file} -of json --silent {extra_opts}')
        try:
            subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=1800)
        except subprocess.TimeoutExpired:
            warn(f"ffuf {scheme} timed out.")
            continue
        except Exception as e:
            warn(f"ffuf {scheme} error: {e}")
            continue
        if os.path.exists(out_file):
            try:
                with open(out_file) as f:
                    data = json.load(f)
                for res in data.get("results", []):
                    host = (res.get("host") or "").lower()
                    if host.endswith("." + domain):
                        found.add(host)
            except Exception:
                pass
            finally:
                try:
                    os.remove(out_file)
                except OSError:
                    pass
    return found


# --------------------------------------------------------------------------- #
#  TLS certificate inspection
# --------------------------------------------------------------------------- #
def grab_tls_cert(host, port, timeout):
    """Return dict with cert text + parsed fields, or None."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")  # tolerate legacy appliance ciphers
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                tls_version = ssock.version()
    except Exception:
        return None
    if not der:
        return None

    result = {"raw": der.decode("latin-1", "ignore"), "tls_version": tls_version,
              "subject_cn": None, "issuer": None, "sans": []}
    if _HAS_CRYPTO:
        try:
            cert = x509.load_der_x509_certificate(der, default_backend())
            try:
                cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                result["subject_cn"] = cn[0].value if cn else None
            except Exception:
                pass
            try:
                result["issuer"] = cert.issuer.rfc4514_string()
            except Exception:
                pass
            try:
                ext = cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                result["sans"] = ext.value.get_values_for_type(x509.DNSName)
            except Exception:
                pass
        except Exception:
            pass
    return result


# --------------------------------------------------------------------------- #
#  Native TCP port scan
# --------------------------------------------------------------------------- #
def tcp_connect_scan(ip, ports, timeout=2.0, threads=100):
    open_ports = []
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET

    def probe(port):
        try:
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    return port
        except Exception:
            return None
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(threads, len(ports) or 1)) as ex:
        for res in ex.map(probe, ports):
            if res:
                open_ports.append(res)
    return sorted(open_ports)


def nmap_service_scan(ip, ports):
    """Optional deep scan with nmap -sV for banner/version enrichment."""
    if shutil.which("nmap") is None or not ports:
        return {}
    port_str = ",".join(map(str, ports))
    cmd = f"nmap -sV -Pn -T4 --open -p {port_str} {ip} -oG -"
    services = {}
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True,
                              text=True, timeout=600)
    except Exception:
        return {}
    for line in proc.stdout.splitlines():
        if "Ports:" not in line:
            continue
        seg = line.split("Ports:")[1].split("\t")[0]
        for entry in seg.split(","):
            parts = entry.strip().split("/")
            if len(parts) >= 7 and parts[1] == "open":
                try:
                    services[int(parts[0])] = {
                        "service": parts[4] or "unknown",
                        "version": parts[6] or "",
                    }
                except ValueError:
                    continue
    return services


# =========================================================================== #
#  CDN detection & origin-IP discovery engine
#
#  When a target hides its real infrastructure behind a CDN/WAF (Cloudflare,
#  CloudFront, Akamai, Fastly, Imperva, Sucuri, ...), the edge IP tells you
#  nothing. This engine works to recover the true origin IP address by every
#  passive/active means available:
#    * a built-in keyless DNS client (A/AAAA/CNAME/MX/TXT/NS)
#    * Team Cymru IP->ASN mapping (keyless) to label and cluster IPs
#    * non-proxied subdomain harvesting (mail/dev/direct/origin leaks)
#    * historical / passive DNS records that predate the CDN
#    * MX and SPF mail infrastructure (often on the origin network)
#    * TLS-certificate and favicon pivoting via Shodan/Censys (if keys set)
#    * direct origin verification (Host-header + SNI request, content/cert match)
#    * optional ASN/netblock sweeping around confirmed origins
# =========================================================================== #

# --- Minimal keyless DNS client (UDP) ------------------------------------- #
_DNS_QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15,
               "TXT": 16, "AAAA": 28}
DNS_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


def _dns_encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        label = label.encode("idna") if any(ord(c) > 127 for c in label) \
            else label.encode("latin-1")
        out += bytes([len(label)]) + label
    return out + b"\x00"


def _dns_parse_name(data, offset):
    labels = []
    jumped = False
    start_after = offset
    for _ in range(128):  # bound the loop against malformed packets
        length = data[offset]
        if length & 0xC0 == 0xC0:
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                start_after = offset + 2
            offset = pointer
            jumped = True
            continue
        if length == 0:
            offset += 1
            break
        labels.append(data[offset + 1:offset + 1 + length].decode("latin-1"))
        offset += 1 + length
    return ".".join(labels), (start_after if jumped else offset)


def _dns_tcp_query(resolver, packet, timeout):
    """Fallback for truncated responses: DNS over TCP (2-byte length prefix)."""
    try:
        with socket.create_connection((resolver, 53), timeout=timeout) as s:
            s.sendall(struct.pack(">H", len(packet)) + packet)
            hdr = b""
            while len(hdr) < 2:
                chunk = s.recv(2 - len(hdr))
                if not chunk:
                    return None
                hdr += chunk
            need = struct.unpack(">H", hdr)[0]
            data = b""
            while len(data) < need:
                chunk = s.recv(need - len(data))
                if not chunk:
                    break
                data += chunk
            return data
    except Exception:
        return None


# DNS-over-HTTPS endpoints (JSON API). Used when UDP is blocked/truncated and
# TCP/53 is unavailable - works anywhere outbound HTTPS is allowed.
_DOH_ENDPOINTS = ["https://dns.google/resolve",
                  "https://cloudflare-dns.com/dns-query"]


def _doh_query(name, qtype):
    for url in _DOH_ENDPOINTS:
        try:
            r = requests.get(url, params={"name": name, "type": qtype},
                             headers={"Accept": "application/dns-json"},
                             timeout=8)
            if r.status_code != 200:
                continue
            answers = r.json().get("Answer", [])
        except Exception:
            continue
        results = []
        for ans in answers:
            atype = ans.get("type")
            data = (ans.get("data") or "").strip()
            if atype == 1:
                results.append(data)
            elif atype == 28:
                results.append(data)
            elif atype in (5, 2, 12):  # CNAME / NS / PTR
                results.append(data.rstrip(".").lower())
            elif atype == 15:  # MX: "10 smtp.example.com."
                parts = data.split(None, 1)
                if len(parts) == 2 and parts[0].isdigit():
                    results.append((int(parts[0]), parts[1].rstrip(".").lower()))
            elif atype == 16:  # TXT (quoted, possibly concatenated)
                results.append(data.strip('"').replace('" "', ""))
        if results:
            return results
    return []


@functools.lru_cache(maxsize=4096)
def dns_query(name, qtype="A", timeout=4.0):
    """Resolve a DNS record with the built-in client. Returns a list.

    Uses UDP first and transparently retries over TCP when the response is
    truncated (TC bit) - important for large TXT/SPF records."""
    qt = _DNS_QTYPES.get(qtype.upper())
    if qt is None:
        return []
    tid = random.randint(0, 0xFFFF)
    packet = (struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
              + _dns_encode_name(name) + struct.pack(">HH", qt, 1))
    data = None
    used_resolver = None
    for resolver in DNS_RESOLVERS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(packet, (resolver, 53))
            data, _ = s.recvfrom(4096)
            s.close()
            used_resolver = resolver
            break
        except Exception:
            try:
                s.close()
            except Exception:
                pass
            continue
    if not data or len(data) < 12:
        return _doh_query(name, qtype.upper())
    rtid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    if rtid != tid:
        return _doh_query(name, qtype.upper())
    if flags & 0x0200:  # TC (truncated): try TCP, then DoH over HTTPS
        tcp_data = _dns_tcp_query(used_resolver, packet, timeout) \
            if used_resolver else None
        if tcp_data and len(tcp_data) >= 12:
            data = tcp_data
            rtid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
            if rtid != tid:
                return []
        else:
            doh = _doh_query(name, qtype.upper())
            if doh:
                return doh
    offset = 12
    for _ in range(qd):
        _, offset = _dns_parse_name(data, offset)
        offset += 4
    results = []
    try:
        for _ in range(an):
            _, offset = _dns_parse_name(data, offset)
            rtype, _rclass, _ttl, rdlength = struct.unpack(
                ">HHIH", data[offset:offset + 10])
            offset += 10
            rdata = data[offset:offset + rdlength]
            if rtype == 1 and rdlength == 4:
                results.append(socket.inet_ntoa(rdata))
            elif rtype == 28 and rdlength == 16:
                results.append(socket.inet_ntop(socket.AF_INET6, rdata))
            elif rtype in (5, 2, 12):  # CNAME / NS / PTR
                nm, _ = _dns_parse_name(data, offset)
                results.append(nm.lower())
            elif rtype == 15:  # MX
                pref = struct.unpack(">H", rdata[:2])[0]
                nm, _ = _dns_parse_name(data, offset + 2)
                results.append((pref, nm.lower()))
            elif rtype == 16:  # TXT
                txt, i = [], 0
                while i < rdlength:
                    ln = rdata[i]
                    txt.append(rdata[i + 1:i + 1 + ln].decode("latin-1"))
                    i += 1 + ln
                results.append("".join(txt))
            offset += rdlength
    except Exception:
        pass
    return results


def cname_chain(host, max_depth=8):
    """Follow the CNAME chain for a host, returning all intermediate names."""
    chain, current, seen = [], host, set()
    for _ in range(max_depth):
        if current in seen:
            break
        seen.add(current)
        cnames = [r for r in dns_query(current, "CNAME") if isinstance(r, str)]
        if not cnames:
            break
        current = cnames[0]
        chain.append(current)
    return chain


# --- Team Cymru IP -> ASN (keyless) --------------------------------------- #
@functools.lru_cache(maxsize=4096)
def ip_to_asn(ip):
    """Map an IPv4/IPv6 address to its ASN, CIDR and org via Team Cymru DNS."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version == 4:
        rev = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    else:
        nibbles = "".join(reversed(addr.exploded.replace(":", "")))
        rev = ".".join(nibbles) + ".origin6.asn.cymru.com"
    txt = [t for t in dns_query(rev, "TXT") if isinstance(t, str)]
    if not txt:
        return None
    parts = [p.strip() for p in txt[0].split("|")]
    if not parts or not parts[0]:
        return None
    asn = parts[0].split()[0]
    info = {"asn": asn, "cidr": parts[1] if len(parts) > 1 else "",
            "cc": parts[2] if len(parts) > 2 else "", "org": ""}
    name_txt = [t for t in dns_query(f"AS{asn}.asn.cymru.com", "TXT")
                if isinstance(t, str)]
    if name_txt:
        info["org"] = name_txt[0].split("|")[-1].strip()
    return info


# --- CDN / WAF fingerprints ----------------------------------------------- #
CDN_CNAME_SIGNS = {
    "cloudflare": "Cloudflare", "cloudflare.net": "Cloudflare",
    "cloudfront.net": "Amazon CloudFront", "awsdns": "AWS",
    "akamai": "Akamai", "akamaiedge.net": "Akamai", "akamaized.net": "Akamai",
    "edgekey.net": "Akamai", "edgesuite.net": "Akamai",
    "fastly.net": "Fastly", "fastlylb.net": "Fastly",
    "azureedge.net": "Azure CDN", "azurefd.net": "Azure Front Door",
    "trafficmanager.net": "Azure", "incapdns.net": "Imperva Incapsula",
    "impervadns.net": "Imperva", "sucuri.net": "Sucuri",
    "edgecastcdn.net": "Edgecast", "stackpathdns.com": "StackPath",
    "stackpathcdn.com": "StackPath", "cdn77.org": "CDN77",
    "b-cdn.net": "BunnyCDN", "googlehosted.com": "Google",
    "ghs.googlehosted.com": "Google", "cachefly.net": "CacheFly",
    "kxcdn.com": "KeyCDN", "footprint.net": "CenturyLink", "llnwd.net": "Limelight",
}
CDN_HEADER_SIGNS = [
    ("server", r"cloudflare", "Cloudflare"),
    ("cf-ray", r".", "Cloudflare"),
    ("server", r"cloudfront", "Amazon CloudFront"),
    ("x-amz-cf-id", r".", "Amazon CloudFront"),
    ("server", r"AkamaiGHost|AkamaiNetStorage", "Akamai"),
    ("x-akamai-transformed", r".", "Akamai"),
    ("server", r"^ECS|^ECAcc|Fastly", "Fastly"),
    ("x-served-by", r"cache-", "Fastly"),
    ("x-fastly-request-id", r".", "Fastly"),
    ("x-sucuri-id", r".", "Sucuri"),
    ("x-cdn", r"Incapsula|Imperva", "Imperva Incapsula"),
    ("x-iinfo", r".", "Imperva Incapsula"),
    ("x-cache", r"cloudfront", "Amazon CloudFront"),
    ("server", r"StackPath", "StackPath"),
    ("x-hw", r".", "StackPath"),
    ("server", r"BunnyCDN", "BunnyCDN"),
]
_CDN_HEADER_RE = [(h, re.compile(p, re.I), name) for h, p, name in CDN_HEADER_SIGNS]
# ASN org substrings that indicate CDN/WAF/edge networks (not real origins).
CDN_ASN_KEYWORDS = {
    "cloudflare": "Cloudflare", "amazon": "AWS/CloudFront",
    "akamai": "Akamai", "fastly": "Fastly", "incapsula": "Imperva Incapsula",
    "imperva": "Imperva", "sucuri": "Sucuri", "google": "Google",
    "microsoft": "Azure", "azure": "Azure", "stackpath": "StackPath",
    "highwinds": "StackPath", "edgecast": "Edgecast", "verizon": "Edgecast",
    "limelight": "Limelight", "cdn77": "CDN77", "bunny": "BunnyCDN",
    "cloudfront": "Amazon CloudFront", "gcore": "Gcore", "keycdn": "KeyCDN",
    "fdcservers": "CDN", "quantil": "Quantil", "cachefly": "CacheFly",
}


def cdn_from_asn(asn_info):
    if not asn_info:
        return None
    org = (asn_info.get("org") or "").lower()
    for kw, name in CDN_ASN_KEYWORDS.items():
        if kw in org:
            return name
    return None


def detect_cdn(host, ips, response_headers=None):
    """Return the CDN/WAF name fronting a host, or None. Uses CNAME chain,
    response headers, and ASN of the resolved IPs."""
    for cn in cname_chain(host):
        for sign, name in CDN_CNAME_SIGNS.items():
            if sign in cn:
                return name
    if response_headers:
        for hdr, rx, name in _CDN_HEADER_RE:
            val = response_headers.get(hdr, "")
            if val and rx.search(val):
                return name
    for ip in ips:
        cdn = cdn_from_asn(ip_to_asn(ip))
        if cdn:
            return cdn
    return None


def is_cdn_ip(ip):
    return cdn_from_asn(ip_to_asn(ip)) is not None


# --- Direct origin verification ------------------------------------------- #
def _page_signature(body):
    m = _TITLE_RE.search(body)
    title = (m.group(1).strip() if m else "")[:120]
    norm = re.sub(r"\s+", " ", body).strip().lower()
    return {"title": title, "length": len(body),
            "hash": hashlib.sha256(norm.encode("utf-8", "ignore")).hexdigest()}


def direct_request(ip, host, port=443, path="/", timeout=6.0):
    """Connect straight to an IP, presenting `host` via SNI and Host header.
    This is how a candidate origin is tested behind a CDN."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except Exception:
        pass
    result = {"status": None, "headers": {}, "body": "", "cert_sha256": None,
              "cert_raw": ""}
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except Exception:
        return None
    try:
        ss = ctx.wrap_socket(raw, server_hostname=host)
    except Exception:
        try:
            raw.close()
        except Exception:
            pass
        return None
    try:
        der = ss.getpeercert(binary_form=True)
        if der:
            result["cert_sha256"] = hashlib.sha256(der).hexdigest()
            result["cert_raw"] = der.decode("latin-1", "ignore")
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
               f"User-Agent: {DEFAULT_USER_AGENT}\r\n"
               f"Accept: */*\r\nAccept-Encoding: identity\r\n"
               f"Connection: close\r\n\r\n")
        ss.sendall(req.encode("latin-1"))
        buf = b""
        while len(buf) < 262144:
            chunk = ss.recv(8192)
            if not chunk:
                break
            buf += chunk
    except Exception:
        buf = b""
    finally:
        try:
            ss.close()
        except Exception:
            pass
    head, _, body = buf.partition(b"\r\n\r\n")
    hlines = head.decode("latin-1", "ignore").split("\r\n")
    if hlines and hlines[0].startswith("HTTP"):
        parts = hlines[0].split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            result["status"] = int(parts[1])
    for line in hlines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            result["headers"][k.strip().lower()] = v.strip()
    if "chunked" in result["headers"].get("transfer-encoding", "").lower():
        body = _dechunk(body)
    result["body"] = body.decode("utf-8", "ignore")
    return result


def _dechunk(data):
    """Decode an HTTP/1.1 chunked transfer-encoded body."""
    out, i, n = b"", 0, len(data)
    try:
        while i < n:
            j = data.find(b"\r\n", i)
            if j == -1:
                break
            size = int(data[i:j].split(b";")[0], 16)
            if size == 0:
                break
            start = j + 2
            out += data[start:start + size]
            i = start + size + 2
    except Exception:
        return data
    return out


def verify_origin(ip, host, reference, timeout):
    """Score whether `ip` is the true origin for `host`. Returns
    (verified: bool, score: int, reasons: list)."""
    resp = direct_request(ip, host, 443, "/", timeout)
    if resp is None:
        return False, 0, ["no HTTPS response"]
    score, reasons = 0, []

    if resp["cert_sha256"] and resp["cert_sha256"] == reference.get("cert_sha256"):
        score += 60
        reasons.append("TLS certificate is identical to the edge")
    # Cert covers the target domain (origin commonly serves the real cert).
    apex = reference.get("domain", host)
    if resp["cert_raw"] and (host in resp["cert_raw"] or apex in resp["cert_raw"]):
        score += 40
        reasons.append("origin certificate covers the target domain")

    ref_sig = reference.get("signature")
    if ref_sig and resp["body"]:
        sig = _page_signature(resp["body"])
        if sig["hash"] == ref_sig["hash"]:
            score += 60
            reasons.append("served page is byte-identical to the CDN response")
        elif ref_sig["title"] and sig["title"] == ref_sig["title"]:
            score += 45
            reasons.append(f"page title matches ('{sig['title'][:40]}')")
        elif (ref_sig["length"] and sig["length"] and
              abs(sig["length"] - ref_sig["length"]) / max(ref_sig["length"], 1) < 0.15):
            score += 20
            reasons.append("response body size closely matches")

    marker = reference.get("marker")
    if marker and marker in resp["body"]:
        score += 35
        reasons.append("origin response contains a unique target marker")

    return (score >= 50), min(score, 100), reasons


def build_origin_reference(session, host, domain, timeout):
    """Fetch the CDN-fronted response and derive a fingerprint used to confirm
    candidate origins."""
    ref = {"domain": domain, "cert_sha256": None, "signature": None,
           "marker": None}
    try:
        r = session.get(f"https://{host}/", timeout=timeout, verify=False)
        ref["signature"] = _page_signature(r.text)
        # A stable, target-specific marker: canonical/og:url/domain mentions.
        m = re.search(r'(?:canonical|og:url)["\']?[^"\']*["\']([^"\']*'
                      + re.escape(domain) + r'[^"\']*)', r.text, re.I)
        if m:
            ref["marker"] = m.group(1)[:80]
    except Exception:
        pass
    # Real edge cert fingerprint for exact-match comparison.
    edge = direct_request(_first_ip(host) or host, host, 443, "/", timeout)
    if edge and edge.get("cert_sha256"):
        ref["cert_sha256"] = edge["cert_sha256"]
    return ref


def _first_ip(host):
    ips = resolve_host(host)
    return ips[0] if ips else None


# --- Favicon hashing (Shodan-compatible murmur3) -------------------------- #
def _murmur3_32(data, seed=0):
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed
    rounded = length & 0xFFFFFFFC
    for i in range(0, rounded, 4):
        k1 = (data[i] | (data[i + 1] << 8) | (data[i + 2] << 16)
              | (data[i + 3] << 24)) & 0xFFFFFFFF
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    k1 = 0
    tail = length & 3
    if tail == 3:
        k1 ^= data[rounded + 2] << 16
    if tail >= 2:
        k1 ^= data[rounded + 1] << 8
    if tail >= 1:
        k1 ^= data[rounded]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def favicon_hash(session, base_url, timeout):
    try:
        r = session.get(base_url + "/favicon.ico", timeout=timeout, verify=False)
        if r.status_code != 200 or not r.content:
            return None
        return _murmur3_32(base64.encodebytes(r.content))
    except Exception:
        return None


# --- Optional external intel sources (activated by env API keys) ---------- #
def shodan_search(session, query, timeout=25):
    key = os.getenv("SHODAN_API_KEY")
    if not key:
        return []
    try:
        r = session.get("https://api.shodan.io/shodan/host/search",
                        params={"key": key, "query": query}, timeout=timeout)
        if r.status_code != 200:
            return []
        return [m["ip_str"] for m in r.json().get("matches", []) if m.get("ip_str")]
    except Exception:
        return []


def censys_search(session, domain, timeout=25):
    cid = os.getenv("CENSYS_API_ID")
    secret = os.getenv("CENSYS_API_SECRET")
    if not (cid and secret):
        return []
    try:
        r = session.post(
            "https://search.censys.io/api/v2/hosts/search",
            auth=(cid, secret), timeout=timeout,
            json={"q": f"services.tls.certificates.leaf_data.names: {domain}",
                  "per_page": 50})
        if r.status_code != 200:
            return []
        hits = r.json().get("result", {}).get("hits", [])
        return [h["ip"] for h in hits if h.get("ip")]
    except Exception:
        return []


def securitytrails_history(session, domain, timeout=25):
    key = os.getenv("SECURITYTRAILS_API_KEY")
    if not key:
        return []
    ips = []
    try:
        r = session.get(
            f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
            headers={"APIKEY": key}, timeout=timeout)
        if r.status_code == 200:
            for rec in r.json().get("records", []):
                for v in rec.get("values", []):
                    if v.get("ip"):
                        ips.append(v["ip"])
    except Exception:
        pass
    return ips


# --- Historical / passive DNS (keyless) ----------------------------------- #
def passive_historical_ips(session, domain, timeout=25):
    ips = set()
    # AlienVault OTX passive DNS - includes historical A records.
    try:
        r = session.get(f"https://otx.alienvault.com/api/v1/indicators/"
                        f"domain/{domain}/passive_dns", timeout=timeout)
        if r.status_code == 200:
            for rec in r.json().get("passive_dns", []):
                addr = rec.get("address", "")
                if addr and _is_ipv4(addr):
                    ips.add(addr)
    except Exception:
        pass
    # HackerTarget reverse/host records.
    try:
        r = session.get(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                        timeout=timeout)
        if r.status_code == 200 and "error" not in r.text.lower():
            for line in r.text.splitlines():
                if "," in line:
                    ip = line.split(",", 1)[1].strip()
                    if _is_ipv4(ip):
                        ips.add(ip)
    except Exception:
        pass
    return ips


def _is_ipv4(value):
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


def mail_infra_ips(domain):
    """MX hosts and SPF ip4 blocks - mail servers frequently live on the
    origin network, outside the CDN."""
    ips = set()
    for pref, mx in [r for r in dns_query(domain, "MX") if isinstance(r, tuple)]:
        for ip in dns_query(mx.rstrip("."), "A"):
            if isinstance(ip, str) and _is_ipv4(ip):
                ips.add(ip)
    for txt in [t for t in dns_query(domain, "TXT") if isinstance(t, str)]:
        if "v=spf1" in txt.lower():
            for tok in txt.split():
                if tok.startswith("ip4:"):
                    net = tok[4:]
                    try:
                        network = ipaddress.ip_network(net, strict=False)
                        if network.num_addresses <= 256:
                            ips.update(str(h) for h in network.hosts())
                        else:
                            ips.add(str(network.network_address))
                    except ValueError:
                        pass
                elif tok.startswith("include:") or tok.startswith("a:"):
                    hostpart = tok.split(":", 1)[1]
                    for ip in dns_query(hostpart, "A"):
                        if isinstance(ip, str) and _is_ipv4(ip):
                            ips.add(ip)
    return ips


def gather_origin_candidates(session, domain, resolved, args):
    """Assemble candidate origin IPs (with their discovery method) from every
    available source, excluding known-CDN addresses."""
    candidates = {}  # ip -> set(methods)

    def add(ip, method):
        if _is_ipv4(ip) and not _is_private(ip):
            candidates.setdefault(ip, set()).add(method)

    # 1. Non-proxied subdomains already resolved.
    for host, ips in resolved.items():
        for ip in ips:
            if _is_ipv4(ip) and not is_cdn_ip(ip):
                add(ip, f"non-proxied subdomain ({host})")

    # 2. Historical / passive DNS.
    for ip in passive_historical_ips(session, domain):
        add(ip, "passive/historical DNS")

    # 3. Mail infrastructure (MX / SPF).
    for ip in mail_infra_ips(domain):
        add(ip, "mail infrastructure (MX/SPF)")

    # 4. External intel (only if API keys present).
    for ip in shodan_search(session, f'ssl:"{domain}"'):
        add(ip, "Shodan cert/hostname pivot")
    for ip in censys_search(session, domain):
        add(ip, "Censys certificate pivot")
    for ip in securitytrails_history(session, domain):
        add(ip, "SecurityTrails DNS history")

    # 5. Favicon pivot via Shodan (if key + favicon available).
    fh = favicon_hash(session, f"https://{domain}", args.timeout)
    if fh is not None:
        for ip in shodan_search(session, f"http.favicon.hash:{fh}"):
            add(ip, f"Shodan favicon pivot (hash={fh})")

    # Drop CDN-network candidates that slipped through intel sources.
    for ip in list(candidates):
        if is_cdn_ip(ip):
            del candidates[ip]
    return candidates


def _is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_reserved or a.is_link_local
    except ValueError:
        return True


def asn_sweep_candidates(confirmed_origins, cap=1024):
    """Expand confirmed origins to their surrounding /24 (and the Cymru CIDR
    when small) for an optional netblock sweep."""
    targets = set()
    for ip in confirmed_origins:
        info = ip_to_asn(ip)
        cidr = info.get("cidr") if info else ""
        added = False
        if cidr:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if net.num_addresses <= cap:
                    targets.update(str(h) for h in net.hosts())
                    added = True
            except ValueError:
                pass
        if not added:
            try:
                net = ipaddress.ip_network(ip + "/24", strict=False)
                targets.update(str(h) for h in net.hosts())
            except ValueError:
                pass
    return targets


def origin_discovery(session, domain, targets_hosts, resolved, args):
    """Full origin-IP recovery workflow for CDN-fronted hosts.

    Returns a dict: {host: {"cdn": name, "reference": {...},
                            "origins": [ {ip, verified, score, methods,
                                          reasons, asn} ]}}."""
    findings = {}
    for host in targets_hosts:
        ips = resolved.get(host) or resolve_host(host) or []
        cdn = detect_cdn(host, ips)
        if not cdn and not args.force_origin:
            continue  # not fronted; the resolved IP is already the origin
        info(f"CDN/WAF on {C.CYAN}{host}{C.ENDC}: "
             f"{C.YELLOW}{cdn or 'unknown'}{C.ENDC} - hunting origin IP...")
        reference = build_origin_reference(session, host, domain, args.timeout)
        candidates = gather_origin_candidates(session, domain, resolved, args)
        info(f"  {C.BOLD}{len(candidates)}{C.ENDC} candidate origin IP(s) to verify.")

        origins = []
        workers = max(1, min(args.threads, 20))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            fut = {ex.submit(verify_origin, ip, host, reference, args.timeout): ip
                   for ip in candidates}
            for f in concurrent.futures.as_completed(fut):
                ip = fut[f]
                try:
                    verified, score, reasons = f.result()
                except Exception:
                    continue
                if verified or score >= 20:
                    asn = ip_to_asn(ip)
                    rec = {"ip": ip, "verified": verified, "score": score,
                           "methods": sorted(candidates[ip]), "reasons": reasons,
                           "asn": asn}
                    origins.append(rec)
                    tag = (f"{C.GREEN}CONFIRMED{C.ENDC}" if verified
                           else f"{C.YELLOW}possible{C.ENDC}")
                    org = f" [{asn['asn']} {asn['org'][:30]}]" if asn else ""
                    good(f"  origin {tag}: {C.CYAN}{ip}{C.ENDC}{org} "
                         f"(score {score})")

        # Optional ASN/netblock sweep around confirmed origins.
        confirmed_ips = [o["ip"] for o in origins if o["verified"]]
        if args.asn_sweep and confirmed_ips:
            sweep = asn_sweep_candidates(confirmed_ips, cap=args.sweep_cap)
            sweep -= set(candidates)
            info(f"  ASN sweep: verifying {C.BOLD}{len(sweep)}{C.ENDC} "
                 f"neighbouring IPs...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.threads, 40)) as ex:
                fut = {ex.submit(verify_origin, ip, host, reference, args.timeout): ip
                       for ip in sweep}
                for f in concurrent.futures.as_completed(fut):
                    ip = fut[f]
                    try:
                        verified, score, reasons = f.result()
                    except Exception:
                        continue
                    if verified:
                        asn = ip_to_asn(ip)
                        origins.append({"ip": ip, "verified": True,
                                        "score": score,
                                        "methods": ["ASN/netblock sweep"],
                                        "reasons": reasons, "asn": asn})
                        good(f"  origin {C.GREEN}CONFIRMED (sweep){C.ENDC}: "
                             f"{C.CYAN}{ip}{C.ENDC} (score {score})")

        origins.sort(key=lambda o: (o["verified"], o["score"]), reverse=True)
        findings[host] = {"cdn": cdn, "reference_marker": reference.get("marker"),
                          "origins": origins}
    return findings


# --------------------------------------------------------------------------- #
#  Fingerprint matching engine
# --------------------------------------------------------------------------- #
def _probe_paths_for_fingerprints():
    """Deduplicated list of (path) to request per host."""
    paths = ["/"]
    for fp in VPN_FINGERPRINTS:
        for p in fp["paths"]:
            if p not in paths:
                paths.append(p)
    return paths


_PROBE_PATHS = _probe_paths_for_fingerprints()
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def http_probe(session, base_url, path, timeout):
    try:
        r = session.get(base_url + path, timeout=timeout, verify=False,
                        allow_redirects=True, stream=True)
        body = r.raw.read(65536, decode_content=True).decode("utf-8", "ignore")
        r.close()
        return {"status": r.status_code, "headers": dict(r.headers),
                "cookies": "; ".join(f"{c.name}" for c in r.cookies),
                "set_cookie": r.headers.get("set-cookie", ""),
                "body": body, "url": r.url}
    except Exception:
        return None


def match_fingerprints(responses, cert, host, open_ports):
    """Score every fingerprint against gathered evidence; return best match
    and the list of evidence strings."""
    cert_text = ""
    cert_fields = ""
    if cert:
        cert_text = cert.get("raw", "")
        cert_fields = " ".join(filter(None, [
            cert.get("subject_cn") or "", cert.get("issuer") or "",
            " ".join(cert.get("sans", []))]))

    best = None
    best_score = 0
    best_evidence = []

    for fp in VPN_FINGERPRINTS:
        score = 0
        evidence = []

        # --- TLS certificate signatures (strong, product-specific) ---
        for rx in fp["_cert"]:
            if rx.search(cert_fields) or rx.search(cert_text):
                score += 30
                evidence.append(f"TLS cert matches /{rx.pattern}/")
                break

        # --- HTTP response signatures ---
        for resp in responses:
            if resp is None:
                continue
            body = resp["body"]
            setck = resp["set_cookie"]
            headers = resp["headers"]
            title_m = _TITLE_RE.search(body)
            title = title_m.group(1).strip() if title_m else ""

            for rx in fp["_body"]:
                if rx.search(body):
                    score += 40
                    evidence.append(f"body matches /{rx.pattern}/ "
                                    f"(HTTP {resp['status']})")
                    break
            for rx in fp["_cookies"]:
                if rx.search(setck) or rx.search(resp["cookies"]):
                    score += 35
                    evidence.append(f"cookie matches /{rx.pattern}/")
                    break
            if title:
                for rx in fp["_title"]:
                    if rx.search(title):
                        score += 25
                        evidence.append(f"title '{title[:50]}'")
                        break
            for hname, rxs in fp["_headers"].items():
                hval = headers.get(hname, "")
                for rx in rxs:
                    if rx.search(hval):
                        score += 25
                        evidence.append(f"header {hname}: {hval[:40]}")
                        break

        # --- Default-port corroboration (weak on its own) ---
        if any(p in open_ports for p in fp["ports"] if p not in (80, 443)):
            score += 5

        # Deduplicate evidence, cap noise.
        evidence = list(dict.fromkeys(evidence))
        if score > best_score:
            best_score, best, best_evidence = score, fp, evidence

    return best, best_score, best_evidence


# --------------------------------------------------------------------------- #
#  Per-host analysis pipeline
# --------------------------------------------------------------------------- #
def analyse_host(session, host, ips, args):
    """Full analysis for a single hostname. Returns a result dict."""
    result = {
        "host": host, "ips": ips, "open_ports": [], "services": {},
        "tls": None, "product": None, "vendor": None, "confidence": 0,
        "verdict": "not-vpn", "evidence": [], "cve_notes": [], "reverse_dns": {},
        "cdn": None, "asn": None,
    }
    # Prefer an IPv4 address for scanning (broadest tool compatibility).
    ip = next((a for a in ips if ":" not in a), ips[0])

    # Reverse DNS for context.
    for a in ips:
        try:
            result["reverse_dns"][a] = socket.gethostbyaddr(a)[0]
        except Exception:
            pass

    # Port scan (native).
    if not args.skip_ports:
        result["open_ports"] = tcp_connect_scan(
            ip, COMMON_VPN_PORTS_TCP, timeout=args.timeout)

    # Optional nmap enrichment.
    if args.nmap and result["open_ports"]:
        result["services"] = nmap_service_scan(ip, result["open_ports"])

    # Determine which TLS ports to fingerprint: prefer open ones, else 443.
    tls_targets = [p for p in TLS_PORTS if p in result["open_ports"]]
    if not tls_targets and (not args.skip_ports and 443 in result["open_ports"]):
        tls_targets = [443]
    if args.skip_ports:  # no port data: try 443 blindly
        tls_targets = [443]

    responses = []
    cert = None
    for port in tls_targets:
        cert = cert or grab_tls_cert(host, port, args.timeout)
        base = f"https://{host}:{port}" if port != 443 else f"https://{host}"
        for path in _PROBE_PATHS:
            resp = http_probe(session, base, path, args.timeout)
            if resp:
                responses.append(resp)
        if responses:
            break  # one working TLS port is enough for fingerprinting
    result["tls"] = cert

    # CDN / WAF detection + ASN labelling of the primary IP.
    resp_headers = responses[0]["headers"] if responses else None
    result["cdn"] = detect_cdn(host, ips, resp_headers)
    result["asn"] = ip_to_asn(ip)

    # Match fingerprints.
    fp, score, evidence = match_fingerprints(
        responses, cert, host, result["open_ports"])

    # --- Compose confidence score from all signals ---
    conf = score
    if fp:
        result["product"] = fp["name"]
        result["vendor"] = fp["vendor"]
        result["cve_notes"] = fp["cve"]
        result["evidence"].extend(evidence)

    if hostname_looks_like_vpn(host):
        conf += 15
        result["evidence"].append("hostname suggests VPN/remote-access")

    for p in result["open_ports"]:
        if p in STRONG_PORT_SIGNAL:
            label, weight = STRONG_PORT_SIGNAL[p]
            conf += weight
            result["evidence"].append(f"port {p}/tcp open ({label})")

    # nmap service keyword corroboration.
    for p, svc in result["services"].items():
        blob = f"{svc.get('service', '')} {svc.get('version', '')}".lower()
        if any(k in blob for k in ("vpn", "fortinet", "globalprotect",
                                   "anyconnect", "pulse", "ivanti", "citrix",
                                   "sonicwall", "openvpn", "wireguard")):
            conf += 20
            result["evidence"].append(
                f"nmap: {p}/tcp {svc.get('service')} {svc.get('version')}".strip())

    result["confidence"] = min(conf, 100)
    if result["confidence"] >= 70:
        result["verdict"] = "confirmed-vpn"
    elif result["confidence"] >= 40:
        result["verdict"] = "likely-vpn"
    elif result["confidence"] >= 20:
        result["verdict"] = "possible-vpn"
    else:
        result["verdict"] = "not-vpn"

    return result


# --------------------------------------------------------------------------- #
#  Reporting
# --------------------------------------------------------------------------- #
VERDICT_STYLE = {
    "confirmed-vpn": (C.GREEN, "CONFIRMED VPN"),
    "likely-vpn": (C.YELLOW, "LIKELY VPN"),
    "possible-vpn": (C.CYAN, "POSSIBLE VPN"),
    "not-vpn": (C.DIM, "no VPN indicators"),
}


def print_host_report(res):
    color, label = VERDICT_STYLE[res["verdict"]]
    bar = f"{color}{C.BOLD}[{label} | {res['confidence']}/100]{C.ENDC}"
    print(f"\n{C.PURPLE}{C.BOLD}=== {res['host']} ==={C.ENDC}  {bar}")
    print(f"  IPs           : {C.CYAN}{', '.join(res['ips'])}{C.ENDC}")
    if res.get("asn"):
        a = res["asn"]
        print(f"  Network       : {C.DIM}AS{a['asn']} {a['org']} "
              f"({a['cidr']} {a['cc']}){C.ENDC}")
    if res.get("cdn"):
        print(f"  CDN / WAF     : {C.YELLOW}{res['cdn']}{C.ENDC} "
              f"{C.DIM}(edge IP - real origin hidden){C.ENDC}")
    for a, ptr in res["reverse_dns"].items():
        print(f"  Reverse DNS   : {C.CYAN}{a}{C.ENDC} -> {C.GREEN}{ptr}{C.ENDC}")
    if res["product"]:
        print(f"  Product       : {C.GREEN}{C.BOLD}{res['product']}{C.ENDC} "
              f"({res['vendor']})")
    if res["open_ports"]:
        pretty = []
        for p in res["open_ports"]:
            svc = res["services"].get(p)
            if svc:
                pretty.append(f"{p}({svc['service']} {svc['version']})".strip())
            elif p in STRONG_PORT_SIGNAL:
                pretty.append(f"{C.YELLOW}{p}{C.ENDC}")
            else:
                pretty.append(str(p))
        print(f"  Open TCP ports: {', '.join(pretty)}")
    if res["tls"] and res["tls"].get("subject_cn"):
        print(f"  TLS cert CN   : {C.DIM}{res['tls']['subject_cn']}{C.ENDC}")
        if res["tls"].get("sans"):
            sans = ", ".join(res["tls"]["sans"][:6])
            print(f"  TLS SANs      : {C.DIM}{sans}{C.ENDC}")
    if res["evidence"]:
        print(f"  Evidence      :")
        for e in res["evidence"]:
            print(f"    {C.GREEN}-{C.ENDC} {e}")
    if res["cve_notes"] and res["verdict"] in ("confirmed-vpn", "likely-vpn"):
        print(f"  {C.RED}{C.BOLD}Known CVEs for this product (verify version!):{C.ENDC}")
        for cve in res["cve_notes"]:
            print(f"    {C.RED}!{C.ENDC} {cve}")


def print_origin_report(findings):
    if not findings:
        print(f"  {C.DIM}No CDN-fronted hosts required origin discovery.{C.ENDC}")
        return
    any_origin = False
    for host, data in findings.items():
        cdn = data.get("cdn") or "unknown"
        origins = data.get("origins", [])
        confirmed = [o for o in origins if o["verified"]]
        print(f"\n  {C.BOLD}{host}{C.ENDC}  "
              f"(behind {C.YELLOW}{cdn}{C.ENDC})")
        if not origins:
            print(f"    {C.DIM}no origin candidates verified.{C.ENDC}")
            continue
        for o in origins:
            any_origin = True
            tag = (f"{C.GREEN}{C.BOLD}CONFIRMED ORIGIN{C.ENDC}" if o["verified"]
                   else f"{C.YELLOW}possible origin{C.ENDC}")
            asn = o.get("asn")
            org = f"  {C.DIM}AS{asn['asn']} {asn['org'][:34]}{C.ENDC}" if asn else ""
            print(f"    {tag}: {C.CYAN}{C.BOLD}{o['ip']}{C.ENDC}"
                  f"  [score {o['score']}]{org}")
            print(f"        found via : {', '.join(o['methods'])}")
            for reason in o["reasons"]:
                print(f"        {C.GREEN}+{C.ENDC} {reason}")
    if any_origin:
        print(f"\n  {C.GREEN}{C.BOLD}>> Real IP address(es) recovered behind the "
              f"CDN above.{C.ENDC}")


def write_json(path, target, results, meta, origin_findings=None):
    payload = {"target": target, "meta": meta,
               "results": [_strip_internal(r) for r in results],
               "origin_discovery": origin_findings or {}}
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
    good(f"JSON report written to {C.CYAN}{path}{C.ENDC}")


def write_origins_csv(path, findings):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["host", "cdn", "origin_ip", "verified", "score",
                    "asn", "asn_org", "methods", "reasons"])
        for host, data in findings.items():
            for o in data.get("origins", []):
                asn = o.get("asn") or {}
                w.writerow([
                    host, data.get("cdn") or "", o["ip"], o["verified"],
                    o["score"], asn.get("asn", ""), asn.get("org", ""),
                    ";".join(o["methods"]), " | ".join(o["reasons"]),
                ])
    good(f"Origins CSV written to {C.CYAN}{path}{C.ENDC}")


def _strip_internal(r):
    r = dict(r)
    if r.get("tls"):
        tls = dict(r["tls"])
        tls.pop("raw", None)  # drop bulky raw cert bytes
        r["tls"] = tls
    return r


def write_csv(path, results):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["host", "ips", "verdict", "confidence", "product",
                    "vendor", "open_ports", "evidence"])
        for r in results:
            w.writerow([
                r["host"], ";".join(r["ips"]), r["verdict"], r["confidence"],
                r["product"] or "", r["vendor"] or "",
                ";".join(map(str, r["open_ports"])),
                " | ".join(r["evidence"]),
            ])
    good(f"CSV report written to {C.CYAN}{path}{C.ENDC}")


# --------------------------------------------------------------------------- #
#  Banner & CLI
# --------------------------------------------------------------------------- #
def print_banner():
    banner = r"""
 __     ______  _   _   _____ _           _
 \ \   / /  _ \| \ | | |  ___(_)_ __   __| | ___ _ __
  \ \ / /| |_) |  \| | | |_  | | '_ \ / _` |/ _ \ '__|
   \ V / |  __/| |\  | |  _| | | | | | (_| |  __/ |
    \_/  |_|   |_| \_| |_|   |_|_| |_|\__,_|\___|_|
"""
    print(f"{C.PURPLE}{banner}{C.ENDC}")
    print(f"{C.BOLD}VPN Finder v{SCRIPT_VERSION}{C.ENDC}  |  "
          f"VPN fingerprinting + CDN-bypass origin discovery  |  "
          f"by {C.YELLOW}{SCRIPT_AUTHORS}{C.ENDC}")
    print(C.DIM + "-" * 72 + C.ENDC)


def build_parser():
    p = argparse.ArgumentParser(
        prog="vpn-finder.py",
        description="Discover and fingerprint VPN / remote-access gateways.",
        epilog="Authorized testing only. You must have explicit permission to "
               "scan the target.",
        formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("target_domain", help="Target apex domain, e.g. company.com")
    p.add_argument("-w", "--wordlist",
                   help="Custom subdomain wordlist for DNS brute-force.")
    p.add_argument("-t", "--threads", type=int, default=40,
                   help="Concurrency for resolution/scanning (default: 40).")
    p.add_argument("--timeout", type=float, default=6.0,
                   help="Per-connection timeout in seconds (default: 6).")
    p.add_argument("--all", action="store_true",
                   help="Fingerprint every resolved host, not just "
                        "VPN-named candidates (slower, more thorough).")
    p.add_argument("--skip-passive", action="store_true",
                   help="Skip passive subdomain enumeration.")
    p.add_argument("--skip-brute", action="store_true",
                   help="Skip active DNS brute-force.")
    p.add_argument("--skip-ports", action="store_true",
                   help="Skip TCP port scanning (fingerprint over 443 only).")
    p.add_argument("--nmap", action="store_true",
                   help="Enrich open ports with nmap -sV (if installed).")
    p.add_argument("--ffuf", action="store_true",
                   help="Also run ffuf HTTP fuzzing (if installed).")
    p.add_argument("--ffuf-options", default="",
                   help="Extra options passed through to ffuf.")

    og = p.add_argument_group("origin / CDN-bypass")
    og.add_argument("--no-origin", action="store_true",
                    help="Disable origin-IP discovery for CDN-fronted hosts.")
    og.add_argument("--force-origin", action="store_true",
                    help="Hunt for an origin IP even when no CDN is detected.")
    og.add_argument("--asn-sweep", action="store_true",
                    help="Sweep the ASN/netblock around confirmed origins "
                         "(heavier; verifies each neighbour).")
    og.add_argument("--sweep-cap", type=int, default=1024,
                    help="Max IPs to sweep from a single CIDR (default: 1024).")

    p.add_argument("-o", "--output",
                   help="Base path for output files (writes .json and .csv).")
    p.add_argument("--min-confidence", type=int, default=20,
                   help="Only report hosts at/above this score (default: 20).")
    p.add_argument("--no-color", action="store_true", help="Disable colours.")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {SCRIPT_VERSION}")
    return p


# --------------------------------------------------------------------------- #
#  Main
# --------------------------------------------------------------------------- #
def main():
    args = build_parser().parse_args()
    if args.no_color:
        C.disable()

    print_banner()
    start = datetime.now(timezone.utc)

    target = args.target_domain.lower().strip().lstrip(".")
    if not re.match(r"^([a-z0-9-]+\.)+[a-z]{2,}$", target):
        err(f"Invalid target domain: {target}")
        sys.exit(2)

    info(f"Target: {C.CYAN}{C.BOLD}{target}{C.ENDC}")
    warn("Ensure you have explicit authorization to test this target.")

    session = build_session()

    # --- Gather subdomains ---
    subdomains = set()
    subdomains.add(target)  # always analyse the apex too

    if not args.skip_passive:
        subdomains |= passive_enumeration(session, target, args.threads)

    wordlist = VPN_WORDLIST
    if args.wordlist:
        if not os.path.exists(args.wordlist):
            err(f"Wordlist not found: {args.wordlist}")
            sys.exit(2)
        with open(args.wordlist) as f:
            wordlist = [ln.strip() for ln in f if ln.strip()
                        and not ln.startswith("#")]

    if not args.skip_brute:
        brute = dns_bruteforce(target, wordlist, args.threads)
        subdomains |= set(brute.keys())

    if args.ffuf:
        wl_path = args.wordlist
        tmp_wl = None
        if not wl_path:
            tmp_wl = os.path.join(os.getenv("TMPDIR", "/tmp"),
                                  f"vpnfinder_wl_{os.getpid()}.txt")
            with open(tmp_wl, "w") as f:
                f.write("\n".join(VPN_WORDLIST))
            wl_path = tmp_wl
        subdomains |= fuzz_with_ffuf(target, wl_path, args.ffuf_options)
        if tmp_wl and os.path.exists(tmp_wl):
            os.remove(tmp_wl)

    info(f"Collected {C.BOLD}{len(subdomains)}{C.ENDC} unique candidate hosts.")

    # --- Resolve all candidates ---
    info("Resolving candidates to IP addresses...")
    resolved = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        fut_map = {ex.submit(resolve_host, h): h for h in subdomains}
        for fut in concurrent.futures.as_completed(fut_map):
            host = fut_map[fut]
            ips = fut.result()
            if ips:
                resolved[host] = ips
    good(f"{C.BOLD}{len(resolved)}{C.ENDC} hosts resolved.")

    if not resolved:
        warn("No hosts resolved. Nothing to analyse.")
        sys.exit(0)

    # --- Select analysis targets ---
    if args.all:
        targets = sorted(resolved.items())
    else:
        targets = sorted((h, ips) for h, ips in resolved.items()
                         if hostname_looks_like_vpn(h) or h == target)
        skipped = len(resolved) - len(targets)
        if skipped:
            info(f"Prioritising {C.BOLD}{len(targets)}{C.ENDC} VPN-named hosts "
                 f"({skipped} others skipped; use {C.DIM}--all{C.ENDC} to include them).")

    if not targets:
        warn("No VPN-named candidates. Re-run with --all to fingerprint "
             "every resolved host.")
        sys.exit(0)

    # --- Analyse hosts concurrently ---
    info(f"Fingerprinting {C.BOLD}{len(targets)}{C.ENDC} hosts...")
    results = []
    analysis_workers = max(1, min(args.threads, 20))
    with concurrent.futures.ThreadPoolExecutor(max_workers=analysis_workers) as ex:
        fut_map = {ex.submit(analyse_host, session, h, ips, args): h
                   for h, ips in targets}
        for fut in concurrent.futures.as_completed(fut_map):
            try:
                results.append(fut.result())
            except Exception as e:
                warn(f"Analysis failed for {fut_map[fut]}: {e}")

    # --- Report ---
    results.sort(key=lambda r: r["confidence"], reverse=True)
    reported = [r for r in results if r["confidence"] >= args.min_confidence]

    print(f"\n{C.PURPLE}{C.BOLD}{'=' * 24} RESULTS {'=' * 24}{C.ENDC}")
    confirmed = [r for r in reported if r["verdict"] == "confirmed-vpn"]
    likely = [r for r in reported if r["verdict"] == "likely-vpn"]
    possible = [r for r in reported if r["verdict"] == "possible-vpn"]

    for r in reported:
        print_host_report(r)

    print(f"\n{C.PURPLE}{C.BOLD}{'=' * 24} SUMMARY {'=' * 24}{C.ENDC}")
    print(f"  {C.GREEN}Confirmed VPNs : {len(confirmed)}{C.ENDC}")
    print(f"  {C.YELLOW}Likely VPNs    : {len(likely)}{C.ENDC}")
    print(f"  {C.CYAN}Possible VPNs  : {len(possible)}{C.ENDC}")
    print(f"  Hosts analysed : {len(results)}")

    if confirmed or likely:
        print(f"\n  {C.BOLD}Top findings:{C.ENDC}")
        for r in (confirmed + likely):
            prod = r["product"] or "unknown product"
            print(f"    {C.GREEN}*{C.ENDC} {C.BOLD}{r['host']}{C.ENDC} -> "
                  f"{prod} [{r['confidence']}/100]")

    # --- Origin-IP discovery (CDN bypass) ---
    origin_findings = {}
    if not args.no_origin:
        hunt_hosts = []
        for h in [target, "www." + target]:
            if h in resolved:
                hunt_hosts.append(h)
        for r in results:  # any host detected behind a CDN
            if r.get("cdn") and r["host"] not in hunt_hosts:
                hunt_hosts.append(r["host"])
        if args.force_origin:
            for h in ([target] + [r["host"] for r in results]):
                if h not in hunt_hosts:
                    hunt_hosts.append(h)
        hunt_hosts = hunt_hosts[:8]  # keep the pass bounded

        if hunt_hosts:
            print(f"\n{C.PURPLE}{C.BOLD}{'=' * 20} ORIGIN DISCOVERY {'=' * 20}{C.ENDC}")
            origin_findings = origin_discovery(
                session, target, hunt_hosts, resolved, args)
            print_origin_report(origin_findings)

    # --- Output files ---
    meta = {"version": SCRIPT_VERSION,
            "started": start.isoformat(),
            "finished": datetime.now(timezone.utc).isoformat(),
            "hosts_resolved": len(resolved),
            "hosts_analysed": len(results)}
    if args.output:
        write_json(args.output + ".json", target, results, meta,
                   origin_findings)
        write_csv(args.output + ".csv", results)
        if origin_findings:
            write_origins_csv(args.output + ".origins.csv", origin_findings)

    duration = datetime.now(timezone.utc) - start
    print(f"\n{C.DIM}Completed in {duration}.{C.ENDC}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        err("Interrupted by user.")
        sys.exit(130)
