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
import shutil
import socket
import ssl
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

SCRIPT_VERSION = "2.0"
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


def write_json(path, target, results, meta):
    payload = {"target": target, "meta": meta,
               "results": [_strip_internal(r) for r in results]}
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
    good(f"JSON report written to {C.CYAN}{path}{C.ENDC}")


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
          f"VPN gateway discovery & fingerprinting  |  "
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

    # --- Output files ---
    meta = {"version": SCRIPT_VERSION,
            "started": start.isoformat(),
            "finished": datetime.now(timezone.utc).isoformat(),
            "hosts_resolved": len(resolved),
            "hosts_analysed": len(results)}
    if args.output:
        write_json(args.output + ".json", target, results, meta)
        write_csv(args.output + ".csv", results)

    duration = datetime.now(timezone.utc) - start
    print(f"\n{C.DIM}Completed in {duration}.{C.ENDC}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        err("Interrupted by user.")
        sys.exit(130)
