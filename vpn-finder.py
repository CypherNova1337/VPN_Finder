#!/usr/bin/env python3

import argparse
import subprocess
import requests
import json
import os
import shutil
import socket
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# --- Configuration & Attribution ---
SCRIPT_VERSION = "1.2" # Updated version
SCRIPT_AUTHORS = "Cyphernova1337, VoidSec"

# --- ANSI Color Codes ---
class TermColors:
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'  # Reset
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    DIM = '\033[2m'   # For less emphasized text

    # Simple check for NO_COLOR environment variable
    if os.getenv('NO_COLOR'):
        PURPLE = BLUE = CYAN = GREEN = YELLOW = RED = ENDC = BOLD = UNDERLINE = DIM = ''

VPN_SUBDOMAIN_WORDLIST_EMBEDDED = [
    "vpn", "remote", "access", "sslvpn", "portal", "gateway", "connect", "client",
    "secure", "login", "auth", "openvpn", "anyconnect", "forti", "pulse", "pulsesecure",
    "globalprotect", "gp", "gw", "internal", "corp", "corporate", "employee", "staff",
    "webvpn", "ras", "tunnel", "netscaler", "citrixgateway", "employeevpn", "staffvpn",
    "myvpn", "vpn01", "vpn1", "remoteaccess", "secureaccess", "dialin", "telework",
    "extranet", "work", "desktop", "vdi", "securegw", "vpngw", "sslaccess"
]

VPN_SERVICE_KEYWORDS_NMAP = [
    "openvpn", "fortisslvpn", "fortinet", "fortigate", "globalprotect", "gpvpn", "panos",
    "pulse secure", "psal", "anyconnect", "cisco-asa", "cisco-secure", "sslvpn", "network connect",
    "juniper sa", "netscreen", "sonicwall ssl vpn", "sonicwall", "array spx", "big-ip", "f5",
    "checkpoint", "meraki", "watchguard", "barracuda", "ztna", "wireguard"
]

COMMON_VPN_PORTS_TCP = [22, 443, 1194, 1723, 3389, 5900, 8080, 10000, 10443, 4443]
COMMON_VPN_PORTS_UDP = [500, 1194, 4500, 1701, 51820]

# --- Helper Functions (with color) ---

def print_banner():
    # ASCII Art for "VPN Finder"
    banner = f"""
V   V  PPPP   N   N        FFFFF  III  N   N  DDDD   EEEE   RRRR  
V   V  P   P  NN  N        F       I   NN  N  D   D  E      R   R 
V   V  PPPP   N N N        FFFF    I   N N N  D   D  EEE    RRRR  
 V V   P      N  NN        F       I   N  NN  D   D  E      R R   
  V    P      N   N        F      III  N   N  DDDD   EEEE   R  RR 
    """
    print(banner)
    print(f"{TermColors.BOLD}VPN Finder v{SCRIPT_VERSION}{TermColors.ENDC} | Created by: {TermColors.YELLOW}{SCRIPT_AUTHORS}{TermColors.ENDC}")
    print(TermColors.DIM + "-" * 70 + TermColors.ENDC)

def print_info(message):
    print(f"{TermColors.BLUE}[*]{TermColors.ENDC} {message}")

def print_success(message):
    print(f"{TermColors.GREEN}[+]{TermColors.ENDC} {message}")

def print_warning(message):
    print(f"{TermColors.YELLOW}[!]{TermColors.ENDC} {message}")

def print_error(message):
    print(f"{TermColors.RED}[ERROR]{TermColors.ENDC} {message}")

def check_tool_installed(tool_name):
    if shutil.which(tool_name) is None:
        print_error(f"{TermColors.BOLD}{tool_name}{TermColors.ENDC} is not installed or not in PATH. Please install it.")
        return False
    return True

def run_command(command, timeout=None):
    try:
        process = subprocess.run(
            command, shell=True, capture_output=True, text=True, check=False, timeout=timeout
        )
        return process.stdout, process.stderr, process.returncode
    except subprocess.TimeoutExpired:
        print_warning(f"Command '{TermColors.DIM}{command}{TermColors.ENDC}' timed out after {timeout} seconds.")
        return "", "Timeout", -1
    except Exception as e:
        print_error(f"Error running command '{TermColors.DIM}{command}{TermColors.ENDC}': {e}")
        return "", str(e), -1

def resolve_host_to_ip(hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror:
        return None

def reverse_dns_lookup(ip_address):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except (socket.herror, socket.gaierror):
        return None

def is_vpn_related_subdomain(subdomain):
    subdomain_lower = subdomain.lower()
    for keyword in VPN_SUBDOMAIN_WORDLIST_EMBEDDED:
        if keyword in subdomain_lower:
            return True
    if re.search(r'(vpn|gw|gateway|remote|access)\d+', subdomain_lower) or \
       re.search(r'(vpn|gw|gateway|remote|access)-[a-z]{2,}', subdomain_lower):
        return True
    return False

def is_vpn_related_service(service_name, version_info):
    text_to_check = (str(service_name) + " " + str(version_info)).lower()
    for keyword in VPN_SERVICE_KEYWORDS_NMAP:
        if keyword in text_to_check:
            return True
    return False

# --- Discovery Functions --- ( Largely unchanged, print statements within them use new helpers )

def fuzz_subdomains_with_ffuf(target_domain, wordlist_path, ffuf_options=""):
    print_info(f"Starting ffuf subdomain fuzzing for {TermColors.CYAN}{target_domain}{TermColors.ENDC} using wordlist: {TermColors.DIM}{wordlist_path}{TermColors.ENDC}")
    found_subdomains = set()
    output_file = f"ffuf_results_{target_domain.replace('.', '_')}_{os.getpid()}.json"
    
    protocols_to_try = [
        (f"ffuf -w {wordlist_path} -u https://FUZZ.{target_domain} -H \"User-Agent: VPNReconScript/{SCRIPT_VERSION}\" -mc 200,204,301,302,307,401,403,500 -fs 0 -o {output_file} -of json --silent {ffuf_options}", "HTTPS"),
        (f"ffuf -w {wordlist_path} -u http://FUZZ.{target_domain} -H \"User-Agent: VPNReconScript/{SCRIPT_VERSION}\" -mc 200,204,301,302,307,401,403,500 -fs 0 -o {output_file} -of json --silent {ffuf_options}", "HTTP")
    ]

    for ffuf_cmd, proto_name in protocols_to_try:
        print_info(f"Running FFUF ({proto_name})... This might take a while.")
        stdout, stderr, returncode = run_command(ffuf_cmd, timeout=1800) # 30 min timeout

        if returncode == -1 and "Timeout" in stderr:
            print_warning(f"FFUF {proto_name} scan timed out.")
            continue

        if os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f: results_data = json.load(f)
                if "results" in results_data and results_data["results"]:
                    for res in results_data["results"]:
                        parsed_url = urlparse(res.get("url", ""))
                        if parsed_url.hostname and target_domain in parsed_url.hostname:
                            hostname_candidate = parsed_url.hostname.lower()
                            if hostname_candidate != target_domain and hostname_candidate not in found_subdomains:
                                print_success(f"FFUF ({proto_name}) found: {TermColors.GREEN}{hostname_candidate}{TermColors.ENDC} (Status: {res.get('status')}, Size: {res.get('length')})")
                                found_subdomains.add(hostname_candidate)
            except json.JSONDecodeError:
                print_warning(f"Could not decode FFUF JSON output from {output_file}. FFUF STDOUT: {stdout[:200]}")
            except Exception as e:
                print_warning(f"Error processing FFUF results for {proto_name}: {e}")
            finally:
                if os.path.exists(output_file):
                    try: os.remove(output_file)
                    except OSError as e: print_warning(f"Could not remove ffuf output file {output_file}: {e}")
        elif stdout or stderr :
             print_info(f"FFUF ({proto_name}) completed. No JSON file or empty. STDOUT: {stdout[:100]} STDERR: {stderr[:100]}")
    
    if not found_subdomains:
        print_info("FFUF did not find any new subdomains responsive via HTTP/S.")
    return list(found_subdomains)


def search_crt_sh(target_domain):
    print_info(f"Querying crt.sh for subdomains of {TermColors.CYAN}{target_domain}{TermColors.ENDC}")
    found_subdomains_crt = set()
    try:
        response = requests.get(f"https://crt.sh/?q=%.{target_domain}&output=json", timeout=30)
        response.raise_for_status()
        if not response.content:
            print_warning("crt.sh returned an empty response.")
            return []
        try: data = response.json()
        except json.JSONDecodeError:
            print_warning(f"crt.sh returned non-JSON response: {TermColors.DIM}{response.text[:200]}{TermColors.ENDC}")
            return []

        for entry in data:
            name_value = entry.get("name_value", "")
            if name_value:
                subdomains_in_entry = name_value.split('\n')
                for sub in subdomains_in_entry:
                    sub = sub.strip().lower()
                    if sub.startswith("*."): sub = sub[2:]
                    if sub and target_domain in sub and sub != target_domain:
                        if re.match(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', sub):
                            if is_vpn_related_subdomain(sub):
                                found_subdomains_crt.add(sub)
                                print_success(f"crt.sh found VPN-related: {TermColors.GREEN}{sub}{TermColors.ENDC}")
                            # else:
                            #    print_info(f"crt.sh found (filtered non-VPN): {TermColors.DIM}{sub}{TermColors.ENDC}")
    except requests.exceptions.RequestException as e:
        print_warning(f"Could not connect to crt.sh: {e}")
    except Exception as e:
        print_error(f"Unexpected error querying crt.sh: {e}")

    if found_subdomains_crt:
        print_info(f"crt.sh found {TermColors.BOLD}{len(found_subdomains_crt)}{TermColors.ENDC} unique VPN-related subdomains.")
    else:
        print_info("crt.sh did not find any VPN-related subdomains (or all were filtered).")
    return list(found_subdomains_crt)


def scan_ports_with_nmap(target_host_or_ip, ports_tcp, ports_udp):
    report = {"host": target_host_or_ip, "tcp_ports": [], "udp_ports": []}
    target_display_name = f"{TermColors.CYAN}{target_host_or_ip}{TermColors.ENDC}"
    
    if ports_tcp:
        tcp_ports_str = ",".join(map(str, ports_tcp))
        print_info(f"Nmap TCP scan on {target_display_name} for ports: {TermColors.DIM}{tcp_ports_str}{TermColors.ENDC}")
        nmap_tcp_cmd = f"nmap -sV -Pn -T4 --open -p {tcp_ports_str} {target_host_or_ip} -oG -"
        stdout, _, _ = run_command(nmap_tcp_cmd, timeout=600)
        if stdout: # Parsing logic remains similar, reporting colorization is handled in main
            for line in stdout.splitlines():
                if "Ports:" in line and "open" in line:
                    parts = line.split("\t")
                    for part in parts:
                        if "Ports:" in part:
                            port_info_str = part.split("Ports:")[1].strip()
                            port_entries = port_info_str.split(", ")
                            for entry in port_entries:
                                p_details = entry.split("/")
                                if len(p_details) >= 7 and p_details[1] == "open":
                                    report["tcp_ports"].append({
                                        "port_num": int(p_details[0]), "protocol": p_details[2],
                                        "service": p_details[4] if p_details[4] else "unknown",
                                        "version": p_details[6] if p_details[6] else "unknown"
                                    })
    if ports_udp:
        udp_ports_str = ",".join(map(str, ports_udp))
        print_info(f"Nmap UDP scan on {target_display_name} for ports: {TermColors.DIM}{udp_ports_str}{TermColors.ENDC} (slow)")
        nmap_udp_cmd = f"sudo nmap -sU -sV -Pn -T4 --open --min-rate 1000 -p {udp_ports_str} {target_host_or_ip} -oG -"
        stdout, stderr, _ = run_command(nmap_udp_cmd, timeout=1200)
        if "requires root privileges" in stderr.lower() and "sudo" not in nmap_udp_cmd:
            print_warning("Optimized UDP scan needs root. Trying without sudo (slower).")
            nmap_udp_cmd = f"nmap -sU -sV -Pn -T3 --open -p {udp_ports_str} {target_host_or_ip} -oG -"
            stdout, _, _ = run_command(nmap_udp_cmd, timeout=1800)
        if stdout: # Parsing logic remains similar
            for line in stdout.splitlines():
                 if "Ports:" in line and ("open" in line or "open|filtered" in line):
                    parts = line.split("\t")
                    for part in parts:
                        if "Ports:" in part:
                            port_info_str = part.split("Ports:")[1].strip()
                            port_entries = port_info_str.split(", ")
                            for entry in port_entries:
                                p_details = entry.split("/")
                                if len(p_details) >= 7 and (p_details[1] == "open" or p_details[1] == "open|filtered"):
                                    report["udp_ports"].append({
                                        "port_num": int(p_details[0]), "protocol": p_details[2], "state": p_details[1],
                                        "service": p_details[4] if p_details[4] else "unknown",
                                        "version": p_details[6] if p_details[6] else "unknown"
                                    })
    return report

# --- Main Logic ---

def main():
    print_banner()
    start_time = datetime.now()

    cli_description = f"""
    {TermColors.BOLD}VPN Finder v{SCRIPT_VERSION} - Automated VPN Endpoint Discovery Tool{TermColors.ENDC}
    {TermColors.DIM}---------------------------------------------------------{TermColors.ENDC}
    This script attempts to discover potential VPN endpoints
    for a given target domain using various techniques:
      {TermColors.CYAN}-{TermColors.ENDC} Subdomain fuzzing with {TermColors.YELLOW}ffuf{TermColors.ENDC}
      {TermColors.CYAN}-{TermColors.ENDC} Certificate Transparency log searching ({TermColors.YELLOW}crt.sh{TermColors.ENDC})
      {TermColors.CYAN}-{TermColors.ENDC} Port scanning for common VPN ports with {TermColors.YELLOW}nmap{TermColors.ENDC}
      {TermColors.CYAN}-{TermColors.ENDC} Reverse DNS lookups

    Crafted by: {TermColors.GREEN}{SCRIPT_AUTHORS}{TermColors.ENDC}
    """
    cli_epilog = f"""
    {TermColors.BOLD}Ethical Use Notice:{TermColors.ENDC}
      Use this script responsibly and {TermColors.UNDERLINE}only on systems you have
      explicit permission to test{TermColors.ENDC}. Unauthorized scanning is
      illegal and unethical.

    {TermColors.BOLD}Example Usage:{TermColors.ENDC}
      {TermColors.DIM}./vpn_recon.py company.com{TermColors.ENDC}
      {TermColors.DIM}./vpn_recon.py company.com -w custom_vpn_list.txt --threads 15{TermColors.ENDC}
      {TermColors.DIM}./vpn_recon.py company.com --skip-crtsh --ffuf-options "-t 100 -timeout 5"{TermColors.ENDC}
    """

    parser = argparse.ArgumentParser(
        description=cli_description,
        epilog=cli_epilog,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("target_domain", help=f"The main domain of the target company (e.g., {TermColors.DIM}company.com{TermColors.ENDC})")
    parser.add_argument("-w", "--wordlist", help=f"Path to a custom subdomain wordlist file.\n(Defaults to an embedded VPN-specific list)", default=None)
    parser.add_argument("-t", "--threads", type=int, help=f"Number of threads for concurrent operations.\n({TermColors.DIM}Default: 10{TermColors.ENDC})", default=10)
    parser.add_argument("--ffuf-options", help=f"Additional options for {TermColors.YELLOW}ffuf{TermColors.ENDC} (e.g., {TermColors.DIM}'-r -ac'{TermColors.ENDC}).\nEnclose in quotes.", default="")
    parser.add_argument("--skip-ffuf", action="store_true", help=f"Skip subdomain fuzzing with {TermColors.YELLOW}ffuf{TermColors.ENDC}.")
    parser.add_argument("--skip-crtsh", action="store_true", help=f"Skip {TermColors.YELLOW}crt.sh{TermColors.ENDC} subdomain lookup.")
    parser.add_argument("--skip-nmap", action="store_true", help=f"Skip {TermColors.YELLOW}Nmap{TermColors.ENDC} port scanning.")
    parser.add_argument('--version', action='version', version=f'%(prog)s {SCRIPT_VERSION}')

    args = parser.parse_args()

    if not args.skip_nmap and not check_tool_installed("nmap"): return
    if not args.skip_ffuf and not check_tool_installed("ffuf"): return

    target_domain = args.target_domain.lower().strip()
    if not re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target_domain):
        print_error(f"Invalid target domain format: {target_domain}")
        return
        
    wordlist_path = args.wordlist
    temp_wordlist_file = None
    if not wordlist_path:
        temp_wordlist_file = f"temp_vpn_wordlist_{os.getpid()}.txt"
        with open(temp_wordlist_file, "w") as f:
            for word in VPN_SUBDOMAIN_WORDLIST_EMBEDDED: f.write(word + "\n")
        wordlist_path = temp_wordlist_file
        print_info(f"Using embedded VPN-specific wordlist (saved to {TermColors.DIM}{temp_wordlist_file}{TermColors.ENDC})")
    elif not os.path.exists(wordlist_path):
        print_error(f"Wordlist file not found: {TermColors.DIM}{wordlist_path}{TermColors.ENDC}")
        if temp_wordlist_file and os.path.exists(temp_wordlist_file): os.remove(temp_wordlist_file)
        return

    all_discovered_subdomains = set()
    unique_resolved_ips = {} 

    if not args.skip_ffuf:
        ffuf_subdomains = fuzz_subdomains_with_ffuf(target_domain, wordlist_path, args.ffuf_options)
        all_discovered_subdomains.update(ffuf_subdomains)

    if not args.skip_crtsh:
        crtsh_subdomains = search_crt_sh(target_domain)
        all_discovered_subdomains.update(crtsh_subdomains)

    if temp_wordlist_file and os.path.exists(temp_wordlist_file):
        try: os.remove(temp_wordlist_file); print_info(f"Cleaned up temporary wordlist: {TermColors.DIM}{temp_wordlist_file}{TermColors.ENDC}")
        except OSError as e: print_warning(f"Could not remove temp wordlist {temp_wordlist_file}: {e}")

    if not all_discovered_subdomains:
        print_warning("No potential VPN-related subdomains found from any source. Exiting.")
        return

    print_info(f"Total unique potential VPN-related subdomains: {TermColors.BOLD}{len(all_discovered_subdomains)}{TermColors.ENDC}. Resolving them...")

    hosts_to_scan_map = {}
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_hostname = {executor.submit(resolve_host_to_ip, sub): sub for sub in all_discovered_subdomains}
        for future in as_completed(future_to_hostname):
            hostname = future_to_hostname[future]
            try:
                ip_address = future.result()
                if ip_address:
                    print_info(f"Resolved: {TermColors.GREEN}{hostname}{TermColors.ENDC} -> {TermColors.CYAN}{ip_address}{TermColors.ENDC}")
                    hosts_to_scan_map[hostname] = ip_address
                    if ip_address not in unique_resolved_ips: unique_resolved_ips[ip_address] = set()
                    unique_resolved_ips[ip_address].add(hostname)
            except Exception as exc: print_warning(f"{hostname} generated an exception during resolution: {exc}")
    
    if not unique_resolved_ips:
        print_warning("No subdomains could be resolved to IP addresses. Cannot proceed with port scanning.")
        return

    print_info(f"Resolved {TermColors.BOLD}{len(hosts_to_scan_map)}{TermColors.ENDC} hostnames to {TermColors.BOLD}{len(unique_resolved_ips)}{TermColors.ENDC} unique IP addresses.")
    
    report_header = f"{TermColors.PURPLE}{TermColors.BOLD}{'=' * 20} VPN Reconnaissance Report {'=' * 20}{TermColors.ENDC}"
    print(f"\n{report_header}")
    print(f"{TermColors.BOLD}Scan Target   :{TermColors.ENDC} {TermColors.CYAN}{target_domain}{TermColors.ENDC}")
    print(f"{TermColors.BOLD}Scan Started  :{TermColors.ENDC} {TermColors.DIM}{start_time.strftime('%Y-%m-%d %H:%M:%S')}{TermColors.ENDC}\n")

    if not args.skip_nmap:
        targets_for_nmap = list(unique_resolved_ips.keys())
        
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_ip = {executor.submit(scan_ports_with_nmap, ip, COMMON_VPN_PORTS_TCP, COMMON_VPN_PORTS_UDP): ip for ip in targets_for_nmap}
            for future in as_completed(future_to_ip):
                ip_target = future_to_ip[future]
                try:
                    scan_result = future.result()
                    associated_hostnames_set = unique_resolved_ips.get(ip_target, set())
                    hostnames_str = ", ".join(f"{TermColors.GREEN}{h}{TermColors.ENDC}" for h in associated_hostnames_set) if associated_hostnames_set else TermColors.DIM + "N/A" + TermColors.ENDC
                    
                    print(f"\n{TermColors.PURPLE}{TermColors.BOLD}--- Results for IP: {TermColors.CYAN}{ip_target}{TermColors.PURPLE} (Hostnames: {hostnames_str}{TermColors.PURPLE}) ---{TermColors.ENDC}")
                    r_dns = reverse_dns_lookup(ip_target)
                    if r_dns: print_info(f"Reverse DNS: {TermColors.CYAN}{ip_target}{TermColors.ENDC} -> {TermColors.GREEN}{r_dns}{TermColors.ENDC}")

                    # TCP Ports Reporting
                    if scan_result.get("tcp_ports"):
                        has_strong_tcp_vpn_indicator = False
                        print_info(f"{TermColors.BOLD}Open TCP Ports:{TermColors.ENDC}")
                        for p_data in scan_result["tcp_ports"]:
                            port_num = p_data['port_num']
                            service = p_data['service']
                            version = p_data['version']
                            service_info = f"{TermColors.GREEN}{service}{TermColors.ENDC} - {TermColors.DIM}{version}{TermColors.ENDC}"
                            port_display = f"  Port {TermColors.BOLD}{port_num}{TermColors.ENDC}/tcp:"

                            if port_num == 443:
                                hostname_is_vpn = any(is_vpn_related_subdomain(h) for h in associated_hostnames_set)
                                service_is_vpn = is_vpn_related_service(service, version)
                                if hostname_is_vpn or service_is_vpn:
                                    indicator = "Hostname" if hostname_is_vpn else ""
                                    if service_is_vpn: indicator += (" & " if indicator else "") + "Service"
                                    print_success(f"{port_display} {service_info} {TermColors.YELLOW}[VPN INDICATOR: {indicator}]{TermColors.ENDC}")
                                    has_strong_tcp_vpn_indicator = True
                                else:
                                    print(f"{TermColors.DIM}{port_display} {service_info} (Standard HTTPS){TermColors.ENDC}")
                            else: # For other TCP ports, generally more indicative if on common VPN lists
                                print_success(f"{port_display} {service_info}")
                                has_strong_tcp_vpn_indicator = True
                        if not has_strong_tcp_vpn_indicator and not any(p['port_num']==443 for p in scan_result.get("tcp_ports",[])): # if only non-443 ports were found but none were "success"
                             print_info("  No strong TCP VPN indicators found on common ports.")
                        elif not scan_result.get("tcp_ports"):
                             print_info("  No common TCP VPN ports found open or responsive.")

                    else:
                        print_info(f"{TermColors.DIM}  No common TCP VPN ports found open or responsive.{TermColors.ENDC}")
                    
                    # UDP Ports Reporting
                    if scan_result.get("udp_ports"):
                        print_info(f"{TermColors.BOLD}Open/Open|Filtered UDP Ports:{TermColors.ENDC}")
                        for p_data in scan_result["udp_ports"]:
                             service_info = f"{TermColors.GREEN}{p_data['service']}{TermColors.ENDC} - {TermColors.DIM}{p_data['version']}{TermColors.ENDC}"
                             print_success(f"  Port {TermColors.BOLD}{p_data['port_num']}{TermColors.ENDC}/udp ({TermColors.YELLOW}{p_data['state']}{TermColors.ENDC}): {service_info}")
                    else:
                        print_info(f"{TermColors.DIM}  No common UDP VPN ports found open or responsive (or scan inconclusive).{TermColors.ENDC}")

                except Exception as exc:
                    print_error(f"Nmap scan processing for {ip_target} generated an exception: {exc}")
    else:
        print_info(f"{TermColors.YELLOW}Nmap scanning was skipped by user.{TermColors.ENDC}")
        print(f"\n{TermColors.PURPLE}{TermColors.BOLD}--- Discovered Hosts & IPs (Nmap Skipped) ---{TermColors.ENDC}")
        for ip, hostnames_set in unique_resolved_ips.items():
            hostnames_str = ", ".join(f"{TermColors.GREEN}{h}{TermColors.ENDC}" for h in hostnames_set) if hostnames_set else TermColors.DIM + "N/A" + TermColors.ENDC
            print_info(f"IP: {TermColors.CYAN}{ip}{TermColors.ENDC} -> Hostnames: {hostnames_str}")
            r_dns = reverse_dns_lookup(ip)
            if r_dns: print_info(f"  Reverse DNS: {TermColors.CYAN}{ip}{TermColors.ENDC} -> {TermColors.GREEN}{r_dns}{TermColors.ENDC}")

    end_time = datetime.now()
    print(f"\n{TermColors.PURPLE}{TermColors.BOLD}{'=' * 20} Scan Finished {'=' * 20}{TermColors.ENDC}")
    print(f"{TermColors.BOLD}Scan Completed:{TermColors.ENDC} {TermColors.DIM}{end_time.strftime('%Y-%m-%d %H:%M:%S')}{TermColors.ENDC}")
    print(f"{TermColors.BOLD}Total duration:{TermColors.ENDC} {TermColors.DIM}{end_time - start_time}{TermColors.ENDC}")

if __name__ == "__main__":
    main()
