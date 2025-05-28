# VPN Finder

<pre>
V   V  PPPP   N   N        FFFFF  III  N   N  DDDD   EEEE   RRRR  
V   V  P   P  NN  N        F       I   NN  N  D   D  E      R   R 
V   V  PPPP   N N N        FFFF    I   N N N  D   D  EEE    RRRR  
 V V   P      N  NN        F       I   N  NN  D   D  E      R R   
  V    P      N   N        F      III  N   N  DDDD   EEEE   R  RR 
</pre>

**Version:** 1.2
**Created by:** Cyphernova1337, VoidSec

VPN Finder is a Python script designed to automate the discovery of potential VPN (Virtual Private Network) endpoints for a given target domain. It employs various reconnaissance techniques to identify subdomains and services that might indicate VPN usage.

---

## 📜 Description

This tool helps security researchers and penetration testers in the initial phases of an engagement by identifying potential VPN gateways. It combines subdomain enumeration through wordlist fuzzing and Certificate Transparency logs with targeted port scanning for common VPN protocols. The output is colorized for better readability and provides verbose details for positive findings.

---

## ⚠️ Disclaimer

**This script is intended for educational purposes and for use in authorized security testing or bug bounty scenarios ONLY.**

* Always ensure you have explicit, written permission from the system owner before scanning any target.
* Unauthorized scanning is illegal and unethical.
* The authors are not responsible for any misuse or damage caused by this script. Use responsibly and at your own risk.

---

## ✨ Features

* **Subdomain Enumeration:**
    * Utilizes `ffuf` with a customizable wordlist (an embedded VPN-specific list is used by default).
    * Queries `crt.sh` for subdomains from Certificate Transparency logs.
* **VPN Keyword Filtering:** Discovered subdomains (especially from `crt.sh`) are filtered to prioritize those likely related to VPN services.
* **Targeted Port Scanning:**
    * Uses `nmap` to scan for common TCP and UDP VPN ports on resolved IP addresses.
    * Includes service and version detection (`nmap -sV`).
* **Intelligent Port 443 Analysis:** Differentiates between standard HTTPS services and potential SSL VPNs on port 443 by checking hostname patterns and `nmap` service detection keywords.
* **Reverse DNS Lookups:** Performs reverse DNS lookups on identified IP addresses.
* **Colorized Output:** Terminal output is enhanced with colors for improved readability and easier parsing of results.
* **Customization:**
    * Supports custom wordlist files.
    * Adjustable number of threads for concurrent operations.
    * Allows passing additional options to `ffuf`.
    * Option to skip specific discovery modules (`ffuf`, `crt.sh`, `nmap`).
* **`NO_COLOR` Support:** Adheres to the `NO_COLOR` environment variable to disable colorized output if needed.

---

## 🛠️ Prerequisites

Before running VPN Finder, ensure you have the following installed:

1.  **Python 3.x** (Script is written for Python 3).
2.  **`ffuf`**:
    * Download: go install github.com/ffuf/ffuf/v2@latest
    * Ensure `ffuf` is in your system's PATH.
3.  **`nmap`**:
    * Install `nmap` for your operating system.
    * Ensure `nmap` is in your system's PATH.
    * **Note:** Optimized UDP scans with `nmap` (using `--min-rate`) often require `sudo` (root privileges). The script will attempt this and fall back to a slower scan if `sudo` is not available or fails.

---

## 🚀 Setup & Installation

1.  **Clone the repository (if applicable) or download the script (`VPN_Finder.py`).**
    ```bash
    # git clone [https://github.com/cyphernova1337/VPN_Finder.git](https://github.com/cyphernova1337/VPN_Finder.git)
    # cd VPN_Finder
    ```

2.  **Create the `requirements.txt` file** (as provided above) in the same directory as the script and install the Python dependencies:
    ```bash
    pip install -r requirements.txt
    ```
    *(This primarily installs the `requests` library).*

3.  **Make the script executable (optional but recommended):**
    ```bash
    chmod +x vpn_recon.py
    ```

4.  **Verify Prerequisites:** Confirm `ffuf` and `nmap` are installed and accessible:
    ```bash
    ffuf -V
    nmap --version
    ```

---

## ⚙️ Usage

Run the script from your terminal using `python3` or by directly executing it if you've made it executable.

**Basic Command:**
```bash
sudo pyhton3 vpn_finder.py <target_domain>
