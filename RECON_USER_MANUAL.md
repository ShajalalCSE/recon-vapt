# Recon Tools — User Manual

**AI Red Team Harness v3 · Kali Linux Reconnaissance Integration**
_Authorised lab / owned-infrastructure use only_

---

## Table of Contents

1. [Quick Reference](#1-quick-reference)
2. [Setup & Installation](#2-setup--installation)
3. [How to Run Tools](#3-how-to-run-tools)
4. [Network Scanning — nmap, masscan](#4-network-scanning--nmap-masscan)
5. [DNS Reconnaissance — nslookup, dig, dnsrecon, dnsx, fierce, dnsenum](#5-dns-reconnaissance--nslookup-dig-dnsrecon-dnsx-fierce-dnsenum)
6. [Subdomain Enumeration — subfinder, amass, assetfinder, gobuster dns](#6-subdomain-enumeration--subfinder-amass-assetfinder-gobuster-dns)
7. [Web Fuzzing — ffuf, gobuster, feroxbuster, dirb, dirsearch, wfuzz](#7-web-fuzzing--ffuf-gobuster-feroxbuster-dirb-dirsearch-wfuzz)
8. [Web Fingerprinting — whatweb, wafw00f, nikto, httpx](#8-web-fingerprinting--whatweb-wafw00f-nikto-httpx)
9. [OSINT — whois, theHarvester](#9-osint--whois-theharvester)
10. [Historical URLs — gau, waybackurls](#10-historical-urls--gau-waybackurls)
11. [Vulnerability Scanning — nuclei](#11-vulnerability-scanning--nuclei)
12. [SMB / Windows Recon — enum4linux, smbmap](#12-smb--windows-recon--enum4linux-smbmap)
13. [Web Crawling — katana](#13-web-crawling--katana)
14. [Useful Combinations](#14-useful-combinations)
15. [Enabling Extra Tools in Config](#15-enabling-extra-tools-in-config)
16. [Output & Reports](#16-output--reports)
17. [Troubleshooting](#17-troubleshooting)
18. [Agentic Mode — run_agent.py](#18-agentic-mode--run_agentpy)
19. [Exploit Intelligence Engine](#19-exploit-intelligence-engine)
20. [MITRE ATT&CK Chain Analysis](#20-mitre-attck-chain-analysis)

---

## 1. Quick Reference

### Run via project

```bash
# List all 29 supported tools
python run_recon.py --list-tools

# Run ALL default recon tools
python run_recon.py --target http://TARGET

# Run specific tools only
python run_recon.py --target http://TARGET --tools TOOL1,TOOL2

# Save to a custom output directory
python run_recon.py --target http://TARGET --output reports/recon/pass1

# Enable verbose/debug output
python run_recon.py --target http://TARGET --verbose
```

### Agentic mode (autonomous, all-in-one)

```bash
# Agent chooses tools automatically + adds exploit lookup + MITRE ATT&CK chains
python run_agent.py --target http://TARGET

# Cap iterations for a faster run
python run_agent.py --target http://TARGET --max-iter 5 --verbose
```

> For web vulnerability scanning (SQLi, XSS, IDOR, etc.) use `run_vapt.py` separately.
> For exploit intelligence and ATT&CK chain analysis see §18–20 of this manual.

### All 29 tools at a glance

| #   | Tool           | Category     | Default |
| --- | -------------- | ------------ | ------- |
| 1   | `nmap`         | Network Scan | yes     |
| 2   | `masscan`      | Network Scan | no      |
| 3   | `nslookup`     | DNS          | yes     |
| 4   | `dig`          | DNS          | yes     |
| 5   | `dnsrecon`     | DNS          | yes     |
| 6   | `dnsx`         | DNS          | no      |
| 7   | `fierce`       | DNS          | no      |
| 8   | `dnsenum`      | DNS          | no      |
| 9   | `subfinder`    | Subdomain    | yes     |
| 10  | `amass`        | Subdomain    | no      |
| 11  | `assetfinder`  | Subdomain    | no      |
| 12  | `ffuf`         | Web Fuzz     | yes     |
| 13  | `gobuster`     | Web Fuzz     | yes     |
| 14  | `feroxbuster`  | Web Fuzz     | no      |
| 15  | `dirb`         | Web Fuzz     | no      |
| 16  | `dirsearch`    | Web Fuzz     | no      |
| 17  | `wfuzz`        | Web Fuzz     | no      |
| 18  | `whatweb`      | Fingerprint  | yes     |
| 19  | `wafw00f`      | Fingerprint  | yes     |
| 20  | `nikto`        | Fingerprint  | yes     |
| 21  | `httpx`        | Fingerprint  | no      |
| 22  | `whois`        | OSINT        | yes     |
| 23  | `theharvester` | OSINT        | no      |
| 24  | `gau`          | Historical   | no      |
| 25  | `waybackurls`  | Historical   | no      |
| 26  | `nuclei`       | Vuln Scan    | yes     |
| 27  | `enum4linux`   | SMB          | no      |
| 28  | `smbmap`       | SMB          | no      |
| 29  | `katana`       | Crawl        | no      |

> **Default = yes** tools run automatically if installed in PATH. **Default = no** tools must be specified with `--tools` or enabled in `config/web_vapt.yaml`.

---

## 2. Setup & Installation

### Step 1 — Create the lab safety marker

```bash
python run_recon.py --create-lab-marker
```

### Step 2 — Add your target to the allowlist

Edit `config/safety.yaml`:

```yaml
web_vapt:
  allowed_urls:
    - "http://192.168.0.107"
    - "http://192.168.0.107/dvwa"
    - "http://target.lab"
```

### Step 3 — Install tools (Kali Linux)

```bash
# Core recon tools
sudo apt update
sudo apt install -y nmap masscan dnsutils dnsrecon dnsenum \
  fierce whatweb wafw00f nikto whois enum4linux smbmap dirb wfuzz \
  theharvester

# Go-based tools (projectdiscovery suite)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/OJ/gobuster/v3@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest

# feroxbuster
sudo apt install -y feroxbuster
# or
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | sudo bash

# dirsearch
sudo apt install -y dirsearch
# or
git clone https://github.com/maurosoria/dirsearch.git /opt/dirsearch

# amass
go install -v github.com/owasp-amass/amass/v4/...@master
# or
sudo apt install -y amass

# SecLists wordlists (required for most fuzzers)
sudo apt install -y seclists
```

### Step 4 — Verify installations

```bash
python run_recon.py --list-tools

# Or check each binary manually
which nmap subfinder ffuf gobuster dnsrecon wafw00f nikto nuclei whatweb whois
```

---

## 3. How to Run Tools

### Syntax

```
python run_recon.py --target URL [--tools TOOL1,TOOL2,...] [OPTIONS]
```

### Options

| Flag                  | What it does                                                  |
| --------------------- | ------------------------------------------------------------- |
| `--target URL`        | Target URL or IP (must be in config/safety.yaml allowlist)    |
| `--tools TOOL1,TOOL2` | Run only these specific tools (omit for default set)          |
| `--list-tools`        | Print all 29 tools with categories and exit                   |
| `--output DIR`        | Save reports to a custom directory (default: `reports/recon`) |
| `--verbose`           | Show DEBUG output including each tool's raw command           |
| `--create-lab-marker` | Create `.lab_mode_enabled` safety marker and exit             |

### Examples

```bash
# Default set of tools (nmap, nslookup, dig, subfinder, ffuf, gobuster,
#                        whatweb, wafw00f, nikto, nuclei, whois)
python run_recon.py --target http://192.168.0.107

# Only nmap and whatweb
python run_recon.py --target http://192.168.0.107 --tools nmap,whatweb

# Save to a named output folder
python run_recon.py --target http://192.168.0.107 --output reports/recon/lab1

# Debug mode — see every tool command and raw output
python run_recon.py --target http://192.168.0.107 --tools nmap --verbose
```

---

## 4. Network Scanning — nmap, masscan

### Via run_recon.py

```bash
# nmap — service detection + NSE scripts
python run_recon.py --target http://192.168.0.107 --tools nmap

# masscan — fast port discovery
python run_recon.py --target http://192.168.0.107 --tools masscan

# Both together
python run_recon.py --target http://192.168.0.107 --tools nmap,masscan
```

### Direct Kali commands

```bash
# Standard scan — service + version detection
nmap -T4 -sV -sC -p 1-10000 --open 192.168.0.107

# With OS detection (requires sudo)
sudo nmap -T4 -sV -sC -O -p 1-10000 --open 192.168.0.107

# Full port range
sudo nmap -T4 -sV -p- --open 192.168.0.107

# Specific ports only (faster)
nmap -T4 -sV -p 21,22,80,443,445,1433,3306,3389,8080,8443 192.168.0.107

# HTTP-focused NSE scripts
nmap -T4 --script http-enum,http-headers,http-methods,http-auth,http-title \
  -p 80,443,8080,8443 192.168.0.107

# SSL/TLS audit
nmap -T4 --script ssl-enum-ciphers,ssl-heartbleed,ssl-poodle \
  -p 443,8443 192.168.0.107

# SMB vulnerability check
sudo nmap -T4 --script smb-vuln-ms17-010,smb-security-mode \
  -p 445 192.168.0.107

# UDP scan (top ports)
sudo nmap -sU --top-ports 100 192.168.0.107

# Save output to file
nmap -T4 -sV -oN reports/nmap_scan.txt -oX reports/nmap_scan.xml 192.168.0.107

# Aggressive scan (OS, version, scripts, traceroute)
sudo nmap -A -T4 192.168.0.107

# masscan — full port sweep
sudo masscan 192.168.0.107 -p 1-65535 --rate 1000

# masscan — faster
sudo masscan 192.168.0.107 -p 1-65535 --rate 10000

# masscan — specific port ranges
sudo masscan 192.168.0.107 -p 80,443,8080-8090 --rate 500

# masscan — save JSON output
sudo masscan 192.168.0.107 -p 1-65535 --rate 1000 -oJ reports/masscan.json
```

### Config adjustments (`config/web_vapt.yaml`)

```yaml
tools:
  nmap:
    enabled: true
    port_range: "1-65535"      # full sweep (slower)
    timing_template: "T3"      # T3 = normal, quieter than T4
    os_detection: false        # set false if no sudo
  masscan:
    enabled: true
    port_range: "1-65535"
    rate: 5000
```

---

## 5. DNS Reconnaissance — nslookup, dig, dnsrecon, dnsx, fierce, dnsenum

### Via run_recon.py

```bash
# nslookup — A, AAAA, MX, NS, TXT, CNAME, SOA
python run_recon.py --target http://target.lab --tools nslookup

# dig — full records + AXFR zone transfer attempt
python run_recon.py --target http://target.lab --tools dig

# dnsrecon — comprehensive enum (std, SRV, brute, AXFR)
python run_recon.py --target http://target.lab --tools dnsrecon

# dnsx — fast multi-type resolver
python run_recon.py --target http://target.lab --tools dnsx

# fierce — DNS brute force + zone walk
python run_recon.py --target http://target.lab --tools fierce

# dnsenum — subdomain brute force via DNS
python run_recon.py --target http://target.lab --tools dnsenum

# All DNS tools in one run
python run_recon.py --target http://target.lab \
  --tools nslookup,dig,dnsrecon,dnsx,fierce,dnsenum
```

### Direct Kali commands

```bash
# nslookup — query each record type
nslookup -type=A target.lab
nslookup -type=AAAA target.lab
nslookup -type=MX target.lab
nslookup -type=NS target.lab
nslookup -type=TXT target.lab
nslookup -type=CNAME target.lab
nslookup -type=SOA target.lab

# nslookup — against a specific DNS server
nslookup -type=A target.lab 8.8.8.8

# dig — clean output per record type
dig +noall +answer A target.lab
dig +noall +answer AAAA target.lab
dig +noall +answer MX target.lab
dig +noall +answer NS target.lab
dig +noall +answer TXT target.lab
dig +noall +answer ANY target.lab

# dig — zone transfer attempt (AXFR)
dig AXFR target.lab
dig AXFR target.lab @ns1.target.lab

# dig — reverse DNS lookup
dig -x 192.168.0.107

# dig — against specific resolver
dig A target.lab @1.1.1.1

# dnsrecon — standard scan
dnsrecon -d target.lab

# dnsrecon — all scan types
dnsrecon -d target.lab -t std,brt,srv,axfr

# dnsrecon — brute force with custom wordlist
dnsrecon -d target.lab -t brt \
  -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# dnsrecon — save to JSON
dnsrecon -d target.lab -t std --json /tmp/dnsrecon.json

# dnsrecon — reverse lookup range
dnsrecon -r 192.168.0.0/24

# dnsx — multi-type fast resolution
dnsx -d target.lab -a -aaaa -mx -ns -txt -json -silent
echo "target.lab" | dnsx -a -mx -ns -txt -json -silent

# dnsx — resolve a list of subdomains
subfinder -d target.lab -silent | dnsx -a -json -silent

# dnsx — bruteforce subdomains
dnsx -d target.lab \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -silent

# fierce — brute force subdomains
fierce --domain target.lab
fierce --domain target.lab --subdomains-file /usr/share/fierce/hosts.txt

# dnsenum — full enumeration
dnsenum --nocolor --noreverse target.lab

# dnsenum — with brute force wordlist
dnsenum --nocolor target.lab \
  -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# host — simple DNS utility
host target.lab
host -t MX target.lab
host -t NS target.lab
host -l target.lab ns1.target.lab   # zone transfer

# whois IP lookup
whois 192.168.0.107
```

### Config adjustments

```yaml
tools:
  dnsrecon:
    enabled: true
    scan_type: "std,brt,srv,axfr"
  dnsx:
    enabled: true
  fierce:
    enabled: true
  dnsenum:
    enabled: true
```

---

## 6. Subdomain Enumeration — subfinder, amass, assetfinder, gobuster dns

### Via run_recon.py

```bash
# subfinder — passive (10+ OSINT sources)
python run_recon.py --target http://target.lab --tools subfinder

# amass — deep enumeration (enable in config first)
python run_recon.py --target http://target.lab --tools amass

# assetfinder — fast quick lookup
python run_recon.py --target http://target.lab --tools assetfinder

# gobuster dns mode — wordlist brute force
python run_recon.py --target http://target.lab --tools gobuster

# All subdomain tools together
python run_recon.py --target http://target.lab \
  --tools subfinder,amass,assetfinder,gobuster

# Combined subdomain + DNS recon
python run_recon.py --target http://target.lab \
  --tools subfinder,amass,assetfinder,dnsrecon,fierce,dnsenum,nslookup,dig
```

### Direct Kali commands

```bash
# subfinder — passive enumeration
subfinder -d target.lab -silent
subfinder -d target.lab -silent -o subdomains.txt

# subfinder — with specific sources
subfinder -d target.lab -silent \
  -sources crtsh,hackertarget,alienvault,virustotal

# subfinder — recursive
subfinder -d target.lab -silent -recursive

# subfinder — all sources, verbose
subfinder -d target.lab -all -v

# subfinder — rate limited
subfinder -d target.lab -silent -rate-limit 10

# amass — passive mode
amass enum -passive -d target.lab
amass enum -passive -d target.lab -o amass_subs.txt

# amass — active mode (more thorough, more noise)
amass enum -active -d target.lab

# amass — intel (WHOIS, ASN data)
amass intel -d target.lab -whois

# amass — network mapping
amass intel -cidr 192.168.0.0/24

# assetfinder — quick passive lookup
assetfinder --subs-only target.lab
assetfinder --subs-only target.lab | tee assetfinder_subs.txt

# gobuster — DNS brute force
gobuster dns -d target.lab \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -t 30 --no-error -q

# gobuster — DNS with larger wordlist
gobuster dns -d target.lab \
  -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt \
  -t 50 -q

# gobuster — DNS save output
gobuster dns -d target.lab \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -t 30 -o reports/gobuster_dns.txt

# Combine subfinder + dnsx for live host verification
subfinder -d target.lab -silent | dnsx -a -silent

# Combine all tools and deduplicate
(subfinder -d target.lab -silent; \
 assetfinder --subs-only target.lab; \
 amass enum -passive -d target.lab) | sort -u | tee all_subdomains.txt

# Filter live subdomains
cat all_subdomains.txt | httpx -silent | tee live_subdomains.txt
```

### Config adjustments

```yaml
tools:
  subfinder:
    enabled: true
    recursive: true
    sources:
      - crtsh
      - hackertarget
      - alienvault
      - virustotal
      - certspotter
  amass:
    enabled: true
    mode: "passive"
  assetfinder:
    enabled: true
```

---

## 7. Web Fuzzing — ffuf, gobuster, feroxbuster, dirb, dirsearch, wfuzz

### Via run_recon.py

```bash
# ffuf — fast fuzzing
python run_recon.py --target http://192.168.0.107/dvwa --tools ffuf

# gobuster dir + dns + vhost
python run_recon.py --target http://192.168.0.107/dvwa --tools gobuster

# feroxbuster — recursive
python run_recon.py --target http://192.168.0.107/dvwa --tools feroxbuster

# dirb — classic
python run_recon.py --target http://192.168.0.107/dvwa --tools dirb

# dirsearch
python run_recon.py --target http://192.168.0.107/dvwa --tools dirsearch

# wfuzz
python run_recon.py --target http://192.168.0.107/dvwa --tools wfuzz

# All fuzzers together
python run_recon.py --target http://192.168.0.107/dvwa \
  --tools ffuf,gobuster,feroxbuster,dirb,dirsearch,wfuzz
```

### Direct Kali commands — ffuf

```bash
# Basic directory fuzzing
ffuf -u http://192.168.0.107/dvwa/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200,301,302,403 -t 50

# With file extensions
ffuf -u http://192.168.0.107/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -e .php,.html,.txt,.bak,.zip,.sql \
  -mc 200,301,302,401,403 -t 50

# With cookies (authenticated)
ffuf -u http://192.168.0.107/dvwa/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -H "Cookie: PHPSESSID=abc123; security=low" \
  -mc 200,301,302,403 -t 50

# Filter by response size (exclude 4096 byte responses)
ffuf -u http://192.168.0.107/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -fs 4096 -t 50

# POST parameter fuzzing
ffuf -u http://192.168.0.107/login.php \
  -X POST -d "username=FUZZ&password=admin" \
  -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -mc 200,302

# VHost fuzzing
ffuf -u http://192.168.0.107 \
  -H "Host: FUZZ.target.lab" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs 4096

# Save output to JSON
ffuf -u http://192.168.0.107/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200,301,302,403 -o reports/ffuf_output.json -of json

# Recursive fuzzing
ffuf -u http://192.168.0.107/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -recursion -recursion-depth 2 -mc 200,301,302,403

# Rate limited fuzzing
ffuf -u http://192.168.0.107/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -rate 50 -mc 200,301,302,403
```

### Direct Kali commands — gobuster

```bash
# Directory brute force
gobuster dir \
  -u http://192.168.0.107/dvwa \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x php,html,txt,js,json,bak,zip \
  -s 200,301,302,403 \
  -t 30 --no-error -q

# With authentication cookie
gobuster dir \
  -u http://192.168.0.107/dvwa \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -c "PHPSESSID=abc123; security=low" \
  -t 30 --no-error

# Large wordlist
gobuster dir \
  -u http://192.168.0.107 \
  -w /usr/share/seclists/Discovery/Web-Content/big.txt \
  -x php,html,txt -t 50

# DNS brute force
gobuster dns \
  -d target.lab \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -t 30 --no-error -q

# VHost discovery
gobuster vhost \
  -u http://192.168.0.107 \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -t 30 --no-error -q

# Save output
gobuster dir \
  -u http://192.168.0.107 \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -o reports/gobuster_dir.txt -t 30
```

### Direct Kali commands — feroxbuster

```bash
# Basic recursive scan
feroxbuster --url http://192.168.0.107 \
  --wordlist /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
  --threads 50 --quiet

# With file extensions
feroxbuster --url http://192.168.0.107 \
  --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt \
  --extensions php,html,txt,bak \
  --threads 50 --quiet

# With cookie
feroxbuster --url http://192.168.0.107/dvwa \
  --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt \
  --cookies "PHPSESSID=abc123; security=low" \
  --threads 30 --quiet

# Limit recursion depth
feroxbuster --url http://192.168.0.107 \
  --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt \
  --depth 2 --threads 50 --quiet

# Save JSON output
feroxbuster --url http://192.168.0.107 \
  --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt \
  --output reports/feroxbuster.json --json --quiet
```

### Direct Kali commands — dirb, dirsearch, wfuzz

```bash
# dirb — basic
dirb http://192.168.0.107 /usr/share/dirb/wordlists/common.txt

# dirb — with cookie
dirb http://192.168.0.107/dvwa /usr/share/dirb/wordlists/common.txt \
  -H "Cookie: PHPSESSID=abc123"

# dirb — custom extensions
dirb http://192.168.0.107 /usr/share/dirb/wordlists/common.txt -X .php,.txt,.bak

# dirsearch
python3 /opt/dirsearch/dirsearch.py -u http://192.168.0.107 -e php,html,txt

# dirsearch — with cookie
python3 /opt/dirsearch/dirsearch.py -u http://192.168.0.107/dvwa \
  --cookie "PHPSESSID=abc123; security=low"

# dirsearch — save report
python3 /opt/dirsearch/dirsearch.py -u http://192.168.0.107 \
  --format json -o reports/dirsearch.json

# wfuzz — directory fuzzing
wfuzz -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  --hc 404 http://192.168.0.107/FUZZ

# wfuzz — with cookie
wfuzz -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -H "Cookie: PHPSESSID=abc123" \
  --hc 404 http://192.168.0.107/FUZZ

# wfuzz — POST parameter brute force
wfuzz -w /usr/share/seclists/Passwords/Leaked-Databases/rockyou-40.txt \
  -d "username=admin&password=FUZZ" \
  --hc 200 http://192.168.0.107/dvwa/login.php

# wfuzz — multiple payload positions
wfuzz -w users.txt -w passwords.txt \
  -d "user=FUZZ&pass=FUZ2Z" \
  --hc 302 http://192.168.0.107/login.php
```

### Config adjustments

```yaml
tools:
  ffuf:
    enabled: true
    wordlist: "/usr/share/seclists/Discovery/Web-Content/big.txt"
    threads: 100
    matcher_status: "200,204,301,302,307,401,403"
  gobuster:
    enabled: true
    wordlist: "/usr/share/seclists/Discovery/Web-Content/common.txt"
    status_codes: "200,204,301,302,307,401,403"
    extensions: "php,html,txt,js,json,xml,bak,zip"
    threads: 50
  feroxbuster:
    enabled: true
    wordlist: "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt"
    threads: 50
  dirb:
    enabled: true
    wordlist: "/usr/share/dirb/wordlists/common.txt"
  dirsearch:
    enabled: true
  wfuzz:
    enabled: true
    wordlist: "/usr/share/seclists/Discovery/Web-Content/common.txt"
```

---

## 8. Web Fingerprinting — whatweb, wafw00f, nikto, httpx

### Via run_recon.py

```bash
# whatweb — technology and CMS detection
python run_recon.py --target http://192.168.0.107/dvwa --tools whatweb

# wafw00f — WAF detection
python run_recon.py --target http://192.168.0.107/dvwa --tools wafw00f

# nikto — web server vulnerability scan
python run_recon.py --target http://192.168.0.107/dvwa --tools nikto

# httpx — HTTP probing
python run_recon.py --target http://192.168.0.107/dvwa --tools httpx

# All fingerprinting tools together
python run_recon.py --target http://192.168.0.107/dvwa \
  --tools whatweb,wafw00f,nikto,httpx
```

### Direct Kali commands — whatweb

```bash
# Basic tech fingerprint
whatweb http://192.168.0.107/dvwa

# Aggressive — aggression level 3
whatweb -a 3 http://192.168.0.107

# JSON output
whatweb --log-json=reports/whatweb.json http://192.168.0.107

# Verbose output
whatweb -v http://192.168.0.107

# With cookies
whatweb --cookie "PHPSESSID=abc123" http://192.168.0.107/dvwa

# Scan a list of hosts
whatweb --input-file=hosts.txt --log-json=reports/whatweb_bulk.json
```

### Direct Kali commands — wafw00f

```bash
# WAF detection
wafw00f http://192.168.0.107

# Test all WAFs (more thorough)
wafw00f http://192.168.0.107 -a

# JSON output
wafw00f http://192.168.0.107 -o reports/wafw00f.json -f json

# Verbose
wafw00f http://192.168.0.107 -v

# Proxy through Burp
wafw00f http://192.168.0.107 --proxy http://127.0.0.1:8080
```

### Direct Kali commands — nikto

```bash
# Basic scan
nikto -h http://192.168.0.107

# Full scan with all plugins
nikto -h http://192.168.0.107 -Plugins @@ALL

# All tuning options (x = everything)
nikto -h http://192.168.0.107 -Tuning x

# With session cookie
nikto -h http://192.168.0.107/dvwa \
  -C "PHPSESSID=abc123; security=low"

# JSON output
nikto -h http://192.168.0.107 -Format json -o reports/nikto.json

# HTML output
nikto -h http://192.168.0.107 -Format html -o reports/nikto.html

# Scan specific port
nikto -h 192.168.0.107 -port 8080

# HTTPS scan
nikto -h https://target.com -ssl

# Through proxy (Burp Suite)
nikto -h http://192.168.0.107 -useproxy http://127.0.0.1:8080

# Scan with HTTP Basic Auth
nikto -h http://192.168.0.107 -id admin:password

# Maximum scan time (seconds)
nikto -h http://192.168.0.107 -maxtime 300
```

### Direct Kali commands — httpx

```bash
# Basic probe
httpx -u http://192.168.0.107 -title -tech-detect -status-code -json

# Probe with web server detection
httpx -u http://192.168.0.107 -title -web-server -content-length -json

# Probe a list of URLs
cat urls.txt | httpx -silent -title -status-code

# Follow redirects
httpx -u http://192.168.0.107 -follow-redirects -json

# Tech detection
httpx -u http://192.168.0.107 -tech-detect -json

# Screenshot pages (requires Chrome/Chromium)
httpx -u http://192.168.0.107 -screenshot -srd reports/screenshots

# Bulk probe from subfinder
subfinder -d target.lab -silent | httpx -silent -title -status-code
```

---

## 9. OSINT — whois, theHarvester

### Via run_recon.py

```bash
# whois — domain registration info
python run_recon.py --target http://target.lab --tools whois

# theHarvester — emails, subdomains, IPs
# (enable in config/web_vapt.yaml: theharvester.enabled: true)
python run_recon.py --target http://target.lab --tools theharvester

# Both together
python run_recon.py --target http://target.lab --tools whois,theharvester
```

### Direct Kali commands — whois

```bash
# Domain lookup
whois target.lab
whois target.com

# IP lookup
whois 192.168.0.107
whois 8.8.8.8

# Save output
whois target.com > reports/whois_target.txt

# Query specific WHOIS server
whois -h whois.arin.net 8.8.8.8
```

### Direct Kali commands — theHarvester

```bash
# Basic OSINT harvest
theHarvester -d target.com -b google,bing,duckduckgo

# All available sources
theHarvester -d target.com -b all -l 500

# Specific sources
theHarvester -d target.com \
  -b google,bing,duckduckgo,linkedin,hackertarget,crtsh \
  -l 500

# With DNS brute force
theHarvester -d target.com -b google -n

# HTML report
theHarvester -d target.com -b google,bing \
  -f reports/theharvester_report

# Limited results
theHarvester -d target.com -b google -l 100
```

### Config adjustments

```yaml
tools:
  theharvester:
    enabled: true
    sources: "google,bing,duckduckgo,linkedin,hackertarget,crtsh"
    limit: 500
  whois:
    enabled: true
```

---

## 10. Historical URLs — gau, waybackurls

### Via run_recon.py

```bash
# gau — Wayback + Common Crawl + OTX
# (enable in config/web_vapt.yaml: gau.enabled: true)
python run_recon.py --target http://target.lab --tools gau

# waybackurls — Wayback Machine
python run_recon.py --target http://target.lab --tools waybackurls

# Both together with subfinder
python run_recon.py --target http://target.lab \
  --tools gau,waybackurls,subfinder
```

### Direct Kali commands

```bash
# gau — fetch all URLs
gau target.com

# gau — exclude media files
gau --blacklist png,jpg,gif,jpeg,css,woff,svg,ico target.com

# gau — include subdomains
gau --subs target.com

# gau — JSON output
gau --json target.com > reports/gau_output.json

# gau — filter for injection points
gau target.com | grep -E "=http|=https|redirect|url|uri|dest"

# waybackurls — basic
echo "target.com" | waybackurls

# waybackurls — save to file
echo "target.com" | waybackurls > reports/wayback_urls.txt

# Filter for interesting file types
echo "target.com" | waybackurls | \
  grep -E "\.(php|asp|aspx|jsp|json|xml|env|bak|sql)$"

# Find parameters
echo "target.com" | waybackurls | grep "?" | sort -u

# Deduplicate and sort
(gau target.com; echo "target.com" | waybackurls) | \
  sort -u > all_historical_urls.txt

# Feed to httpx for live checking
echo "target.com" | waybackurls | \
  httpx -silent -status-code | grep "200" | tee live_urls.txt
```

### Config adjustments

```yaml
tools:
  gau:
    enabled: true
  waybackurls:
    enabled: true
```

---

## 11. Vulnerability Scanning — nuclei

### Via run_recon.py

```bash
# nuclei — CVE + misconfiguration templates
python run_recon.py --target http://192.168.0.107/dvwa --tools nuclei

# Combine nuclei with other recon
python run_recon.py --target http://192.168.0.107/dvwa \
  --tools nmap,nikto,nuclei,whatweb
```

### Direct Kali commands

```bash
# Basic scan — critical and high only
nuclei -u http://192.168.0.107/dvwa -severity high,critical -silent

# All severities
nuclei -u http://192.168.0.107/dvwa \
  -severity low,medium,high,critical -json -silent

# Specific template categories
nuclei -u http://192.168.0.107 -t cves/ -json -silent
nuclei -u http://192.168.0.107 -t misconfiguration/ -json -silent
nuclei -u http://192.168.0.107 -t vulnerabilities/ -json -silent
nuclei -u http://192.168.0.107 -t exposures/ -json -silent
nuclei -u http://192.168.0.107 -t default-logins/ -json -silent

# Specific template tags
nuclei -u http://192.168.0.107 -tags sqli,xss,lfi -json -silent
nuclei -u http://192.168.0.107 -tags rce -severity critical -json -silent
nuclei -u http://192.168.0.107 -tags wordpress -json -silent

# Custom rate limit
nuclei -u http://192.168.0.107 -t cves/ -rl 50 -c 25 -json -silent

# With authentication cookie
nuclei -u http://192.168.0.107/dvwa \
  -H "Cookie: PHPSESSID=abc123; security=low" \
  -json -silent

# Scan a list of URLs
nuclei -l urls.txt -t cves/ -severity high,critical -json -silent

# Save JSON output
nuclei -u http://192.168.0.107 \
  -t cves/ -t misconfiguration/ \
  -json -o reports/nuclei_findings.json -silent

# Update templates
nuclei -update-templates

# Dry run (show what would be tested)
nuclei -u http://192.168.0.107 -t cves/ -dry-run
```

### Config adjustments

```yaml
tools:
  nuclei:
    enabled: true
    templates:
      - "cves/"
      - "misconfiguration/"
      - "vulnerabilities/"
      - "exposures/"
      - "default-logins/"
    severity_filter: "low,medium,high,critical"
    rate_limit: 100
    concurrency: 25
```

---

## 12. SMB / Windows Recon — enum4linux, smbmap

### Via run_recon.py

```bash
# enum4linux — users, shares, domain info
# (enable: enum4linux.enabled: true in config)
python run_recon.py --target http://192.168.0.107 --tools enum4linux

# smbmap — share permissions
python run_recon.py --target http://192.168.0.107 --tools smbmap

# Both together
python run_recon.py --target http://192.168.0.107 \
  --tools enum4linux,smbmap

# Full network recon including SMB
python run_recon.py --target http://192.168.0.107 \
  --tools nmap,enum4linux,smbmap
```

### Direct Kali commands — enum4linux

```bash
# Full enumeration
enum4linux -a 192.168.0.107

# List shares
enum4linux -S 192.168.0.107

# List users
enum4linux -U 192.168.0.107

# Get OS info
enum4linux -o 192.168.0.107

# With credentials
enum4linux -a -u admin -p password 192.168.0.107

# Save to file
enum4linux -a 192.168.0.107 > reports/enum4linux.txt

# enum4linux-ng (newer, more reliable)
enum4linux-ng -A 192.168.0.107
enum4linux-ng -A 192.168.0.107 -oY reports/enum4linux_ng.yaml
```

### Direct Kali commands — smbmap

```bash
# List shares (anonymous)
smbmap -H 192.168.0.107

# With credentials
smbmap -H 192.168.0.107 -u admin -p password

# List files in a share
smbmap -H 192.168.0.107 -r SHARENAME

# Recursive listing
smbmap -H 192.168.0.107 -R

# Domain account
smbmap -H 192.168.0.107 -d DOMAIN -u user -p password

# Additional SMB tools
smbclient -L //192.168.0.107 -N
crackmapexec smb 192.168.0.107
crackmapexec smb 192.168.0.107 --shares
crackmapexec smb 192.168.0.107 --users
```

### Config adjustments

```yaml
tools:
  enum4linux:
    enabled: true
  smbmap:
    enabled: true
```

---

## 13. Web Crawling — katana

### Via run_recon.py

```bash
# katana — JS-aware crawling
# (enable: katana.enabled: true in config)
python run_recon.py --target http://192.168.0.107/dvwa --tools katana
```

### Direct Kali commands

```bash
# Basic crawl
katana -u http://192.168.0.107/dvwa -silent

# With JS crawling enabled
katana -u http://192.168.0.107/dvwa -jc -silent

# Custom depth
katana -u http://192.168.0.107/dvwa -d 5 -jc -silent

# With cookies
katana -u http://192.168.0.107/dvwa \
  -H "Cookie: PHPSESSID=abc123; security=low" \
  -jc -d 3 -silent

# JSON output
katana -u http://192.168.0.107/dvwa -jc -jsonl -silent

# Headless browser mode
katana -u http://192.168.0.107/dvwa -headless -jc -d 3

# Save output
katana -u http://192.168.0.107/dvwa -jc -o reports/katana_urls.txt

# Full feature crawl
katana -u http://192.168.0.107/dvwa \
  -jc -d 5 -aff -kf all \
  -H "Cookie: PHPSESSID=abc123; security=low" \
  -jsonl -o reports/katana_full.json
```

### Config adjustments

```yaml
tools:
  katana:
    enabled: true
    depth: 5
```

---

## 14. Useful Combinations

### Quick fingerprint (30 seconds)

```bash
python run_recon.py --target http://192.168.0.107 \
  --tools nmap,whatweb,wafw00f,whois
```

### Full DNS + subdomain recon

```bash
python run_recon.py --target http://target.lab \
  --tools nslookup,dig,dnsrecon,subfinder,gobuster,assetfinder
```

### Directory discovery only

```bash
python run_recon.py --target http://192.168.0.107/dvwa \
  --tools ffuf,gobuster,nikto
```

### Full OSINT package

```bash
# Enable gau, waybackurls, theharvester in config/web_vapt.yaml first
python run_recon.py --target http://target.com \
  --tools whois,theharvester,subfinder,amass,gau,waybackurls
```

### Network + service recon (internal lab)

```bash
python run_recon.py --target http://192.168.0.107 \
  --tools nmap,masscan,enum4linux,smbmap
```

### Full recon phase before vulnerability scan

```bash
# Step 1 — full recon, save to dedicated directory
python run_recon.py --target http://192.168.0.107/dvwa \
  --output reports/recon/pass1

# Step 2 — web vuln scan separately
python run_vapt.py -r burp_request.txt \
  --output reports/web/pass1
```

### Run ALL 29 tools (enable all in config first — be patient)

```bash
python run_recon.py --target http://target.lab \
  --tools nmap,masscan,nslookup,dig,dnsrecon,dnsx,fierce,dnsenum,\
subfinder,amass,assetfinder,ffuf,gobuster,feroxbuster,dirb,dirsearch,\
wfuzz,whatweb,wafw00f,nikto,httpx,whois,theharvester,gau,waybackurls,\
nuclei,enum4linux,smbmap,katana
```

### DVWA full recon scan

```bash
python run_recon.py --target http://192.168.0.107/dvwa \
  --tools nmap,nslookup,ffuf,gobuster,whatweb,wafw00f,nikto,nuclei
```

---

## 15. Enabling Extra Tools in Config

Edit `config/web_vapt.yaml` to enable tools that are off by default. After saving, run without `--tools` to use everything that is `enabled: true`:

```bash
python run_recon.py --target http://192.168.0.107
```

```yaml
tools:
  masscan:
    enabled: true
  dnsx:
    enabled: true
  fierce:
    enabled: true
  dnsenum:
    enabled: true
  amass:
    enabled: true
    mode: "passive"
  assetfinder:
    enabled: true
  feroxbuster:
    enabled: true
  dirb:
    enabled: true
  dirsearch:
    enabled: true
  wfuzz:
    enabled: true
  httpx:
    enabled: true
  theharvester:
    enabled: true
    sources: "google,bing,duckduckgo,linkedin,hackertarget"
    limit: 500
  gau:
    enabled: true
  waybackurls:
    enabled: true
  enum4linux:
    enabled: true
  smbmap:
    enabled: true
  katana:
    enabled: true
    depth: 3
```

---

## 16. Output & Reports

### Terminal output after scan

```
==========================================================
  RECON COMPLETE
==========================================================
  Report ID   : recon_20260612_140312
  Target      : http://192.168.0.107
  Duration    : 62s
  Tools run   : 8
    dig, ffuf, gobuster, nikto, nmap, nslookup, whatweb, whois
  Skipped     : dnsrecon, nuclei, wafw00f

  Open Ports  : 80/tcp (http), 443/tcp (https), 3306/tcp (mysql)
  Subdomains  : 3  (dev.target.lab, api.target.lab, ...)
  Web Paths   : 47 discovered
  Tech Stack  : Apache, PHP, MySQL, WordPress
  WAF         : ModSecurity
  DNS         : A(2), MX(1), NS(3), TXT(4)

  Findings    : 5
    HIGH      : 1
    MEDIUM    : 2
    LOW       : 1
    INFO      : 1

  JSON Report : reports/recon/recon_20260612_140312.json
  MD Report   : reports/recon/recon_20260612_140312.md
==========================================================
```

When Ctrl+C is pressed, the report filename is prefixed with `PARTIAL_`:

```
  JSON Report : reports/recon/recon_PARTIAL_20260612_140312.json
  MD Report   : reports/recon/recon_PARTIAL_20260612_140312.md
```

### Report directory

```
reports/recon/
  recon_YYYYMMDD_HHMMSS.md       ← Human-readable Markdown
  recon_YYYYMMDD_HHMMSS.json     ← Machine-readable JSON
  recon_PARTIAL_YYYYMMDD_HHMMSS.md   ← Ctrl+C interrupted
```

### JSON report structure

```json
{
  "report_id": "recon_20260612_140312",
  "generated_at": "2026-06-12T14:03:12Z",
  "target_url": "http://192.168.0.107",
  "domain": "192.168.0.107",
  "host": "192.168.0.107",
  "port": 80,
  "interrupted": false,
  "duration_s": 62.1,
  "tools_run": ["nmap", "nslookup", "ffuf", "gobuster", "whatweb"],
  "tools_available": ["nmap", "nslookup", "ffuf", "gobuster"],
  "tools_unavailable": ["whatweb"],
  "open_ports": [
    {"port": 80, "protocol": "tcp", "state": "open", "service": "http"}
  ],
  "subdomains": ["dev.target.lab", "api.target.lab"],
  "dns_records": {"A": ["192.168.0.107"], "MX": ["mail.target.lab"]},
  "web_dirs": ["/admin", "/uploads", "/backup", "/phpmyadmin"],
  "technologies": ["Apache", "PHP", "MySQL"],
  "emails": ["admin@target.lab"],
  "waf_detected": "",
  "findings": [
    {
      "tool": "nikto",
      "category": "misconfiguration",
      "title": "X-Frame-Options header missing",
      "severity": "medium",
      "description": "...",
      "evidence": "..."
    }
  ]
}
```

### Save recon output to a named folder

```bash
python run_recon.py --target http://192.168.0.107 \
  --output reports/recon/lab1_pass1
```

### Enable verbose mode to see every tool command

```bash
python run_recon.py --target http://192.168.0.107 \
  --tools nmap,ffuf --verbose
```

---

## 17. Troubleshooting

### Tool shows as Skipped

The binary is not in PATH. Install it and verify:

```bash
which nmap           # should print /usr/bin/nmap
which subfinder      # should print ~/.go/bin/subfinder
which ffuf
which gobuster
```

Add Go bin directory to PATH if needed:

```bash
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### nmap shows "Operation not permitted"

OS detection (`-O`) and SYN scan (`-sS`) require root:

```bash
# Run with sudo
sudo python run_recon.py --target http://192.168.0.107 --tools nmap

# Or disable OS detection in config
# config/web_vapt.yaml:
#   nmap:
#     os_detection: false
```

### ffuf / gobuster find nothing

Wordlist may not exist at the configured path:

```bash
ls /usr/share/seclists/Discovery/Web-Content/common.txt

# If missing, install SecLists
sudo apt install seclists

# Or change the path in config/web_vapt.yaml
#   ffuf:
#     wordlist: "/usr/share/wordlists/dirb/common.txt"
```

### dnsrecon / subfinder return nothing on private IP

Expected — private IPs have no public DNS records. Use nmap + nslookup instead:

```bash
python run_recon.py --target http://192.168.0.107 \
  --tools nmap,nslookup,nikto,whatweb
```

### Target blocked by the allowlist

Add it to `config/safety.yaml`:

```yaml
web_vapt:
  allowed_urls:
    - "http://192.168.0.107"
    - "http://192.168.0.107/dvwa"
```

### Tool times out before finishing

Increase the tool timeout in `config/web_vapt.yaml`:

```yaml
timeouts:
  tool_execution_seconds: 300    # was 120
```

Or use faster tool options:

```yaml
tools:
  nmap:
    port_range: "80,443,8080,8443"    # fewer ports = faster
    timing_template: "T5"
  ffuf:
    threads: 200
```

### Run tools in separate passes to avoid overlap

```bash
python run_recon.py --target http://192.168.0.107 \
  --tools nmap,nslookup,whatweb \
  --output reports/recon/pass1

python run_recon.py --target http://192.168.0.107 \
  --tools ffuf,gobuster,nikto \
  --output reports/recon/pass2
```

---

---

## 18. Agentic Mode — run_agent.py

The agentic mode wraps `ReconEngine`, `ExploitEngine`, and `AttackChainBuilder` into an autonomous **ReAct loop** that decides which tools to run based on what it has already discovered.

### Quick start

```bash
# Full autonomous run
python run_agent.py --target http://192.168.0.102

# Cap iterations for a faster run
python run_agent.py --target http://192.168.0.102 --max-iter 5

# Show the agent's reasoning at every step
python run_agent.py --target http://192.168.0.102 --verbose

# Offline mode (skip NVD CVE API)
python run_agent.py --target http://192.168.0.102 --no-nvd

# Custom output folder
python run_agent.py --target http://192.168.0.102 --output reports/agent/pass1
```

### How the agent picks its next tool

| Iteration | Action | Condition |
|---|---|---|
| 1 | `initial_recon` | Always first |
| 2 | `subdomain_deep` | Subdomains found in iteration 1 |
| 3 | `web_discovery` | Technologies fingerprinted |
| 4 | `exploit_lookup` | Any findings accumulated |
| 5 | `chain_analysis` | Exploit report ready |
| 6 | `osint` | Subdomains exist |
| 7 | `vuln_scan` | Tech stack known |
| 8 | `smb_scan` | Port 445 or 139 open |

Each action feeds its results back into the shared context so later phases start with richer data.

### Comparing run_recon.py vs run_agent.py

| Feature | `run_recon.py` | `run_agent.py` |
|---|---|---|
| Tool selection | Manual (`--tools`) or default set | Automatic (rule-based planner) |
| Exploit lookup | No | Yes — searchsploit + NVD |
| MITRE ATT&CK chains | No | Yes |
| Attack narratives | No | Yes |
| MSF module hints | No | Yes |
| Iterations | Single pass | Up to `--max-iter` |
| Reports | `reports/recon/` | `reports/agent/` |

### When to use each

- **`run_recon.py --tools X,Y`** — when you know which specific tools you want and want full control
- **`run_recon.py`** (interactive) — when you want to pick from a menu of scan profiles
- **`run_agent.py`** — when you want an autonomous, full-depth assessment including exploit suggestions and attack chain mapping

---

## 19. Exploit Intelligence Engine

`modules/exploit_engine.py` is invoked by `run_agent.py` during the `exploit_lookup` phase.

### What it does

1. **Technology scan** — extracts search terms from discovered tech stack, services, and CVEs found in findings
2. **searchsploit** — calls `searchsploit --json <query>` for each term (never `shell=True`)
3. **NVD enrichment** — queries `https://services.nvd.nist.gov/rest/json/cves/2.0` for CVSS score + description
4. **MSF mapping** — matches CVEs to curated Metasploit module table

### Output per exploit match

| Field | Description |
|---|---|
| `title` | Exploit-DB title |
| `cve` | CVE identifier (if in title) |
| `cvss_score` | CVSS base score (from NVD) |
| `severity` | critical / high / medium / low |
| `exploit_type` | remote / local / dos / webapps |
| `platform` | Target platform |
| `msf_module` | Metasploit module path (if mapped) |
| `searchsploit_path` | Path to copy with `searchsploit -m` |
| `url` | Exploit-DB permalink |

### Using exploit results manually

After the agent writes a report, use the searchsploit commands directly:

```bash
# Copy exploit to current directory
searchsploit -m exploits/linux/remote/50383.py

# Examine the exploit
cat 50383.py | head -50

# Run msfconsole with module from report
msfconsole -q -x "use exploit/multi/http/apache_normalize_path_rce; set RHOSTS 192.168.0.102; exploit"
```

### NVD rate limiting

The NVD API is public but rate-limited. The engine caps enrichment at 8 CVEs per run. If you hit a rate limit:

```bash
# Add a delay by running with fewer iterations
python run_agent.py --target http://192.168.0.102 --max-iter 3

# Or disable NVD entirely
python run_agent.py --target http://192.168.0.102 --no-nvd
```

---

## 20. MITRE ATT&CK Chain Analysis

`modules/attack_chain.py` is invoked by `run_agent.py` during the `chain_analysis` phase.

### What it does

1. Maps every finding to a MITRE ATT&CK **tactic** and **technique** via a 50+ keyword lookup table
2. Deduplicates nodes by technique ID, keeping the highest-exploitability instance
3. Builds attack chains using a sliding window across the kill-chain tactic sequence
4. Generates three named scenarios automatically
5. Scores each chain and ranks them

### ATT&CK tactic ordering (kill chain)

```
Reconnaissance → Resource Development → Initial Access → Execution →
Persistence → Privilege Escalation → Defense Evasion → Credential Access →
Discovery → Lateral Movement → Collection → Exfiltration → Impact
```

### Named attack scenarios

| Scenario | Tactics | What it means |
|---|---|---|
| **Full Kill Chain** | Recon → IA → Exec → PrivEsc → LM → Impact | Complete end-to-end compromise |
| **Data Breach Path** | IA → Credential Access → Collection → Exfil | Sensitive data theft |
| **Ransomware Path** | IA → Execution → PrivEsc → Impact | Encryption + disruption |

### Chain scoring

```
score = tactic_diversity × avg_exploitability × (1 + span_bonus)
```

- `tactic_diversity` — number of distinct tactics in the chain
- `avg_exploitability` — average exploitability of all nodes (0–1, derived from severity)
- `span_bonus` — bonus for longer chains (capped at 1.5)

Higher score = more dangerous and more exploitable chain.

### Example chain output in report

```
### Chain 1: Initial Access → Execution  (score 4.8)

Impact: Remote code execution on target host.

Attack Path:
  [T1190 — Initial Access]
      ↓
  [T1059 — Execution]

Narrative:
  Step 1  [T1190 — Initial Access]
           An attacker leverages 'Exploit Public-Facing Application'
           via 'SQL Injection in login form' (severity: high, tool: sqlmap).
  Step 2  [T1059 — Execution]
           next leverages 'Command and Scripting Interpreter'
           via 'Command Injection in ping param' (severity: critical, tool: nikto).

Impact: Remote code execution on target host.
```

### Reading the attack surface score

The **attack surface score** (0–10) summarises overall risk:

```
attack_surface_score = (tactic_coverage / 13) × 10 × avg_exploitability
```

| Score | Risk level |
|---|---|
| 8–10 | Critical — immediate remediation required |
| 6–8 | High — significant attack surface |
| 4–6 | Medium — multiple entry points found |
| 2–4 | Low — limited attack surface |
| 0–2 | Minimal — informational findings only |

---

_AI Red Team Harness v3 · Recon Tools Manual_
_Authorised lab / owned-infrastructure use only_
_Python 3.11+ · Kali Linux_
