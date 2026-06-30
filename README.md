# Attack Surface Discovery Agent

An automated OSINT recon tool that maps the external attack surface of a target domain.
Give it a domain, it returns subdomains, live hosts, open ports, and tech stack — all in one run.

## What it does

- Subdomain enumeration via VirusTotal passive DNS and crt.sh certificate transparency logs
- DNS resolution to filter live hosts from dead ones
- Port scanning across 18 common ports (HTTP, SSH, RDP, databases, etc.)
- Tech stack fingerprinting from HTTP headers and HTML body signatures
- Saves a full JSON report for every scan

## Example output

```
[*] Starting recon on: vulnweb.com

[*] Enumerating subdomains for vulnweb.com...
    [+] VirusTotal: 1200 subdomains
    [+] Total unique: 1200

[*] Resolving 1200 subdomains...
    [+] 7 live hosts

[*] Port scanning 7 hosts...
    [+] rest.vulnweb.com — open: 80
    [+] testasp.vulnweb.com — open: 80
    [+] testaspnet.vulnweb.com — open: 80

[*] Fingerprinting tech stack on 7 hosts...

ATTACK SURFACE REPORT: vulnweb.com
Subdomains found : 1200
Live hosts       : 7
Open ports found : 3

OPEN PORTS
  rest.vulnweb.com (18.215.71.186)
    80/tcp   HTTP
  testasp.vulnweb.com (44.238.29.244)
    80/tcp   HTTP

TECH STACK
  rest.vulnweb.com [HTTP 200]
    server: Apache/2.4.25 (Debian)
    powered_by: PHP/7.1.26
  testasp.vulnweb.com [HTTP 200]
    server: Microsoft-IIS/8.5
    powered_by: ASP.NET
```

## Setup

### 1. Clone the repo

```bash
git clone https://github.com/yourusername/osint-agent.git
cd osint-agent
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Add your API keys

Copy the example env file and fill in your keys:

```bash
cp .env.example .env
```

Open `.env` and add:

```
VIRUSTOTAL_API_KEY=your_key_here
GITHUB_TOKEN=your_token_here
```

Get your free VirusTotal key at [virustotal.com](https://www.virustotal.com) — sign up and go to your profile.

### 4. Run it

```bash
python main.py example.com
```

## Project structure

```
osint-agent/
├── main.py                  # Orchestrator
├── report.py                # Report generator
├── modules/
│   ├── subdomain_enum.py    # crt.sh + VirusTotal
│   ├── port_scanner.py      # Concurrent port scanner
│   └── tech_stack.py        # HTTP fingerprinting
├── .env                     # API keys (never committed)
└── requirements.txt
```

## Legal

Only scan domains you own or have explicit permission to test.
This tool is for educational purposes and authorized security assessments only.

## Roadmap

- [ ] GitHub secret scanning module
- [ ] Breach data lookup
- [ ] Shodan/Censys integration
- [ ] HTML report output
- [ ] Async scanning for faster results
