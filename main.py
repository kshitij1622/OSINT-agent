import os
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv

from modules.subdomain_enum import enumerate_subdomains
from modules.port_scanner import scan_host
from modules.tech_stack import fingerprint
from report import generate_report, print_report, save_report

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

MAX_HOSTS_TO_SCAN = 20  # cap to avoid scanning for hours


def resolve(subdomain):
    try:
        return subdomain, socket.gethostbyname(subdomain)
    except Exception:
        return subdomain, None


def main():
    if len(sys.argv) > 1:
        domain = sys.argv[1].strip().lower()
    else:
        domain = input("Enter target domain (e.g. example.com): ").strip().lower()

    if not domain:
        print("[!] No domain provided. Exiting.")
        sys.exit(1)

    if not VT_API_KEY or VT_API_KEY == "your_virustotal_key_here":
        print("[!] VIRUSTOTAL_API_KEY not set in .env — skipping VirusTotal.")

    print(f"\n[*] Starting recon on: {domain}\n")

    # --- Step 1: Subdomain Enumeration ---
    subdomains = enumerate_subdomains(domain, VT_API_KEY)

    # Always include the root domain itself
    if domain not in subdomains:
        subdomains = [domain] + subdomains

    # --- Step 2: Resolve to IPs, filter dead hosts ---
    print(f"\n[*] Resolving {len(subdomains)} subdomains...")
    with ThreadPoolExecutor(max_workers=100) as executor:
        resolved = list(executor.map(resolve, subdomains))

    live_hosts = {sub: ip for sub, ip in resolved if ip}
    print(f"    [+] {len(live_hosts)} live hosts")

    # Cap scan targets
    hosts_to_scan = list(live_hosts.keys())[:MAX_HOSTS_TO_SCAN]
    if len(live_hosts) > MAX_HOSTS_TO_SCAN:
        print(f"    [!] Capping port scan to first {MAX_HOSTS_TO_SCAN} hosts")

    # --- Step 3: Port Scanning ---
    print(f"\n[*] Port scanning {len(hosts_to_scan)} hosts...")
    scan_results = {}
    for host in hosts_to_scan:
        open_ports = scan_host(host)
        scan_results[host] = {"ip": live_hosts[host], "open_ports": open_ports}
        if open_ports:
            ports_str = ", ".join(str(p["port"]) for p in open_ports)
            print(f"    [+] {host} — open: {ports_str}")
        else:
            print(f"    [-] {host} — no common ports open")

    # --- Step 4: Tech Stack Fingerprinting ---
    print(f"\n[*] Fingerprinting tech stack on {len(hosts_to_scan)} hosts...")
    tech_results = {}
    for host in hosts_to_scan:
        tech_results[host] = fingerprint(host)
        techs = tech_results[host].get("technologies", [])
        status = tech_results[host].get("status_code", "N/A")
        print(f"    {host} [{status}] — {', '.join(techs) if techs else 'no techs detected'}")

    # --- Step 5: Report ---
    report = generate_report(domain, subdomains, scan_results, tech_results)
    print_report(report)

    filename = save_report(report)
    print(f"[+] Full report saved to {filename}\n")


if __name__ == "__main__":
    main()
