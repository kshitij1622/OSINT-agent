import time
import requests


def get_crtsh_subdomains(domain, retries=3):
    """Pull subdomains from crt.sh certificate transparency logs with retry logic."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {"User-Agent": "Mozilla/5.0 (compatible; OSINTAgent/1.0)"}

    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            subdomains = set()
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower()
                    if name.endswith(domain) and "*" not in name:
                        subdomains.add(name)
            return subdomains
        except requests.exceptions.Timeout:
            if attempt < retries:
                wait = attempt * 5
                print(f"    [!] crt.sh timeout (attempt {attempt}/{retries}), retrying in {wait}s...")
                time.sleep(wait)
            else:
                print(f"    [!] crt.sh failed after {retries} attempts — skipping.")
        except Exception as e:
            print(f"    [!] crt.sh error: {e}")
            break

    return set()


def get_hackertarget_subdomains(domain):
    """Pull subdomains from HackerTarget — free, no API key needed."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        subdomains = set()
        for line in resp.text.splitlines():
            parts = line.strip().split(",")
            if parts and parts[0].endswith(domain):
                subdomains.add(parts[0].lower())
        return subdomains
    except Exception as e:
        print(f"    [!] HackerTarget error: {e}")
        return set()


def get_virustotal_subdomains(domain, api_key):
    """Pull subdomains from VirusTotal passive DNS."""
    subdomains = set()
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {"x-apikey": api_key}
    try:
        while url:
            resp = requests.get(url, headers=headers, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            for item in data.get("data", []):
                subdomains.add(item["id"])
            url = data.get("links", {}).get("next")
    except Exception as e:
        print(f"    [!] VirusTotal error: {e}")
    return subdomains


def enumerate_subdomains(domain, vt_api_key):
    print(f"[*] Enumerating subdomains for {domain}...")

    crt_subs = get_crtsh_subdomains(domain)
    print(f"    [+] crt.sh: {len(crt_subs)} subdomains")

    ht_subs = get_hackertarget_subdomains(domain)
    print(f"    [+] HackerTarget: {len(ht_subs)} subdomains")

    vt_subs = get_virustotal_subdomains(domain, vt_api_key)
    print(f"    [+] VirusTotal: {len(vt_subs)} subdomains")

    all_subs = sorted(crt_subs | ht_subs | vt_subs)
    print(f"    [+] Total unique: {len(all_subs)}")
    return all_subs
