import requests


HIBP_API_URL = "https://haveibeenpwned.com/api/v3"


def check_domain_breaches(domain, api_key):
    """
    Query HIBP for all email addresses from the domain found in breaches.
    Returns a dict: { "email_prefix": ["BreachName1", "BreachName2"] }
    """
    headers = {
        "hibp-api-key": api_key,
        "user-agent": "OSINTAgent/1.0",
    }
    try:
        resp = requests.get(
            f"{HIBP_API_URL}/breacheddomain/{domain}",
            headers=headers,
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json()  # { "prefix": ["Breach1", ...] }
        elif resp.status_code == 404:
            return {}  # No breaches found
        elif resp.status_code == 401:
            print("    [!] HIBP API key invalid or unauthorized.")
            return {}
        elif resp.status_code == 429:
            print("    [!] HIBP rate limit hit. Try again in a moment.")
            return {}
        else:
            print(f"    [!] HIBP returned status {resp.status_code}")
            return {}
    except Exception as e:
        print(f"    [!] HIBP error: {e}")
        return {}


def get_breach_details(breach_name, api_key):
    """Fetch details about a specific breach."""
    headers = {
        "hibp-api-key": api_key,
        "user-agent": "OSINTAgent/1.0",
    }
    try:
        resp = requests.get(
            f"{HIBP_API_URL}/breach/{breach_name}",
            headers=headers,
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json()
        return {}
    except Exception:
        return {}


def scan_breaches(domain, api_key):
    """Entry point for breach data check."""
    if not api_key or api_key == "your_hibp_key_here":
        print("    [!] No HIBP API key set — skipping breach check.")
        return {"emails": {}, "breach_details": {}, "summary": {}}

    print(f"    [*] Checking {domain} against HaveIBeenPwned...")
    email_breaches = check_domain_breaches(domain, api_key)

    if not email_breaches:
        print(f"    [+] No breached accounts found for {domain}")
        return {"emails": {}, "breach_details": {}, "summary": {}}

    # Collect unique breach names
    all_breach_names = set()
    for breaches in email_breaches.values():
        all_breach_names.update(breaches)

    print(f"    [+] {len(email_breaches)} breached accounts found across {len(all_breach_names)} breaches")

    # Fetch details for each unique breach
    breach_details = {}
    for name in all_breach_names:
        details = get_breach_details(name, api_key)
        if details:
            breach_details[name] = {
                "title": details.get("Title", name),
                "date": details.get("BreachDate", "Unknown"),
                "pwn_count": details.get("PwnCount", 0),
                "data_classes": details.get("DataClasses", []),
            }

    # Build summary
    data_types = set()
    for b in breach_details.values():
        data_types.update(b["data_classes"])

    summary = {
        "total_accounts": len(email_breaches),
        "total_breaches": len(all_breach_names),
        "data_types_exposed": sorted(data_types),
    }

    return {
        "emails": email_breaches,
        "breach_details": breach_details,
        "summary": summary,
    }
