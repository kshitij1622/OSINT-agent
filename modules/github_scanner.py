import re
import requests

# Patterns that indicate a secret in source code
SECRET_PATTERNS = {
    "AWS Access Key":       r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":       r"(?i)aws(.{0,20})secret(.{0,20})['\"][0-9a-zA-Z/+]{40}['\"]",
    "Generic API Key":      r"(?i)(api_key|apikey|api-key)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]",
    "Generic Token":        r"(?i)(token|access_token|auth_token)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.]{20,})['\"]",
    "Generic Password":     r"(?i)(password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
    "Private Key":          r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
    "GitHub Token":         r"ghp_[a-zA-Z0-9]{36}",
    "Slack Token":          r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Stripe Key":           r"(?:r|s)k_live_[0-9a-zA-Z]{24}",
    "Google API Key":       r"AIza[0-9A-Za-z\-_]{35}",
    "Heroku API Key":       r"(?i)heroku(.{0,20})['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]",
    "Database URL":         r"(?i)(mysql|postgres|mongodb|redis):\/\/[^\s'\"]+",
}


def search_github(domain, token, max_results=10):
    """Search GitHub code for the domain and scan matches for secrets."""
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }

    findings = []
    queries = [domain, f'"{domain}"']

    seen_urls = set()

    for query in queries:
        try:
            resp = requests.get(
                "https://api.github.com/search/code",
                headers=headers,
                params={"q": query, "per_page": max_results},
                timeout=15,
            )

            if resp.status_code == 403:
                print("    [!] GitHub rate limit hit. Wait 60s or use a token.")
                break
            if resp.status_code == 422:
                continue
            resp.raise_for_status()

            items = resp.json().get("items", [])
            for item in items:
                raw_url = item.get("html_url", "").replace(
                    "github.com", "raw.githubusercontent.com"
                ).replace("/blob/", "/")

                if raw_url in seen_urls:
                    continue
                seen_urls.add(raw_url)

                repo = item.get("repository", {}).get("full_name", "unknown")
                file_path = item.get("path", "")

                # Fetch raw file content
                try:
                    raw = requests.get(raw_url, timeout=10)
                    content = raw.text
                except Exception:
                    continue

                # Scan for secret patterns
                secrets_found = []
                for secret_type, pattern in SECRET_PATTERNS.items():
                    matches = re.findall(pattern, content)
                    if matches:
                        secrets_found.append({
                            "type": secret_type,
                            "count": len(matches),
                        })

                if secrets_found or domain in content:
                    findings.append({
                        "repo": repo,
                        "file": file_path,
                        "url": item.get("html_url"),
                        "secrets": secrets_found,
                        "domain_mentioned": domain in content,
                    })

        except Exception as e:
            print(f"    [!] GitHub search error: {e}")
            continue

    return findings


def scan_github(domain, token):
    """Entry point for GitHub secret scanning."""
    if not token or token == "your_github_token_here" or token == "placeholder":
        print("    [!] No GitHub token set — skipping GitHub scan.")
        return []

    print(f"    [*] Searching GitHub for references to {domain}...")
    findings = search_github(domain, token)

    secrets_total = sum(len(f["secrets"]) for f in findings)
    print(f"    [+] {len(findings)} files found, {secrets_total} potential secrets detected")

    return findings
