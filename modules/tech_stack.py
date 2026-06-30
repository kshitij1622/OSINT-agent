import requests


# Headers that reveal server technology
HEADER_MAP = {
    "Server": "server",
    "X-Powered-By": "powered_by",
    "X-Generator": "generator",
    "X-AspNet-Version": "aspnet_version",
    "X-Runtime": "runtime",
}

# Strings in HTML body that signal specific frameworks or CMSs
BODY_SIGNATURES = {
    "wp-content": "WordPress",
    "wp-includes": "WordPress",
    "drupal.settings": "Drupal",
    "sites/default/files": "Drupal",
    "joomla": "Joomla",
    "__next": "Next.js",
    "_nuxt": "Nuxt.js",
    "ng-version": "Angular",
    "react-root": "React",
    "__vue": "Vue.js",
    "laravel": "Laravel",
    "csrf-token": "Rails/Laravel",
    "django": "Django",
}


def fingerprint(host):
    """Attempt HTTP/HTTPS connection and fingerprint the tech stack."""
    result = {
        "status_code": None,
        "final_url": None,
        "headers": {},
        "technologies": [],
    }

    for scheme in ["https", "http"]:
        try:
            url = f"{scheme}://{host}"
            resp = requests.get(
                url,
                timeout=5,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; OSINTAgent/1.0)"},
            )
            result["status_code"] = resp.status_code
            result["final_url"] = resp.url

            for header, key in HEADER_MAP.items():
                if header in resp.headers:
                    result["headers"][key] = resp.headers[header]

            body = resp.text.lower()
            for sig, tech in BODY_SIGNATURES.items():
                if sig.lower() in body and tech not in result["technologies"]:
                    result["technologies"].append(tech)

            break  # stop after first successful scheme
        except Exception:
            continue

    return result
