import json
from datetime import datetime


def generate_report(domain, subdomains, scan_results, tech_results, github_findings=None, breach_data=None):
    total_open_ports = sum(len(v["open_ports"]) for v in scan_results.values())
    github_findings = github_findings or []
    secrets_found = sum(len(f["secrets"]) for f in github_findings)
    breach_data = breach_data or {}
    breach_summary = breach_data.get("summary", {})
    return {
        "target": domain,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total_subdomains": len(subdomains),
            "live_hosts": len(scan_results),
            "total_open_ports": total_open_ports,
            "github_files_found": len(github_findings),
            "potential_secrets": secrets_found,
            "breached_accounts": breach_summary.get("total_accounts", 0),
            "breaches_found": breach_summary.get("total_breaches", 0),
        },
        "subdomains": subdomains,
        "port_scan": scan_results,
        "tech_stack": tech_results,
        "github_findings": github_findings,
        "breach_data": breach_data,
    }


def print_report(report):
    sep = "=" * 60
    print(f"\n{sep}")
    print(f"  ATTACK SURFACE REPORT: {report['target']}")
    print(f"  Generated: {report['generated_at']}")
    print(sep)

    s = report["summary"]
    print(f"\nSUMMARY")
    print(f"  Subdomains found   : {s['total_subdomains']}")
    print(f"  Live hosts         : {s['live_hosts']}")
    print(f"  Open ports found   : {s['total_open_ports']}")
    print(f"  GitHub files found : {s.get('github_files_found', 0)}")
    print(f"  Potential secrets  : {s.get('potential_secrets', 0)}")
    print(f"  Breached accounts  : {s.get('breached_accounts', 0)}")
    print(f"  Breaches found     : {s.get('breaches_found', 0)}")

    print(f"\nSUBDOMAINS ({s['total_subdomains']} total)")
    for sub in report["subdomains"][:20]:
        print(f"  {sub}")
    if s["total_subdomains"] > 20:
        print(f"  ... and {s['total_subdomains'] - 20} more (see JSON report)")

    print(f"\nOPEN PORTS")
    found_any = False
    for host, data in report["port_scan"].items():
        if data["open_ports"]:
            found_any = True
            print(f"  {host} ({data['ip']})")
            for p in data["open_ports"]:
                print(f"    {p['port']}/tcp   {p['service']}")
    if not found_any:
        print("  None found on scanned hosts")

    print(f"\nTECH STACK")
    for host, data in report["tech_stack"].items():
        status = data.get("status_code", "N/A")
        techs = ", ".join(data.get("technologies", [])) or "None detected"
        headers = data.get("headers", {})
        print(f"  {host}  [HTTP {status}]")
        if headers:
            for k, v in headers.items():
                print(f"    {k}: {v}")
        print(f"    Technologies: {techs}")

    print(f"\nBREACH DATA")
    bd = report.get("breach_data", {})
    emails = bd.get("emails", {})
    breach_details = bd.get("breach_details", {})
    b_summary = bd.get("summary", {})
    if not emails:
        print("  No breached accounts found")
    else:
        print(f"  {b_summary.get('total_accounts', 0)} accounts found across {b_summary.get('total_breaches', 0)} breaches")
        data_types = b_summary.get("data_types_exposed", [])
        if data_types:
            print(f"  Data exposed: {', '.join(data_types[:5])}")
        print(f"\n  Top breaches:")
        for name, detail in list(breach_details.items())[:5]:
            print(f"    {detail['title']} ({detail['date']}) — {detail['pwn_count']:,} accounts")

    print(f"\nGITHUB FINDINGS")
    findings = report.get("github_findings", [])
    if not findings:
        print("  None found")
    else:
        for f in findings:
            print(f"  {f['repo']} — {f['file']}")
            print(f"    URL: {f['url']}")
            if f["secrets"]:
                for s in f["secrets"]:
                    print(f"    [!] {s['type']} ({s['count']} match{'es' if s['count'] > 1 else ''})")
            else:
                print(f"    Domain mentioned, no secrets pattern matched")

    print(f"\n{sep}\n")


def save_report(report):
    filename = f"report_{report['target'].replace('.', '_')}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    return filename
