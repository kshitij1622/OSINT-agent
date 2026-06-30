import json
from datetime import datetime


def generate_report(domain, subdomains, scan_results, tech_results):
    total_open_ports = sum(len(v["open_ports"]) for v in scan_results.values())
    return {
        "target": domain,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total_subdomains": len(subdomains),
            "live_hosts": len(scan_results),
            "total_open_ports": total_open_ports,
        },
        "subdomains": subdomains,
        "port_scan": scan_results,
        "tech_stack": tech_results,
    }


def print_report(report):
    sep = "=" * 60
    print(f"\n{sep}")
    print(f"  ATTACK SURFACE REPORT: {report['target']}")
    print(f"  Generated: {report['generated_at']}")
    print(sep)

    s = report["summary"]
    print(f"\nSUMMARY")
    print(f"  Subdomains found : {s['total_subdomains']}")
    print(f"  Live hosts       : {s['live_hosts']}")
    print(f"  Open ports found : {s['total_open_ports']}")

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

    print(f"\n{sep}\n")


def save_report(report):
    filename = f"report_{report['target'].replace('.', '_')}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    return filename
