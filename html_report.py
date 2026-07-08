from datetime import datetime


def generate_html(report):
    domain = report["target"]
    s = report["summary"]
    generated = report["generated_at"]
    subdomains = report["subdomains"]
    port_scan = report["port_scan"]
    tech_stack = report["tech_stack"]
    github_findings = report.get("github_findings", [])
    breach_data = report.get("breach_data", {})
    breach_emails = breach_data.get("emails", {})
    breach_details = breach_data.get("breach_details", {})
    breach_summary = breach_data.get("summary", {})

    # --- Subdomain rows ---
    subdomain_rows = ""
    for sub in subdomains:
        subdomain_rows += f"<tr><td>{sub}</td></tr>\n"

    # --- Port scan rows ---
    port_rows = ""
    for host, data in port_scan.items():
        ip = data.get("ip", "N/A")
        ports = data.get("open_ports", [])
        if ports:
            for p in ports:
                port_rows += f"""
                <tr>
                    <td>{host}</td>
                    <td>{ip}</td>
                    <td>{p['port']}/tcp</td>
                    <td><span class="badge badge-green">{p['service']}</span></td>
                </tr>"""
        else:
            port_rows += f"""
            <tr>
                <td>{host}</td>
                <td>{ip}</td>
                <td colspan="2"><span class="badge badge-grey">No open ports</span></td>
            </tr>"""

    # --- Tech stack rows ---
    tech_rows = ""
    for host, data in tech_stack.items():
        status = data.get("status_code", "N/A")
        headers = data.get("headers", {})
        techs = data.get("technologies", [])
        status_class = "badge-green" if status == 200 else "badge-grey"
        tech_rows += f"""
        <tr>
            <td>{host}</td>
            <td><span class="badge {status_class}">HTTP {status}</span></td>
            <td>{headers.get('server', '—')}</td>
            <td>{headers.get('powered_by', '—')}</td>
            <td>{', '.join(techs) if techs else '—'}</td>
        </tr>"""

    # --- GitHub findings rows ---
    github_rows = ""
    if not github_findings:
        github_rows = "<tr><td colspan='3'>No findings</td></tr>"
    else:
        for f in github_findings:
            secrets = f.get("secrets", [])
            secret_badges = ""
            for sec in secrets:
                secret_badges += f"<span class='badge badge-red'>{sec['type']} x{sec['count']}</span> "
            if not secret_badges:
                secret_badges = "<span class='badge badge-grey'>Domain mentioned</span>"
            github_rows += f"""
            <tr>
                <td><a href="{f['url']}" target="_blank">{f['repo']}</a></td>
                <td>{f['file']}</td>
                <td>{secret_badges}</td>
            </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Attack Surface Report — {domain}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: #0f1117;
            color: #e2e8f0;
            padding: 2rem;
        }}

        header {{
            border-bottom: 1px solid #2d3748;
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}

        header h1 {{
            font-size: 1.8rem;
            font-weight: 700;
            color: #f8fafc;
        }}

        header h1 span {{
            color: #38bdf8;
        }}

        header p {{
            color: #94a3b8;
            font-size: 0.85rem;
            margin-top: 0.3rem;
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2.5rem;
        }}

        .stat-card {{
            background: #1e2433;
            border: 1px solid #2d3748;
            border-radius: 8px;
            padding: 1.2rem;
            text-align: center;
        }}

        .stat-card .number {{
            font-size: 2rem;
            font-weight: 700;
            color: #38bdf8;
        }}

        .stat-card .label {{
            font-size: 0.75rem;
            color: #94a3b8;
            margin-top: 0.3rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        section {{
            margin-bottom: 2.5rem;
        }}

        section h2 {{
            font-size: 1rem;
            font-weight: 600;
            color: #94a3b8;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}

        section h2::before {{
            content: '';
            display: inline-block;
            width: 3px;
            height: 1rem;
            background: #38bdf8;
            border-radius: 2px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.875rem;
        }}

        th {{
            text-align: left;
            padding: 0.6rem 1rem;
            background: #1a2030;
            color: #64748b;
            font-weight: 500;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border-bottom: 1px solid #2d3748;
        }}

        td {{
            padding: 0.6rem 1rem;
            border-bottom: 1px solid #1e2433;
            color: #cbd5e1;
            font-family: 'Courier New', monospace;
            font-size: 0.8rem;
        }}

        tr:hover td {{
            background: #1a2030;
        }}

        a {{
            color: #38bdf8;
            text-decoration: none;
        }}

        a:hover {{
            text-decoration: underline;
        }}

        .badge {{
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 600;
            font-family: 'Segoe UI', sans-serif;
        }}

        .badge-green {{ background: #064e3b; color: #34d399; }}
        .badge-red   {{ background: #450a0a; color: #f87171; }}
        .badge-grey  {{ background: #1e293b; color: #64748b; }}

        .subdomain-table td {{
            font-size: 0.78rem;
        }}

        footer {{
            text-align: center;
            color: #334155;
            font-size: 0.75rem;
            margin-top: 3rem;
            padding-top: 1rem;
            border-top: 1px solid #1e2433;
        }}
    </style>
</head>
<body>

<header>
    <h1>Attack Surface Report — <span>{domain}</span></h1>
    <p>Generated: {generated} &nbsp;|&nbsp; Tool: OSINT Agent</p>
</header>

<div class="summary-grid">
    <div class="stat-card">
        <div class="number">{s['total_subdomains']}</div>
        <div class="label">Subdomains</div>
    </div>
    <div class="stat-card">
        <div class="number">{s['live_hosts']}</div>
        <div class="label">Live Hosts</div>
    </div>
    <div class="stat-card">
        <div class="number">{s['total_open_ports']}</div>
        <div class="label">Open Ports</div>
    </div>
    <div class="stat-card">
        <div class="number">{s.get('github_files_found', 0)}</div>
        <div class="label">GitHub Files</div>
    </div>
    <div class="stat-card">
        <div class="number" style="color: {'#f87171' if s.get('potential_secrets', 0) > 0 else '#38bdf8'}">{s.get('potential_secrets', 0)}</div>
        <div class="label">Potential Secrets</div>
    </div>
    <div class="stat-card">
        <div class="number" style="color: {'#f87171' if s.get('breached_accounts', 0) > 0 else '#38bdf8'}">{s.get('breached_accounts', 0)}</div>
        <div class="label">Breached Accounts</div>
    </div>
    <div class="stat-card">
        <div class="number" style="color: {'#f87171' if s.get('breaches_found', 0) > 0 else '#38bdf8'}">{s.get('breaches_found', 0)}</div>
        <div class="label">Breaches Found</div>
    </div>
</div>

<section>
    <h2>Open Ports</h2>
    <table>
        <thead>
            <tr>
                <th>Host</th>
                <th>IP</th>
                <th>Port</th>
                <th>Service</th>
            </tr>
        </thead>
        <tbody>
            {port_rows if port_rows else '<tr><td colspan="4">No hosts scanned</td></tr>'}
        </tbody>
    </table>
</section>

<section>
    <h2>Tech Stack</h2>
    <table>
        <thead>
            <tr>
                <th>Host</th>
                <th>Status</th>
                <th>Server</th>
                <th>Powered By</th>
                <th>Technologies</th>
            </tr>
        </thead>
        <tbody>
            {tech_rows if tech_rows else '<tr><td colspan="5">No data</td></tr>'}
        </tbody>
    </table>
</section>

<section>
    <h2>Breach Data</h2>
    {'<p style="color:#64748b;font-size:0.85rem;margin-bottom:1rem;">No breached accounts found for this domain.</p>' if not breach_emails else f'''
    <p style="color:#94a3b8;font-size:0.85rem;margin-bottom:1rem;">
        {breach_summary.get("total_accounts", 0)} accounts from this domain appeared in {breach_summary.get("total_breaches", 0)} data breaches.
        Data exposed: {", ".join(breach_summary.get("data_types_exposed", [])[:6]) or "Unknown"}
    </p>
    <table>
        <thead><tr><th>Breach</th><th>Date</th><th>Accounts Affected</th><th>Data Exposed</th></tr></thead>
        <tbody>
            {"".join(f"<tr><td>{d['title']}</td><td>{d['date']}</td><td>{d['pwn_count']:,}</td><td>{', '.join(d['data_classes'][:3])}</td></tr>" for d in list(breach_details.values())[:10])}
        </tbody>
    </table>'''}
</section>

<section>
    <h2>GitHub Findings</h2>
    <table>
        <thead>
            <tr>
                <th>Repository</th>
                <th>File</th>
                <th>Findings</th>
            </tr>
        </thead>
        <tbody>
            {github_rows}
        </tbody>
    </table>
</section>

<section>
    <h2>Subdomains ({len(subdomains)} total)</h2>
    <table class="subdomain-table">
        <thead>
            <tr><th>Subdomain</th></tr>
        </thead>
        <tbody>
            {subdomain_rows}
        </tbody>
    </table>
</section>

<footer>
    OSINT Agent &nbsp;|&nbsp; For authorized security assessments only
</footer>

</body>
</html>"""

    return html


def save_html_report(report):
    html = generate_html(report)
    filename = f"report_{report['target'].replace('.', '_')}.html"
    with open(filename, "w") as f:
        f.write(html)
    return filename
