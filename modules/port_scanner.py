import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    27017: "MongoDB",
}


def scan_port(host, port, timeout=1):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port, True
    except Exception:
        return port, False


def scan_host(host, ports=None):
    """Scan a host for open ports. Returns list of {port, service} dicts."""
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    open_ports = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_port, host, port): port for port in ports}
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append({
                    "port": port,
                    "service": COMMON_PORTS.get(port, "Unknown"),
                })

    return sorted(open_ports, key=lambda x: x["port"])
