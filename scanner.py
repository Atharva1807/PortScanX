import asyncio
import json
import subprocess
import nmap
import argparse
from datetime import datetime
import os
import getpass

COMMON_PORTS_SERVICES = {
    7: "Echo",
    19: "CHARGEN",
    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    42: "WINS Replication",
    41: "WHOIS",
    49: "TACACS",
    53: "DNS",
    67: "DHCP/BOOTP/server",
    68: "DHCP/BOOTP/client",
    69: "TFTP",
    70: "Gopher",
    79: "Finger",
    80: "HTTP",
    88: "Kerberos/Auth",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "Kerberos/Password",
    500: "IPSec/IKE",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    5432: "PostgreSQL"
}

ROLES = {
    "admin": {"tcp": True, "udp": True, "vuln": True, "view": True},
    "analyst": {"tcp": True, "udp": False, "vuln": False, "view": True},
    "viewer": {"tcp": False, "udp": False, "vuln": False, "view": True}
}

async def scan_port_async(ip, port, timeout=5):
    """Asynchronous TCP port scanner using ncat"""
    try:
        process = await asyncio.create_subprocess_exec(
            'ncat', '-zvw', str(timeout), ip, str(port),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        return "succeeded!" in (stdout.decode() + stderr.decode())
    except Exception:
        return False

async def scan_ports_async(ip, start_port, end_port, timeout=5):
    """Scan TCP ports concurrently"""
    open_ports = []
    for port in range(start_port, end_port + 1):
        if await scan_port_async(ip, port, timeout):
            open_ports.append(port)
    return open_ports

def run_nmap_scan(ip, open_ports, timeout=10, udp=False, vuln=False):
    """Run Nmap for TCP/UDP + vuln detection"""
    nm = nmap.PortScanner()
    ports_str = ','.join(map(str, open_ports))
    args = f"-p {ports_str} -sU" if udp else f"-p {ports_str} -sV"
    if vuln:
        args += " --script vulners,vulscan"
    try:
        nm.scan(ip, arguments=f"{args} --host-timeout {timeout}s")
    except nmap.PortScannerError as e:
        print(f"[!] Nmap Error: {e}")
        return {}
    return nm[ip] if ip in nm.all_hosts() else {}

async def process_host(ip, start_port, end_port, timeout, role):
    """Main logic per host"""
    results = {ip: {"ports": {}, "vulnerabilities": {}}}

    # TCP Scan (Admin/Analyst)
    if ROLES[role]["tcp"]:
        open_tcp = await scan_ports_async(ip, start_port, end_port, timeout)
        for p in open_tcp:
            results[ip]["ports"][p] = {"service": COMMON_PORTS_SERVICES.get(p, "Unknown")}

        if ROLES[role]["vuln"]:
            results[ip]["vulnerabilities"]["tcp"] = run_nmap_scan(ip, open_tcp, timeout, udp=False, vuln=True)

    # UDP Scan (Admin only)
    if ROLES[role]["udp"]:
        open_udp = [53, 123, 161]  # common UDP ports for demo
        results[ip]["vulnerabilities"]["udp"] = run_nmap_scan(ip, open_udp, timeout, udp=True, vuln=False)

    return results

async def main():
    parser = argparse.ArgumentParser(description="PortScanX - Async Port Scanner with RBAC & Nmap")
    parser.add_argument("targets", help="Target IP addresses (comma-separated)")
    parser.add_argument("--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("--end", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout (default: 5s)")
    parser.add_argument("--json", help="Save results to JSON file")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    # Simple RBAC
    role = input("Enter role (admin/analyst/viewer): ").strip().lower()
    if role not in ROLES:
        print("[!] Invalid role")
        return

    # Viewer mode: only view saved JSON
    if role == "viewer":
        if os.path.exists(args.json if args.json else "results.json"):
            with open(args.json, "r") as f:
                print(json.dumps(json.load(f), indent=2))
        else:
            print("[!] No saved report found")
        return

    targets = [ip.strip() for ip in args.targets.split(",")]
    all_results = {}

    for ip in targets:
        result = await process_host(ip, args.start, args.end, args.timeout, role)
        all_results.update(result)

    if args.verbose:
        print(json.dumps(all_results, indent=2))

    if args.json:
        filename = f"{args.json}_{datetime.now().strftime('%Y%m%d%H%M%S')}.json"
        with open(filename, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"[+] Results saved to {filename}")

if __name__ == "__main__":
    asyncio.run(main())
