import asyncio
import json
import subprocess
import nmap
from datetime import datetime

# Dictionary of common ports and their services
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
    70: " Gopher",
    79: "Finger",
    80: "HTTP",
    88: "Kerberos/Network Auth",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "Kerberos/Password",
    500: "IPSec / ISAKMP / IKE",
    993: "IMAP over SSL (IMAPS)",
    995: "POP3 over SSL (POP3S)",
    3306: "MySQL",
    5432: "PostgreSQL",
}

async def scan_port_async(ip, port, timeout=10):
    try:
        process = await asyncio.create_subprocess_exec(
            'ncat', '-zvw', str(timeout), ip, str(port),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        output = stdout.decode().strip()
        return output
    except asyncio.CancelledError:
        process.terminate()
        raise
    except Exception as e:
        return str(e)

async def scan_ports_async(ip, start_port, end_port, timeout=10):
    open_ports = []
    for port in range(start_port, end_port + 1):
        result = await scan_port_async(ip, port, timeout)
        if 'succeeded!' in result:
            open_ports.append(port)
    return open_ports

async def get_service(port):
    # Lookup service associated with port
    return COMMON_PORTS_SERVICES.get(port, "Unknown")

async def process_host(ip, open_ports, timeout=10):
    port_info = {}
    for port in open_ports:
        service = await get_service(port)
        port_info[port] = {"service": service}
    return {ip: port_info}

async def scan_vulnerabilities_async(ip, ports, timeout=10, extra_args=''):
    nm = nmap.PortScanner()
    open_ports_str = ','.join(map(lambda x: f"{x[1]}/{x[2]}", ports))
    try:
        await asyncio.to_thread(nm.scan, ip, f'-p {open_ports_str} --script vulners,vulscan -sV -O --host-timeout {timeout}s {extra_args}')
    except nmap.PortScannerError as e:
        print(f"Error: {e}")
        return {}

    results = {}
    for host in nm.all_hosts():
        results[host] = {'ports': {}}
        for proto in nm[host].all_protocols():
            results[host]['ports'][proto] = {}
            for port in nm[host][proto].keys():
                if nm[host][proto][port]['state'] == 'open':
                    results[host]['ports'][proto][port] = {
                        'service': nm[host][proto][port]['name'],
                        'version': nm[host][proto][port]['version'],
                        'scripts': {}
                    }

                    if 'script' in nm[host][proto][port]:
                        for script_name, script_output in nm[host][proto][port]['script'].items():
                            results[host]['ports'][proto][port]['scripts'][script_name] = script_output

    return results

async def main_async():
    target_ips = input("Enter target IPs (comma-separated): ").split(',')
    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))
    timeout = int(input("Enter timeout (seconds): "))
    output_file = input("Enter output file name (press Enter for no file output): ").strip()
    verbose_input = input("Verbose output? (y/n): ").strip().lower()

    verbose = True if verbose_input == 'y' else False

    all_results = {}

    async def run_port_scans(ip):
        open_ports = await scan_ports_async(ip.strip(), start_port, end_port, timeout)
        results = await process_host(ip.strip(), open_ports, timeout)
        all_results.update(results)

    await asyncio.gather(*[run_port_scans(ip) for ip in target_ips])

    if all_results:
        print(json.dumps(all_results, indent=2)) if verbose else None

        if output_file:
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            filename = f"{output_file}_{timestamp}.json"

            with open(filename, 'w') as file:
                json.dump(all_results, file, indent=2)

            print(f"Results saved to: {filename}")

if __name__ == "__main__":
    asyncio.run(main_async()







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
