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
    asyncio.run(main_async())
