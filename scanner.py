#!/usr/bin/env python3
"""
Basic Network Scanner
- Discovers live hosts on an authorized private IPv4 subnet using Scapy ARP.
- Scans a small list of common TCP ports with Python sockets.
- Attempts basic TCP banner grabbing.
- Writes a plain-text report.

Use only on networks and devices you own or have explicit permission to assess.
"""
from __future__ import annotations

import argparse
import ipaddress
import socket
from datetime import datetime
from pathlib import Path
from typing import Iterable

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MS RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-alt",
}

def validate_private_subnet(value: str) -> ipaddress.IPv4Network:
    """Accept only private IPv4 subnets and reject very large ranges."""
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Invalid network: {exc}") from exc

    if not isinstance(network, ipaddress.IPv4Network):
        raise argparse.ArgumentTypeError("Only IPv4 networks are supported.")
    if not network.is_private:
        raise argparse.ArgumentTypeError(
            "For safety, this project only scans private IPv4 networks (for example 192.168.1.0/24)."
        )
    if network.num_addresses > 256:
        raise argparse.ArgumentTypeError(
            "Subnet is too large for this beginner project. Use a /24 or smaller range."
        )
    return network

def discover_hosts(network: ipaddress.IPv4Network, timeout: float = 2.0) -> list[dict[str, str]]:
    """Use ARP requests to find devices on the local Layer-2 network."""
    try:
        from scapy.all import ARP, Ether, srp
    except ImportError as exc:
        raise RuntimeError(
            "Scapy is not installed. Run: python -m pip install -r requirements.txt"
        ) from exc

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
    answered, _ = srp(packet, timeout=timeout, retry=1, verbose=False)
    hosts = []
    for _, reply in answered:
        hosts.append({
            "ip": str(reply.psrc),
            "mac": str(reply.hwsrc),
        })
    return sorted(hosts, key=lambda item: ipaddress.ip_address(item["ip"]))

def grab_banner(sock: socket.socket, port: int) -> str:
    """Try a small, non-invasive read; send an HTTP HEAD only to common web ports."""
    sock.settimeout(1.0)
    try:
        if port in (80, 8080):
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        data = sock.recv(512)
        if data:
            return data.decode("utf-8", errors="replace").strip().replace("\r", " ")[:180]
    except (socket.timeout, OSError):
        pass
    return "No banner returned"

def scan_ports(host: str, ports: Iterable[int], timeout: float = 0.5) -> list[dict[str, str | int]]:
    """Attempt TCP connections to the selected common ports."""
    findings = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((host, int(port)))
                if result == 0:
                    banner = grab_banner(sock, int(port))
                    findings.append({
                        "port": int(port),
                        "service": COMMON_PORTS.get(int(port), "Unknown"),
                        "banner": banner or "No banner returned",
                    })
        except (OSError, ValueError):
            continue
    return findings

def write_report(
    output: Path,
    network: ipaddress.IPv4Network,
    hosts: list[dict[str, str]],
    results: dict[str, list[dict[str, str | int]]],
) -> None:
    lines = [
        "BASIC PYTHON NETWORK SCANNER — REPORT",
        "=" * 44,
        f"Generated: {datetime.now().astimezone().isoformat(timespec='seconds')}",
        f"Subnet: {network}",
        f"Live hosts found: {len(hosts)}",
        "",
        "HOST DETAILS",
        "-" * 44,
    ]
    if not hosts:
        lines.append("No hosts responded to ARP discovery.")
    for host in hosts:
        lines.extend([f"Host: {host['ip']}    MAC: {host['mac']}"])
        open_ports = results.get(host["ip"], [])
        if not open_ports:
            lines.append("  No open ports found in the selected common-port list.")
        for item in open_ports:
            lines.append(
                f"  TCP/{item['port']} ({item['service']}): OPEN | Banner: {item['banner']}"
            )
        lines.append("")
    lines.extend([
        "NOTES",
        "-" * 44,
        "Only the configured common TCP ports were checked; this is not a full port audit.",
        "A missing banner does not mean a service is absent or safe.",
        "Use results only for systems you own or are authorized to assess.",
        "",
    ])
    output.write_text("\n".join(lines), encoding="utf-8")

def parse_ports(value: str) -> list[int]:
    try:
        ports = sorted({int(part.strip()) for part in value.split(",") if part.strip()})
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Ports must be comma-separated numbers.") from exc
    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise argparse.ArgumentTypeError("Provide ports in the range 1–65535.")
    if len(ports) > 64:
        raise argparse.ArgumentTypeError("Limit this beginner scanner to 64 ports per run.")
    return ports

def main() -> int:
    parser = argparse.ArgumentParser(description="Discover hosts and common TCP ports on a private IPv4 subnet.")
    parser.add_argument("subnet", type=validate_private_subnet, help="Private subnet, e.g. 192.168.1.0/24")
    parser.add_argument("--ports", type=parse_ports,
                        default=list(COMMON_PORTS),
                        help="Optional comma-separated TCP ports (default: common ports)")
    parser.add_argument("--timeout", type=float, default=0.5,
                        help="TCP connection timeout in seconds (default: 0.5)")
    parser.add_argument("--output", default="scan_report.txt",
                        help="Text report path (default: scan_report.txt)")
    args = parser.parse_args()

    if not 0.1 <= args.timeout <= 3.0:
        parser.error("--timeout must be between 0.1 and 3.0 seconds")

    print(f"[*] Discovering hosts on {args.subnet} using ARP...")
    try:
        hosts = discover_hosts(args.subnet)
    except RuntimeError as exc:
        print(f"[!] {exc}")
        return 1
    except PermissionError:
        print("[!] Permission denied. Try running with appropriate privileges for Scapy/packet capture.")
        return 1
    except OSError as exc:
        print(f"[!] Network discovery failed: {exc}")
        return 1

    print(f"[+] Found {len(hosts)} live host(s).")
    results: dict[str, list[dict[str, str | int]]] = {}
    for index, host in enumerate(hosts, start=1):
        print(f"[{index}/{len(hosts)}] Scanning {host['ip']}...")
        results[host["ip"]] = scan_ports(host["ip"], args.ports, args.timeout)
        for item in results[host["ip"]]:
            print(f"    OPEN TCP/{item['port']} ({item['service']})")

    output = Path(args.output)
    write_report(output, args.subnet, hosts, results)
    print(f"[+] Report saved to: {output.resolve()}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
