"""Host discovery utilities for chaos-bot.

Uses nmap ARP sweep to find live hosts on a VLAN subnet before attacking.
"""

import ipaddress
import re
import subprocess

from chaos_bot.logger import get_logger


def gateway_to_subnet(gateway: str) -> str:
    """Derive /24 subnet from gateway IP.

    Example: '172.16.40.1' -> '172.16.40.0/24'
    """
    net = ipaddress.ip_network(f"{gateway}/24", strict=False)
    return str(net)


def discover_hosts(subnet: str, interface: str, source_ip: str,
                   excluded: list[str] | None = None,
                   dry_run: bool = False) -> list[str]:
    """Run nmap ARP sweep and return list of live host IPs.

    Args:
        subnet: CIDR subnet to scan (e.g. '172.16.40.0/24')
        interface: Network interface to scan from (e.g. 'eth1.40')
        source_ip: Source IP for the scan
        excluded: IPs to exclude from results (gateways, self, etc.)
        dry_run: If True, skip actual scan and return empty list
    """
    log = get_logger()
    excluded = set(excluded or [])
    excluded.add(source_ip)

    if dry_run:
        log.info(f"[DRY RUN] Would discover hosts on {subnet} via {interface}",
                 extra={"bot_module": "discovery"})
        return []

    cmd = ["nmap", "-sn", "-PR", "-S", source_ip, "-e", interface, subnet]
    log.info(f"Discovering hosts: {' '.join(cmd)}", extra={"bot_module": "discovery"})

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        log.warning("Host discovery timed out", extra={"bot_module": "discovery"})
        return []
    except FileNotFoundError:
        log.error("nmap not found — host discovery unavailable",
                  extra={"bot_module": "discovery"})
        return []

    # Parse "Nmap scan report for <ip>" lines
    hosts = []
    for line in result.stdout.splitlines():
        m = re.match(r"Nmap scan report for (\S+)", line)
        if m:
            ip = m.group(1)
            # nmap may report hostname (ip) format
            ip_match = re.search(r"\(([^)]+)\)", ip)
            if ip_match:
                ip = ip_match.group(1)
            if ip not in excluded:
                hosts.append(ip)

    log.info(f"Discovered {len(hosts)} live host(s) on {subnet}",
             extra={"bot_module": "discovery"})
    return hosts
