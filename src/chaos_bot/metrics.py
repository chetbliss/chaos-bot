"""Prometheus metrics for chaos-bot."""

from prometheus_client import Counter, Gauge, Histogram, start_http_server


class ChaosMetrics:
    """Prometheus metrics collector."""

    def __init__(self):
        # Hop metrics
        self.hops_total = Counter(
            "chaosbot_hops_total",
            "Total VLAN hop cycles completed",
            ["vlan_id"],
        )
        self.hop_duration = Histogram(
            "chaosbot_hop_duration_seconds",
            "Duration of each hop cycle",
            buckets=[30, 60, 120, 300, 600, 1200],
        )
        self.current_vlan = Gauge(
            "chaosbot_current_vlan",
            "Currently active VLAN ID",
        )

        # Module metrics
        self.module_runs_total = Counter(
            "chaosbot_module_runs_total",
            "Total module executions",
            ["module", "status"],
        )
        self.module_duration = Histogram(
            "chaosbot_module_duration_seconds",
            "Module execution duration",
            ["module"],
        )

        # Scan metrics
        self.scan_hosts_found = Counter(
            "chaosbot_scan_hosts_found_total",
            "Hosts discovered by net_scanner",
        )
        self.scan_ports_found = Counter(
            "chaosbot_scan_ports_found_total",
            "Open ports discovered by net_scanner",
        )

        # Auth prober metrics
        self.auth_attempts_total = Counter(
            "chaosbot_auth_attempts_total",
            "Authentication attempts made",
            ["protocol", "result"],
        )

        # DNS noise metrics
        self.dns_queries_total = Counter(
            "chaosbot_dns_queries_total",
            "DNS queries generated",
            ["query_type"],
        )

        # HTTP probe metrics
        self.http_probes_total = Counter(
            "chaosbot_http_probes_total",
            "HTTP probe requests sent",
            ["probe_type"],
        )

        # Lease metrics
        self.leases_total = Counter(
            "chaosbot_leases_total",
            "Total DHCP leases obtained",
        )
        self.duplicate_ips = Counter(
            "chaosbot_duplicate_ips_total",
            "Duplicate IP assignments detected",
        )

        # State
        self.state = Gauge(
            "chaosbot_state",
            "Current bot state (0=idle, 1=hopping, 2=attacking, 3=cooldown)",
        )

    def record_hop(self, vlan_id: int, ip: str, duration: float, results: list[dict]) -> None:
        """Record metrics for a completed hop cycle."""
        self.hops_total.labels(vlan_id=str(vlan_id)).inc()
        self.hop_duration.observe(duration)
        self.current_vlan.set(vlan_id)
        self.leases_total.inc()

        for result in results:
            module = result.get("module", "unknown")
            status = result.get("status", "unknown")
            self.module_runs_total.labels(module=module, status=status).inc()

    def start_server(self, port: int = 9100, addr: str = "0.0.0.0") -> None:
        """Start Prometheus HTTP metrics server."""
        start_http_server(port, addr=addr)
