"""802.1Q VLAN rotation engine for chaos-bot.

Requires root privileges. Cycles through VLANs on the attack NIC,
obtaining DHCP leases and running modules from each VLAN.
"""

import os
import random
import signal
import subprocess
import time

from chaos_bot.discovery import discover_hosts, gateway_to_subnet
from chaos_bot.lease_db import LeaseDB
from chaos_bot.logger import get_logger


class VlanHopper:
    """Manages VLAN interface lifecycle: create, DHCP, route, teardown."""

    def __init__(self, config: dict, modules: dict, metrics=None, notifier=None):
        self.config = config
        self.modules = modules
        self.metrics = metrics
        self.notifier = notifier
        self.log = get_logger()
        self.lease_db = LeaseDB()

        self.interface = config["general"].get("interface", "eth1")
        self.vlans = config.get("vlans", [])
        self.schedule = config.get("schedule", {})
        self.dry_run = config["general"].get("dry_run", False)

        self._current_vlan = None
        self._current_iface = None
        self._current_ip = None
        self._running = False
        self._state = "idle"

    @property
    def state(self) -> str:
        return self._state

    @property
    def current_vlan(self) -> int | None:
        return self._current_vlan

    @property
    def current_ip(self) -> str | None:
        return self._current_ip

    def _run_cmd(self, cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
        """Execute a system command, or log it in dry-run mode."""
        self.log.debug(f"CMD: {' '.join(cmd)}", extra={"bot_module": "vlan_hopper"})
        if self.dry_run:
            self.log.info(f"[DRY RUN] {' '.join(cmd)}", extra={"bot_module": "vlan_hopper"})
            return subprocess.CompletedProcess(cmd, 0, stdout="dry-run", stderr="")
        return subprocess.run(cmd, capture_output=True, text=True, check=check)

    def _create_vlan_iface(self, vlan_id: int) -> str:
        """Create 802.1Q sub-interface."""
        iface = f"{self.interface}.{vlan_id}"
        self._run_cmd(["ip", "link", "add", "link", self.interface,
                        "name", iface, "type", "vlan", "id", str(vlan_id)])
        self._run_cmd(["ip", "link", "set", iface, "up"])
        return iface

    def _obtain_dhcp(self, iface: str) -> str | None:
        """Get IP via DHCP. Returns IP or None on failure."""
        result = self._run_cmd(["dhclient", "-1", "-v", iface], check=False)
        if self.dry_run:
            return "192.168.0.100"  # Fake IP for dry-run

        # Parse assigned IP from interface
        ip_result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", iface],
            capture_output=True, text=True
        )
        for line in ip_result.stdout.strip().split("\n"):
            parts = line.split()
            for i, part in enumerate(parts):
                if part == "inet":
                    return parts[i + 1].split("/")[0]
        return None

    def _obtain_dhcp_with_retry(self, iface: str, vlan_id: int) -> str | None:
        """DHCP with retry — try for a different IP but accept duplicate after retries."""
        ip = None
        last_ip = None
        for attempt in range(3):
            ip = self._obtain_dhcp(iface)
            if ip is None:
                self.log.warning(f"DHCP failed on attempt {attempt + 1}", extra={
                    "bot_module": "vlan_hopper", "vlan_id": vlan_id
                })
                continue
            last_ip = ip
            if self.lease_db.check_duplicate(vlan_id, ip):
                self.log.warning(f"Duplicate IP {ip} on VLAN {vlan_id}, retrying", extra={
                    "bot_module": "vlan_hopper", "vlan_id": vlan_id, "source_ip": ip
                })
                self._run_cmd(["dhclient", "-r", iface], check=False)
                ip = None
                continue
            break

        # Accept duplicate IP if DHCP keeps giving the same one
        if not ip and last_ip:
            self.log.warning(f"Accepting duplicate IP {last_ip} on VLAN {vlan_id}", extra={
                "bot_module": "vlan_hopper", "vlan_id": vlan_id, "source_ip": last_ip
            })
            # Re-obtain the lease we released
            ip = self._obtain_dhcp(iface) or last_ip

        return ip

    def _setup_policy_routing(self, ip: str, gateway: str, iface: str) -> None:
        """Add policy routing so attack traffic uses the VLAN interface."""
        self._run_cmd(["ip", "rule", "add", "from", ip, "table", "attack"], check=False)
        self._run_cmd(["ip", "route", "add", "default", "via", gateway,
                        "dev", iface, "table", "attack"], check=False)

    def _teardown(self, vlan_id: int, ip: str | None, iface: str) -> None:
        """Clean up: release DHCP, flush routes, delete interface."""
        self.log.info(f"Tearing down VLAN {vlan_id}", extra={
            "bot_module": "vlan_hopper", "vlan_id": vlan_id
        })
        if ip:
            self._run_cmd(["ip", "rule", "del", "from", ip, "table", "attack"], check=False)
        self._run_cmd(["ip", "route", "flush", "table", "attack"], check=False)
        self._run_cmd(["dhclient", "-r", iface], check=False)
        self._run_cmd(["ip", "link", "set", iface, "down"], check=False)
        self._run_cmd(["ip", "link", "delete", iface], check=False)
        self._current_vlan = None
        self._current_iface = None
        self._current_ip = None
        self._state = "cooldown"

    def teardown_current(self) -> None:
        """Public teardown of current VLAN interface. Idempotent."""
        if self._current_iface and self._current_vlan:
            self._teardown(self._current_vlan, self._current_ip, self._current_iface)

    def hop_to_vlan(self, vlan_id: int) -> dict:
        """Hop to a specific VLAN, discover hosts, but do NOT attack or tear down.

        Caller is responsible for calling teardown_current() when done.

        Returns:
            dict with status, vlan_id, ip, iface, gateway, hosts
        """
        vlan = None
        for v in self.vlans:
            if v["id"] == vlan_id:
                vlan = v
                break
        if not vlan:
            return {"status": "error", "message": f"VLAN {vlan_id} not in config"}

        gateway = vlan.get("gateway", "")
        static_targets = vlan.get("targets") or []

        self.log.info(f"Hopping to VLAN {vlan_id} ({vlan.get('name', '')})", extra={
            "bot_module": "vlan_hopper", "vlan_id": vlan_id
        })
        self._state = "hopping"
        self._current_vlan = vlan_id

        iface = self._create_vlan_iface(vlan_id)
        self._current_iface = iface

        ip = self._obtain_dhcp_with_retry(iface, vlan_id)

        if not ip:
            self.log.error(f"Failed to obtain IP on VLAN {vlan_id}", extra={
                "bot_module": "vlan_hopper", "vlan_id": vlan_id
            })
            self._teardown(vlan_id, None, iface)
            return {"status": "error", "vlan_id": vlan_id, "message": "DHCP failed"}

        self._current_ip = ip
        self.log.info(f"Got IP {ip} on VLAN {vlan_id}", extra={
            "bot_module": "vlan_hopper", "vlan_id": vlan_id, "source_ip": ip
        })

        # Policy routing
        if gateway:
            self._setup_policy_routing(ip, gateway, iface)

        # Discover live hosts
        hosts = []
        if gateway:
            subnet = gateway_to_subnet(gateway)
            excluded = [gateway]
            hosts = discover_hosts(subnet, iface, ip, excluded=excluded,
                                   dry_run=self.dry_run)

        # Fallback to static targets if discovery finds nothing
        if not hosts and static_targets:
            self.log.info(f"Discovery found no hosts, falling back to {len(static_targets)} static target(s)",
                          extra={"bot_module": "vlan_hopper", "vlan_id": vlan_id})
            hosts = list(static_targets)

        return {
            "status": "ready",
            "vlan_id": vlan_id,
            "ip": ip,
            "iface": iface,
            "gateway": gateway,
            "hosts": hosts,
        }

    def hop_once(self, vlan_filter: list[int] | None = None) -> dict:
        """Execute a single VLAN hop cycle.

        Args:
            vlan_filter: If provided, only hop to VLANs with these IDs.
        """
        available_vlans = self.vlans
        if vlan_filter is not None:
            available_vlans = [v for v in self.vlans if v["id"] in vlan_filter]
            if not available_vlans:
                self.log.error("No VLANs match filter", extra={"bot_module": "vlan_hopper"})
                return {"status": "error", "message": "No VLANs match filter"}
        vlan = random.choice(available_vlans)
        vlan_id = vlan["id"]
        gateway = vlan.get("gateway", "")
        static_targets = vlan.get("targets") or []

        self.log.info(f"Hopping to VLAN {vlan_id} ({vlan.get('name', '')})", extra={
            "bot_module": "vlan_hopper", "vlan_id": vlan_id
        })
        self._state = "hopping"
        self._current_vlan = vlan_id

        iface = self._create_vlan_iface(vlan_id)
        self._current_iface = iface

        ip = self._obtain_dhcp_with_retry(iface, vlan_id)

        if not ip:
            self.log.error(f"Failed to obtain IP on VLAN {vlan_id}", extra={
                "bot_module": "vlan_hopper", "vlan_id": vlan_id
            })
            self._teardown(vlan_id, None, iface)
            return {"status": "error", "vlan_id": vlan_id, "message": "DHCP failed"}

        self._current_ip = ip
        self.log.info(f"Got IP {ip} on VLAN {vlan_id}", extra={
            "bot_module": "vlan_hopper", "vlan_id": vlan_id, "source_ip": ip
        })

        # Policy routing
        if gateway:
            self._setup_policy_routing(ip, gateway, iface)

        # Discover live hosts, fallback to static targets
        targets = []
        if gateway:
            subnet = gateway_to_subnet(gateway)
            excluded = [gateway]
            targets = discover_hosts(subnet, iface, ip, excluded=excluded,
                                     dry_run=self.dry_run)
        if not targets:
            targets = list(static_targets)

        if not targets:
            self.log.warning(f"No targets found on VLAN {vlan_id}, skipping attack",
                             extra={"bot_module": "vlan_hopper", "vlan_id": vlan_id})
            self._teardown(vlan_id, ip, iface)
            return {"status": "skipped", "vlan_id": vlan_id, "ip": ip,
                    "message": "No targets found"}

        # Bind modules to VLAN source IP and interface
        for mod in self.modules.values():
            mod.source_ip = ip
            mod.interface = iface

        # Run modules
        self._state = "attacking"
        start_time = time.time()
        results = []

        from chaos_bot.scheduler import run_once
        results = run_once(self.modules, targets, self.config)

        duration = time.time() - start_time
        module_names = [r.get("module", "unknown") for r in results]

        # Record lease
        mac = self._get_mac(iface)
        self.lease_db.record_lease(vlan_id, ip, mac, module_names, duration)

        if self.metrics:
            self.metrics.record_hop(vlan_id, ip, duration, results)

        # Teardown
        self._teardown(vlan_id, ip, iface)

        summary = {
            "status": "complete",
            "vlan_id": vlan_id,
            "ip": ip,
            "duration_sec": round(duration, 1),
            "modules_run": module_names,
            "results": results,
        }

        if self.notifier:
            self.notifier.send_cycle_summary(summary)

        return summary

    def _get_mac(self, iface: str) -> str:
        """Get MAC address of interface."""
        if self.dry_run:
            return "00:00:00:00:00:00"
        try:
            result = subprocess.run(
                ["ip", "link", "show", iface],
                capture_output=True, text=True
            )
            for line in result.stdout.split("\n"):
                line = line.strip()
                if line.startswith("link/ether"):
                    return line.split()[1]
        except Exception:
            pass
        return "unknown"

    def run_daemon(self, stop_event=None, vlan_filter: list[int] | None = None) -> None:
        """Continuously hop VLANs until stopped."""
        self._running = True

        def _signal_handler(signum, frame):
            self.log.info("Signal received, initiating clean shutdown", extra={
                "bot_module": "vlan_hopper"
            })
            self._running = False
            if stop_event:
                stop_event.set()

        import threading
        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGINT, _signal_handler)
            signal.signal(signal.SIGTERM, _signal_handler)

        while self._running:
            if stop_event and stop_event.is_set():
                break

            try:
                self.hop_once(vlan_filter=vlan_filter)
            except Exception as e:
                self.log.error(f"Hop cycle failed: {e}", extra={
                    "bot_module": "vlan_hopper"
                }, exc_info=True)
                if self._current_iface and self._current_vlan:
                    self._teardown(self._current_vlan, self._current_ip, self._current_iface)

            # Cooldown
            self._state = "cooldown"
            cooldown = random.uniform(
                self.schedule.get("cooldown_min", 30),
                self.schedule.get("cooldown_max", 120),
            )
            self.log.info(f"Cooldown {cooldown:.1f}s", extra={"bot_module": "vlan_hopper"})
            if stop_event:
                stop_event.wait(timeout=cooldown)
            else:
                time.sleep(cooldown)

        self._state = "idle"
        self.log.info("VLAN hopper stopped", extra={"bot_module": "vlan_hopper"})

    def stop(self) -> None:
        """Request graceful stop."""
        self._running = False
        if self._current_iface and self._current_vlan:
            self._teardown(self._current_vlan, self._current_ip, self._current_iface)
