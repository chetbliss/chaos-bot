"""Network scanner module — nmap scans bound to attack interface."""

import random
import subprocess
import time

from chaos_bot.modules.base import BaseModule


class NetScanner(BaseModule):
    """Run nmap scans with randomized target order and intensity."""

    def run(self, targets: list[str]) -> dict:
        mod_cfg = self.config.get("modules", {}).get("net_scanner", {})
        intensity = mod_cfg.get("intensity", "medium")
        port_list = mod_cfg.get("port_list", "22,80,443,445,3389,8080,8443")

        shuffled = list(targets)
        random.shuffle(shuffled)

        results = []
        scan_type = self._pick_scan_type(intensity)

        for target in shuffled:
            self.log.info(
                f"Scanning {target} ({scan_type})",
                extra={"bot_module": "net_scanner", "target_ip": target,
                       "source_ip": self.source_ip},
            )

            if self.dry_run:
                results.append({"target": target, "scan": scan_type, "status": "dry-run"})
                continue

            try:
                result = self._run_nmap(target, scan_type, port_list)
                results.append(result)
                if self.metrics:
                    hosts = result.get("hosts_up", 0)
                    ports = result.get("open_ports", 0)
                    self.metrics.scan_hosts_found.inc(hosts)
                    self.metrics.scan_ports_found.inc(ports)
            except Exception as e:
                self.log.error(f"Scan failed for {target}: {e}",
                               extra={"bot_module": "net_scanner", "target_ip": target})
                results.append({"target": target, "status": "error", "message": str(e)})

            # Jitter between targets
            time.sleep(random.uniform(0.5, 3.0))

        return {
            "status": "complete",
            "summary": f"{scan_type} scan of {len(shuffled)} targets",
            "details": results,
        }

    def _pick_scan_type(self, intensity: str) -> str:
        """Select scan type based on intensity level."""
        if intensity == "low":
            return random.choice(["syn", "syn"])
        elif intensity == "high":
            return random.choice(["syn", "service", "aggressive", "arp"])
        else:  # medium
            return random.choice(["syn", "service", "os"])

    def _run_nmap(self, target: str, scan_type: str, port_list: str) -> dict:
        """Execute nmap scan and parse basic output."""
        extra_args = ["-p", port_list]

        if scan_type == "syn":
            extra_args.extend(["-sS"])
        elif scan_type == "service":
            extra_args.extend(["-sS", "-sV"])
        elif scan_type == "os":
            extra_args.extend(["-sS", "-sV", "-O"])
        elif scan_type == "aggressive":
            extra_args.extend(["-A"])
        elif scan_type == "arp":
            extra_args = ["-sn", "-PR"]  # ARP sweep, no port list

        cmd = self._nmap_args(extra_args + [target])
        self.log.debug(f"Running: {' '.join(cmd)}", extra={"bot_module": "net_scanner"})

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        # Parse basic results from stdout
        hosts_up = 0
        open_ports = 0
        for line in proc.stdout.split("\n"):
            if "Host is up" in line:
                hosts_up += 1
            if "/open/" in line or "open" in line.split():
                open_ports += 1

        return {
            "target": target,
            "scan": scan_type,
            "status": "complete",
            "hosts_up": hosts_up,
            "open_ports": open_ports,
            "exit_code": proc.returncode,
        }
