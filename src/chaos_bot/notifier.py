"""Apprise notification sender for chaos-bot cycle summaries."""

import json

import requests

from chaos_bot.logger import get_logger


class AppriseNotifier:
    """Send notifications via Apprise API."""

    def __init__(self, config: dict):
        self.log = get_logger()
        notif_cfg = config.get("notifications", {})
        self.enabled = notif_cfg.get("enabled", False)
        self.url = notif_cfg.get("apprise_url", "http://10.10.10.3:8800/notify")
        self.on_cycle = notif_cfg.get("on_cycle_complete", True)
        self.on_error = notif_cfg.get("on_error", True)

    def _send(self, title: str, body: str) -> None:
        """POST to Apprise API."""
        if not self.enabled:
            return
        try:
            resp = requests.post(
                self.url,
                json={"title": title, "body": body},
                timeout=10,
            )
            if resp.status_code >= 400:
                self.log.warning(
                    f"Apprise returned {resp.status_code}",
                    extra={"bot_module": "notifier"},
                )
        except requests.RequestException as e:
            self.log.warning(
                f"Apprise notification failed: {e}",
                extra={"bot_module": "notifier"},
            )

    def send_cycle_summary(self, summary: dict) -> None:
        """Send cycle completion notification."""
        if not self.on_cycle:
            return
        vlan = summary.get("vlan_id", "?")
        ip = summary.get("ip", "?")
        duration = summary.get("duration_sec", 0)
        modules = ", ".join(summary.get("modules_run", []))
        body = (
            f"VLAN {vlan} | IP {ip} | {duration}s\n"
            f"Modules: {modules}"
        )
        self._send("Chaos Bot — Cycle Complete", body)

    def send_error(self, message: str) -> None:
        """Send error notification."""
        if not self.on_error:
            return
        self._send("Chaos Bot — Error", message)
