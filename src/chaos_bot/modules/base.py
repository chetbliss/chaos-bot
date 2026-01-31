"""Base module ABC for chaos-bot attack modules."""

import logging
import socket
from abc import ABC, abstractmethod


class BaseModule(ABC):
    """Abstract base for all chaos-bot modules.

    Provides source_ip binding and common nmap argument building.
    """

    def __init__(self, source_ip: str, interface: str, config: dict,
                 metrics=None, logger: logging.Logger | None = None):
        self.source_ip = source_ip
        self.interface = interface
        self.config = config
        self.metrics = metrics
        self.log = logger or logging.getLogger("chaos_bot")
        self.dry_run = config.get("general", {}).get("dry_run", False)

    def _bind_socket(self, sock: socket.socket) -> None:
        """Bind a socket to the source IP for traffic attribution."""
        sock.bind((self.source_ip, 0))

    def _nmap_args(self, extra: list[str] | None = None) -> list[str]:
        """Build nmap command with source IP and interface binding."""
        args = ["nmap", "-S", self.source_ip, "-e", self.interface]
        if extra:
            args.extend(extra)
        return args

    @abstractmethod
    def run(self, targets: list[str]) -> dict:
        """Execute module against targets.

        Returns:
            dict with keys: status, summary, details
        """
        ...
