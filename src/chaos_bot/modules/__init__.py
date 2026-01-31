"""Chaos-bot module registry."""

from chaos_bot.modules.net_scanner import NetScanner
from chaos_bot.modules.auth_prober import AuthProber
from chaos_bot.modules.dns_noise import DnsNoise
from chaos_bot.modules.http_probe import HttpProbe

MODULES = {
    "net_scanner": NetScanner,
    "auth_prober": AuthProber,
    "dns_noise": DnsNoise,
    "http_probe": HttpProbe,
}


def build_modules(source_ip: str, interface: str, config: dict,
                   metrics=None, module_filter: list[str] | None = None) -> dict:
    """Instantiate enabled modules, optionally filtering by name."""
    from chaos_bot.logger import get_logger
    log = get_logger()
    built = {}
    for name, cls in MODULES.items():
        if module_filter and name not in module_filter:
            continue
        mod_cfg = config.get("modules", {}).get(name, {})
        if not mod_cfg.get("enabled", True):
            continue
        built[name] = cls(
            source_ip=source_ip,
            interface=interface,
            config=config,
            metrics=metrics,
            logger=log,
        )
    return built
