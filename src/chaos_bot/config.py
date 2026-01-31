"""YAML config loader and validation for chaos-bot."""

import os
from pathlib import Path

import yaml


DEFAULT_CONFIG_PATHS = [
    Path("config.yml"),
    Path("/etc/chaos-bot/config.yml"),
    Path.home() / ".chaos-bot" / "config.yml",
]

REQUIRED_SECTIONS = ["general", "vlans", "schedule", "modules"]


def find_config(override_path: str | None = None) -> Path:
    """Locate config file, checking override then default paths."""
    if override_path:
        p = Path(override_path)
        if not p.exists():
            raise FileNotFoundError(f"Config file not found: {p}")
        return p
    for p in DEFAULT_CONFIG_PATHS:
        if p.exists():
            return p
    raise FileNotFoundError(
        f"No config found. Searched: {[str(p) for p in DEFAULT_CONFIG_PATHS]}"
    )


def load_config(path: str | None = None, overrides: dict | None = None) -> dict:
    """Load and validate config, merging CLI overrides."""
    config_path = find_config(path)
    with open(config_path) as f:
        cfg = yaml.safe_load(f)

    if cfg is None:
        raise ValueError(f"Empty config file: {config_path}")

    for section in REQUIRED_SECTIONS:
        if section not in cfg:
            raise ValueError(f"Missing required config section: {section}")

    if not cfg.get("vlans"):
        raise ValueError("Config must define at least one VLAN")

    for vlan in cfg["vlans"]:
        if "id" not in vlan or "targets" not in vlan:
            raise ValueError(f"VLAN entry missing 'id' or 'targets': {vlan}")

    # Apply CLI overrides
    if overrides:
        _merge(cfg, overrides)

    # Ensure defaults
    cfg.setdefault("credentials", {"username": "chaos-bot", "password": "NotARealPassword"})
    cfg.setdefault("excluded_hosts", [])
    cfg.setdefault("notifications", {"enabled": False})
    cfg.setdefault("metrics", {"enabled": False})
    cfg.setdefault("web", {"enabled": False})

    cfg["_config_path"] = str(config_path)
    return cfg


def _merge(base: dict, override: dict) -> dict:
    """Deep-merge override into base dict."""
    for key, val in override.items():
        if isinstance(val, dict) and isinstance(base.get(key), dict):
            _merge(base[key], val)
        else:
            base[key] = val
    return base
