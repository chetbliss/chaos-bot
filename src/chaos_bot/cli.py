"""Click CLI for chaos-bot."""

import json
import sys
import threading

import click

from chaos_bot import __version__
from chaos_bot.config import load_config
from chaos_bot.logger import setup_logging, get_logger


@click.group()
@click.version_option(__version__)
def cli():
    """Chaos Bot — Automated red-team traffic generator for lab security validation."""


@cli.command()
@click.option("--once", is_flag=True, help="Run all modules once and exit")
@click.option("--daemon", is_flag=True, help="Run continuously with randomized intervals")
@click.option("--dry-run", is_flag=True, help="Log actions without executing")
@click.option("--modules", type=str, default=None, help="Comma-separated module list")
@click.option("--config", "config_path", type=click.Path(), default=None, help="Config file path")
def run(once, daemon, dry_run, modules, config_path):
    """Run chaos-bot modules against configured targets."""
    cfg = load_config(config_path)
    if dry_run:
        cfg["general"]["dry_run"] = True

    log = setup_logging(
        level=cfg["general"].get("log_level", "INFO"),
        log_file=cfg["general"].get("log_file"),
    )
    log.info("chaos-bot starting", extra={"bot_module": "cli"})

    from chaos_bot.modules import build_modules
    from chaos_bot.metrics import ChaosMetrics
    from chaos_bot.notifier import AppriseNotifier

    metrics = ChaosMetrics()
    if cfg.get("metrics", {}).get("enabled"):
        metrics.start_server(
            port=cfg["metrics"].get("port", 9100),
            addr=cfg["metrics"].get("bind_address", "0.0.0.0"),
        )

    notifier = AppriseNotifier(cfg)

    # Collect all targets from all VLANs
    all_targets = []
    for vlan in cfg.get("vlans", []):
        all_targets.extend(vlan.get("targets", []))
    excluded = set(cfg.get("excluded_hosts", []))
    all_targets = [t for t in all_targets if t not in excluded]

    # Filter modules if specified
    module_filter = None
    if modules:
        module_filter = [m.strip() for m in modules.split(",")]

    built = build_modules(
        source_ip=cfg["general"].get("management_ip", "0.0.0.0"),
        interface=cfg["general"].get("interface", "eth1"),
        config=cfg,
        metrics=metrics,
        module_filter=module_filter,
    )

    if once or not daemon:
        from chaos_bot.scheduler import run_once
        results = run_once(built, all_targets, cfg)
        for r in results:
            click.echo(json.dumps(r, indent=2))
    else:
        from chaos_bot.scheduler import run_daemon
        stop_event = threading.Event()
        run_daemon(built, all_targets, cfg, stop_event=stop_event)


@cli.command()
@click.option("--once", is_flag=True, help="Single hop cycle and exit")
@click.option("--daemon", is_flag=True, help="Continuous VLAN hopping")
@click.option("--dry-run", is_flag=True, help="Log actions without executing")
@click.option("--vlans", type=str, default=None, help="Comma-separated VLAN IDs to hop")
@click.option("--dwell-min", type=int, default=None, help="Min dwell time (seconds)")
@click.option("--dwell-max", type=int, default=None, help="Max dwell time (seconds)")
@click.option("--config", "config_path", type=click.Path(), default=None, help="Config file path")
def hop(once, daemon, dry_run, vlans, dwell_min, dwell_max, config_path):
    """VLAN hopper mode — rotate through VLANs running modules from each."""
    cfg = load_config(config_path)
    if dry_run:
        cfg["general"]["dry_run"] = True

    log = setup_logging(
        level=cfg["general"].get("log_level", "INFO"),
        log_file=cfg["general"].get("log_file"),
    )

    # Apply VLAN filter
    if vlans:
        vlan_ids = {int(v.strip()) for v in vlans.split(",")}
        cfg["vlans"] = [v for v in cfg["vlans"] if v["id"] in vlan_ids]
        if not cfg["vlans"]:
            click.echo(f"No matching VLANs for: {vlans}", err=True)
            sys.exit(1)

    # Apply schedule overrides
    if dwell_min is not None:
        cfg["schedule"]["hop_dwell_min"] = dwell_min
    if dwell_max is not None:
        cfg["schedule"]["hop_dwell_max"] = dwell_max

    from chaos_bot.modules import build_modules
    from chaos_bot.metrics import ChaosMetrics
    from chaos_bot.notifier import AppriseNotifier
    from chaos_bot.vlan_hopper import VlanHopper

    metrics = ChaosMetrics()
    if cfg.get("metrics", {}).get("enabled"):
        metrics.start_server(
            port=cfg["metrics"].get("port", 9100),
            addr=cfg["metrics"].get("bind_address", "0.0.0.0"),
        )

    notifier = AppriseNotifier(cfg)
    built = build_modules(
        source_ip="0.0.0.0",  # Will be set per-hop
        interface=cfg["general"].get("interface", "eth1"),
        config=cfg,
        metrics=metrics,
    )

    hopper = VlanHopper(cfg, built, metrics=metrics, notifier=notifier)

    if once:
        result = hopper.hop_once()
        click.echo(json.dumps(result, indent=2))
    else:
        stop_event = threading.Event()
        hopper.run_daemon(stop_event=stop_event)


@cli.command()
@click.option("--vlan", type=int, default=None, help="Filter by VLAN ID")
@click.option("--last", type=int, default=20, help="Number of entries to show")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.option("--clear", is_flag=True, help="Delete all lease history")
@click.option("--config", "config_path", type=click.Path(), default=None, help="Config file path")
def history(vlan, last, fmt, clear, config_path):
    """View VLAN hop lease history."""
    from chaos_bot.lease_db import LeaseDB
    db = LeaseDB()

    if clear:
        count = db.clear()
        click.echo(f"Cleared {count} lease records")
        return

    rows = db.get_history(vlan_id=vlan, last=last)

    if fmt == "json":
        click.echo(json.dumps(rows, indent=2))
    else:
        if not rows:
            click.echo("No lease history found")
            return
        click.echo(f"{'ID':>5} {'VLAN':>5} {'IP':<16} {'MAC':<18} {'Timestamp':<26} {'Duration':>8} Modules")
        click.echo("-" * 100)
        for r in rows:
            modules = r.get("modules_run", "[]")
            if isinstance(modules, str):
                try:
                    modules = ", ".join(json.loads(modules))
                except (json.JSONDecodeError, TypeError):
                    pass
            click.echo(
                f"{r['id']:>5} {r['vlan_id']:>5} {r['ip']:<16} {r.get('mac', ''):<18} "
                f"{r['timestamp']:<26} {r.get('duration_sec', 0):>7.1f}s {modules}"
            )


@cli.command()
@click.option("--config", "config_path", type=click.Path(), default=None, help="Config file path")
def serve(config_path):
    """Start the C2 web UI (hopper idle until started from dashboard)."""
    cfg = load_config(config_path)

    log = setup_logging(
        level=cfg["general"].get("log_level", "INFO"),
        log_file=cfg["general"].get("log_file"),
    )
    log.info("chaos-bot web UI starting", extra={"bot_module": "cli"})

    from chaos_bot.modules import build_modules
    from chaos_bot.metrics import ChaosMetrics
    from chaos_bot.notifier import AppriseNotifier
    from chaos_bot.vlan_hopper import VlanHopper
    from chaos_bot.web import run_web

    metrics = ChaosMetrics()
    if cfg.get("metrics", {}).get("enabled"):
        metrics.start_server(
            port=cfg["metrics"].get("port", 9100),
            addr=cfg["metrics"].get("bind_address", "0.0.0.0"),
        )

    notifier = AppriseNotifier(cfg)
    built = build_modules(
        source_ip="0.0.0.0",
        interface=cfg["general"].get("interface", "eth1"),
        config=cfg,
        metrics=metrics,
    )

    hopper = VlanHopper(cfg, built, metrics=metrics, notifier=notifier)
    stop_event = threading.Event()

    log.info("Hopper initialized, idle until started from web UI", extra={"bot_module": "cli"})
    run_web(cfg, hopper=hopper, stop_event=stop_event)


@cli.command("config")
@click.option("--show", is_flag=True, help="Dump resolved config")
@click.option("--config", "config_path", type=click.Path(), default=None, help="Config file path")
def config_cmd(show, config_path):
    """View or validate configuration."""
    cfg = load_config(config_path)
    if show:
        # Remove internal keys
        cfg.pop("_config_path", None)
        click.echo(json.dumps(cfg, indent=2, default=str))
    else:
        click.echo(f"Config loaded from: {cfg.get('_config_path', 'unknown')}")
        click.echo(f"VLANs: {[v['id'] for v in cfg.get('vlans', [])]}")
        click.echo(f"Modules: {list(cfg.get('modules', {}).keys())}")
        click.echo(f"Notifications: {'enabled' if cfg.get('notifications', {}).get('enabled') else 'disabled'}")
        click.echo(f"Metrics: {'enabled' if cfg.get('metrics', {}).get('enabled') else 'disabled'}")
