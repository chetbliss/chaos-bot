"""Flask C2 web UI and API for chaos-bot."""

import json
import time
import threading
from datetime import datetime, timezone

from flask import Flask, render_template, request, jsonify, Response, stream_with_context

import requests as http_requests

from chaos_bot.config import load_config
from chaos_bot.lease_db import LeaseDB
from chaos_bot.logger import get_log_buffer
from chaos_bot.modules import MODULES, build_modules
from chaos_bot.scheduler import run_once

app = Flask(__name__)


@app.after_request
def add_no_cache_headers(response):
    """Prevent browser caching of HTML pages."""
    if response.content_type and 'text/html' in response.content_type:
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

# Shared state — set by cli.py or external caller before app.run()
_state = {
    "status": "idle",      # idle | hopping | attacking | cooldown
    "current_vlan": None,
    "current_ip": None,
    "uptime_start": None,
    "cycle_summaries": [],  # last N cycle results
    "hopper": None,         # VlanHopper instance
    "stop_event": None,     # threading.Event
    "config": None,
    "daemon_thread": None,
    "selected_modules": [],
    "selected_targets": [],
    "selected_vlans": [],
}


def init_app(config: dict, hopper=None, stop_event=None):
    """Initialize web app with shared state."""
    _state["config"] = config
    _state["hopper"] = hopper
    _state["stop_event"] = stop_event or threading.Event()
    _state["uptime_start"] = datetime.now(timezone.utc).isoformat()


# ── HTML Routes ──────────────────────────────────────────────

@app.route("/")
def dashboard():
    db = LeaseDB()
    recent = db.get_history(last=10)
    return render_template("dashboard.html",
                           state=_state,
                           recent_leases=recent)


@app.route("/history")
def history_page():
    vlan = request.args.get("vlan", type=int)
    db = LeaseDB()
    leases = db.get_history(vlan_id=vlan, last=100)
    vlans = _state["config"].get("vlans", []) if _state["config"] else []
    return render_template("history.html",
                           leases=leases,
                           vlans=vlans,
                           selected_vlan=vlan)


@app.route("/config")
def config_page():
    cfg = _state["config"] or {}
    cfg_display = {k: v for k, v in cfg.items() if not k.startswith("_")}
    return render_template("config.html", config=cfg_display)


@app.route("/logs")
def logs_page():
    return render_template("logs.html")


# ── API Routes ───────────────────────────────────────────────

@app.route("/api/v1/status")
def api_status():
    hopper = _state.get("hopper")
    return jsonify({
        "status": hopper.state if hopper else _state["status"],
        "current_vlan": hopper.current_vlan if hopper else _state["current_vlan"],
        "current_ip": hopper.current_ip if hopper else _state["current_ip"],
        "uptime_start": _state["uptime_start"],
        "cycle_count": len(_state["cycle_summaries"]),
        "last_cycle": _state["cycle_summaries"][-1] if _state["cycle_summaries"] else None,
    })


@app.route("/api/v1/hop", methods=["POST"])
def api_hop():
    hopper = _state.get("hopper")
    if not hopper:
        return jsonify({"error": "Hopper not initialized"}), 503
    if hopper.state == "attacking":
        return jsonify({"error": "Cannot hop: currently attacking"}), 409
    if hopper.state == "hopping":
        return jsonify({"error": "Cannot hop: already hopping"}), 409

    def _hop():
        try:
            result = hopper.hop_once()
            _state["cycle_summaries"].append(result)
            if len(_state["cycle_summaries"]) > 50:
                _state["cycle_summaries"] = _state["cycle_summaries"][-50:]
        except Exception:
            import traceback
            traceback.print_exc()
            hopper._state = "idle"
            if hopper._current_iface and hopper._current_vlan:
                hopper._teardown(hopper._current_vlan, hopper._current_ip, hopper._current_iface)

    t = threading.Thread(target=_hop, daemon=True)
    t.start()
    return jsonify({"status": "hop_triggered"})


@app.route("/api/v1/start", methods=["POST"])
def api_start():
    hopper = _state.get("hopper")
    if not hopper:
        return jsonify({"error": "Hopper not initialized"}), 503
    if hopper.state not in ("idle", "cooldown"):
        return jsonify({"error": f"Cannot start: currently {hopper.state}"}), 409

    stop_event = _state.get("stop_event")
    if stop_event:
        stop_event.clear()

    # Accept optional VLAN filter from request body
    vlan_filter = None
    body = request.get_json(silent=True)
    if body and body.get("vlans"):
        vlan_filter = [int(v) for v in body["vlans"]]

    def _run_daemon():
        hopper.run_daemon(stop_event=stop_event, vlan_filter=vlan_filter)

    if _state.get("daemon_thread") and _state["daemon_thread"].is_alive():
        return jsonify({"status": "already_running"})

    t = threading.Thread(target=_run_daemon, daemon=True)
    t.start()
    _state["daemon_thread"] = t
    return jsonify({"status": "started"})


@app.route("/api/v1/stop", methods=["POST"])
def api_stop():
    hopper = _state.get("hopper")
    stop_event = _state.get("stop_event")
    if stop_event:
        stop_event.set()
    if hopper:
        hopper.stop()
    return jsonify({"status": "stop_requested"})


@app.route("/api/v1/history")
def api_history():
    vlan = request.args.get("vlan", type=int)
    last = request.args.get("last", 50, type=int)
    db = LeaseDB()
    return jsonify(db.get_history(vlan_id=vlan, last=last))


@app.route("/api/v1/config", methods=["GET"])
def api_config_get():
    cfg = _state["config"] or {}
    safe = {k: v for k, v in cfg.items() if not k.startswith("_")}
    return jsonify(safe)


@app.route("/api/v1/config", methods=["PUT"])
def api_config_put():
    hopper = _state.get("hopper")
    if hopper and hopper.state == "attacking":
        return jsonify({"error": "Cannot update config while attacking"}), 409
    try:
        new_cfg = request.get_json()
        if not new_cfg:
            return jsonify({"error": "No JSON body"}), 400

        # Reload and merge
        current = _state["config"] or {}
        from chaos_bot.config import _merge
        _merge(current, new_cfg)
        _state["config"] = current
        return jsonify({"status": "updated"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/v1/logs")
def api_logs_sse():
    """Server-Sent Events stream of log lines."""
    def generate():
        # Send existing buffer first so page isn't empty
        buf = get_log_buffer()
        for line in buf:
            yield f"data: {line}\n\n"
        last_idx = len(buf)
        while True:
            buf = get_log_buffer()
            if len(buf) > last_idx:
                for line in buf[last_idx:]:
                    yield f"data: {line}\n\n"
                last_idx = len(buf)
            time.sleep(1)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/v1/modules")
def api_modules():
    """Return available modules and their enabled state."""
    cfg = _state.get("config") or {}
    mod_configs = cfg.get("modules", {})
    modules_list = []
    for name in MODULES:
        mod_cfg = mod_configs.get(name, {})
        modules_list.append({
            "name": name,
            "enabled": mod_cfg.get("enabled", True),
        })
    return jsonify({"modules": modules_list})


@app.route("/api/v1/targets")
def api_targets():
    """Return all targets grouped by VLAN."""
    cfg = _state.get("config") or {}
    vlans = cfg.get("vlans", [])
    vlan_list = []
    for vlan in vlans:
        vlan_list.append({
            "id": vlan.get("id"),
            "name": vlan.get("name", ""),
            "gateway": vlan.get("gateway", ""),
            "targets": vlan.get("targets") or [],
        })
    return jsonify({"vlans": vlan_list})


@app.route("/api/v1/trigger", methods=["POST"])
def api_trigger():
    """Run selected modules against selected hosts without hopping."""
    hopper = _state.get("hopper")
    if hopper and hopper.state == "attacking":
        return jsonify({"error": "Cannot trigger while attacking"}), 409
    if hopper and hopper.state == "hopping":
        return jsonify({"error": "Cannot trigger while hopping"}), 409

    body = request.get_json()
    if not body:
        return jsonify({"error": "No JSON body"}), 400

    modules_requested = body.get("modules", [])
    targets_requested = body.get("targets", [])

    if not modules_requested:
        return jsonify({"error": "No modules selected"}), 400
    if not targets_requested:
        return jsonify({"error": "No targets selected"}), 400

    # Validate module names
    for mod_name in modules_requested:
        if mod_name not in MODULES:
            return jsonify({"error": f"Unknown module: {mod_name}"}), 400

    # Validate targets against config
    cfg = _state.get("config") or {}
    valid_targets = set()
    for vlan in cfg.get("vlans", []):
        targets = vlan.get("targets") or []
        valid_targets.update(targets)
        if vlan.get("gateway"):
            valid_targets.add(vlan["gateway"])
    for target in targets_requested:
        if target not in valid_targets:
            return jsonify({"error": f"Target not in config: {target}"}), 400

    management_ip = cfg.get("general", {}).get("management_ip", "0.0.0.0")
    interface = cfg.get("general", {}).get("interface", "eth1")

    def _run_trigger():
        hopper = _state.get("hopper")
        if hopper:
            hopper._state = "attacking"
        try:
            built = build_modules(
                source_ip=management_ip,
                interface=interface,
                config=cfg,
                module_filter=modules_requested,
            )
            run_once(built, targets_requested, cfg)
        finally:
            if hopper:
                hopper._state = "idle"

    t = threading.Thread(target=_run_trigger, daemon=True)
    t.start()
    return jsonify({
        "status": "triggered",
        "modules": modules_requested,
        "targets": targets_requested,
    })


@app.route("/api/v1/alerts")
def api_alerts():
    """Proxy Suricata alerts from EveBox API."""
    cfg = _state.get("config") or {}
    evebox_cfg = cfg.get("evebox", {})
    evebox_url = evebox_cfg.get("url", "https://evebox.lab.chettv.com")
    evebox_user = evebox_cfg.get("username", "admin")
    evebox_pass = evebox_cfg.get("password", "")
    time_range = request.args.get("time_range", "86400s")

    try:
        session = http_requests.Session()
        session.verify = False  # internal HTTPS with self-signed cert

        # Authenticate to EveBox
        login_resp = session.post(
            f"{evebox_url}/api/login",
            data={"username": evebox_user, "password": evebox_pass},
            timeout=5,
        )
        if login_resp.status_code != 200:
            return jsonify({"error": "EveBox auth failed", "alerts": []}), 502

        resp = session.get(
            f"{evebox_url}/api/alerts",
            params={"time_range": time_range, "tags": "-archived"},
            timeout=5,
        )
        resp.raise_for_status()
        return jsonify(resp.json())
    except http_requests.RequestException as e:
        return jsonify({"error": f"EveBox unreachable: {e}", "alerts": []}), 502


def run_web(config: dict, hopper=None, stop_event=None):
    """Start the Flask web server."""
    init_app(config, hopper, stop_event)
    web_cfg = config.get("web", {})
    app.run(
        host=web_cfg.get("host", "0.0.0.0"),
        port=web_cfg.get("port", 8880),
        debug=False,
        use_reloader=False,
    )
