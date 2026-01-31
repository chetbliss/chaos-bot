"""Flask C2 web UI and API for chaos-bot."""

import json
import time
import threading
from datetime import datetime, timezone

from flask import Flask, render_template, request, jsonify, Response, stream_with_context

from chaos_bot.config import load_config
from chaos_bot.lease_db import LeaseDB
from chaos_bot.logger import get_log_buffer

app = Flask(__name__)

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

    def _hop():
        result = hopper.hop_once()
        _state["cycle_summaries"].append(result)
        if len(_state["cycle_summaries"]) > 50:
            _state["cycle_summaries"] = _state["cycle_summaries"][-50:]

    t = threading.Thread(target=_hop, daemon=True)
    t.start()
    return jsonify({"status": "hop_triggered"})


@app.route("/api/v1/start", methods=["POST"])
def api_start():
    hopper = _state.get("hopper")
    if not hopper:
        return jsonify({"error": "Hopper not initialized"}), 503

    stop_event = _state.get("stop_event")
    if stop_event:
        stop_event.clear()

    def _run_daemon():
        hopper.run_daemon(stop_event=stop_event)

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
        last_idx = len(get_log_buffer())
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
