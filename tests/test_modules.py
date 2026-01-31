"""Tests for module instantiation and dry-run execution."""

import logging

import pytest

from chaos_bot.modules.base import BaseModule
from chaos_bot.modules.net_scanner import NetScanner
from chaos_bot.modules.auth_prober import AuthProber
from chaos_bot.modules.dns_noise import DnsNoise
from chaos_bot.modules.http_probe import HttpProbe
from chaos_bot.modules import MODULES, build_modules


DRY_CONFIG = {
    "general": {"hostname": "test", "interface": "eth0", "dry_run": True},
    "vlans": [{"id": 10, "targets": ["10.0.0.1"]}],
    "schedule": {"module_delay_min": 0, "module_delay_max": 0},
    "modules": {
        "net_scanner": {"enabled": True, "intensity": "low", "port_list": "22,80"},
        "auth_prober": {"enabled": True, "max_attempts": 2, "protocols": ["ssh"]},
        "dns_noise": {"enabled": True, "resolver": "127.0.0.1", "query_count": 3},
        "http_probe": {"enabled": True, "paths": ["/admin"]},
    },
    "credentials": {"username": "test", "password": "test"},
}

TARGETS = ["10.0.0.1", "10.0.0.2"]


@pytest.fixture
def logger():
    return logging.getLogger("chaos_bot_test")


def test_module_registry():
    assert "net_scanner" in MODULES
    assert "auth_prober" in MODULES
    assert "dns_noise" in MODULES
    assert "http_probe" in MODULES


def test_base_module_is_abstract():
    with pytest.raises(TypeError):
        BaseModule(source_ip="0.0.0.0", interface="eth0", config={})


def test_net_scanner_dry_run(logger):
    mod = NetScanner("0.0.0.0", "eth0", DRY_CONFIG, logger=logger)
    result = mod.run(TARGETS)
    assert result["status"] == "complete"
    assert len(result["details"]) == len(TARGETS)
    assert all(d["status"] == "dry-run" for d in result["details"])


def test_auth_prober_dry_run(logger):
    mod = AuthProber("0.0.0.0", "eth0", DRY_CONFIG, logger=logger)
    result = mod.run(TARGETS)
    assert result["status"] == "complete"
    assert all(d["status"] == "dry-run" for d in result["details"])


def test_dns_noise_dry_run(logger):
    mod = DnsNoise("0.0.0.0", "eth0", DRY_CONFIG, logger=logger)
    result = mod.run(TARGETS)
    assert result["status"] == "complete"
    assert len(result["details"]) > 0
    assert all(d["status"] == "dry-run" for d in result["details"])


def test_http_probe_dry_run(logger):
    mod = HttpProbe("0.0.0.0", "eth0", DRY_CONFIG, logger=logger)
    result = mod.run(TARGETS)
    assert result["status"] == "complete"
    assert all(d["status"] == "dry-run" for d in result["details"])


def test_build_modules_all(logger):
    built = build_modules("0.0.0.0", "eth0", DRY_CONFIG)
    assert set(built.keys()) == {"net_scanner", "auth_prober", "dns_noise", "http_probe"}


def test_build_modules_filter(logger):
    built = build_modules("0.0.0.0", "eth0", DRY_CONFIG, module_filter=["net_scanner"])
    assert list(built.keys()) == ["net_scanner"]


def test_build_modules_disabled(logger):
    cfg = {**DRY_CONFIG, "modules": {
        **DRY_CONFIG["modules"],
        "dns_noise": {"enabled": False},
    }}
    built = build_modules("0.0.0.0", "eth0", cfg)
    assert "dns_noise" not in built


# ── v0.1.1 Web API tests ────────────────────────────────────

from unittest.mock import MagicMock, patch
from chaos_bot.web import app, _state, init_app

WEB_CONFIG = {
    "general": {"hostname": "test", "interface": "eth0", "dry_run": True, "management_ip": "10.10.10.4"},
    "vlans": [
        {"id": 30, "name": "servers", "gateway": "10.30.30.1", "targets": ["10.30.30.10", "10.30.30.11"]},
        {"id": 40, "name": "honeypot", "gateway": "10.40.40.1", "targets": []},
    ],
    "schedule": {"module_delay_min": 0, "module_delay_max": 0},
    "modules": {
        "net_scanner": {"enabled": True, "intensity": "low", "port_list": "22,80"},
        "auth_prober": {"enabled": True, "max_attempts": 2, "protocols": ["ssh"]},
        "dns_noise": {"enabled": True, "resolver": "127.0.0.1", "query_count": 3},
        "http_probe": {"enabled": True, "paths": ["/admin"]},
    },
    "credentials": {"username": "test", "password": "test"},
}


@pytest.fixture
def web_client():
    app.config["TESTING"] = True
    mock_hopper = MagicMock()
    mock_hopper.state = "idle"
    mock_hopper.current_vlan = None
    mock_hopper.current_ip = None
    init_app(WEB_CONFIG, hopper=mock_hopper)
    with app.test_client() as client:
        yield client, mock_hopper


def test_trigger_api_rejects_while_attacking(web_client):
    client, hopper = web_client
    hopper.state = "attacking"
    resp = client.post("/api/v1/trigger",
                       json={"modules": ["net_scanner"], "targets": ["10.30.30.10"]})
    assert resp.status_code == 409
    assert "attacking" in resp.get_json()["error"]


def test_trigger_api_rejects_empty_modules(web_client):
    client, hopper = web_client
    resp = client.post("/api/v1/trigger",
                       json={"modules": [], "targets": ["10.30.30.10"]})
    assert resp.status_code == 400
    assert "No modules" in resp.get_json()["error"]


def test_trigger_api_rejects_empty_targets(web_client):
    client, hopper = web_client
    resp = client.post("/api/v1/trigger",
                       json={"modules": ["net_scanner"], "targets": []})
    assert resp.status_code == 400
    assert "No targets" in resp.get_json()["error"]


def test_modules_api_returns_all(web_client):
    client, _ = web_client
    resp = client.get("/api/v1/modules")
    assert resp.status_code == 200
    data = resp.get_json()
    names = [m["name"] for m in data["modules"]]
    assert "net_scanner" in names
    assert "auth_prober" in names
    assert "dns_noise" in names
    assert "http_probe" in names


def test_targets_api_returns_vlans(web_client):
    client, _ = web_client
    resp = client.get("/api/v1/targets")
    assert resp.status_code == 200
    data = resp.get_json()
    vlan_ids = [v["id"] for v in data["vlans"]]
    assert 30 in vlan_ids
    assert 40 in vlan_ids
    # Check targets present for VLAN 30
    vlan30 = next(v for v in data["vlans"] if v["id"] == 30)
    assert "10.30.30.10" in vlan30["targets"]


def test_start_rejects_while_attacking(web_client):
    client, hopper = web_client
    hopper.state = "attacking"
    resp = client.post("/api/v1/start")
    assert resp.status_code == 409
    assert "attacking" in resp.get_json()["error"]
