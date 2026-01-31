"""Tests for config loading and validation."""

import os
import tempfile

import pytest
import yaml

from chaos_bot.config import load_config, find_config


MINIMAL_CONFIG = {
    "general": {"hostname": "test", "interface": "eth0"},
    "vlans": [{"id": 10, "targets": ["10.0.0.1"]}],
    "schedule": {"hop_dwell_min": 10, "hop_dwell_max": 30},
    "modules": {"net_scanner": {"enabled": True}},
}


@pytest.fixture
def config_file(tmp_path):
    path = tmp_path / "config.yml"
    path.write_text(yaml.dump(MINIMAL_CONFIG))
    return str(path)


def test_load_valid_config(config_file):
    cfg = load_config(config_file)
    assert cfg["general"]["hostname"] == "test"
    assert len(cfg["vlans"]) == 1
    assert cfg["vlans"][0]["id"] == 10


def test_missing_config_raises():
    with pytest.raises(FileNotFoundError):
        load_config("/nonexistent/path/config.yml")


def test_empty_config_raises(tmp_path):
    path = tmp_path / "empty.yml"
    path.write_text("")
    with pytest.raises(ValueError, match="Empty config"):
        load_config(str(path))


def test_missing_section_raises(tmp_path):
    incomplete = {"general": {"hostname": "test"}}
    path = tmp_path / "bad.yml"
    path.write_text(yaml.dump(incomplete))
    with pytest.raises(ValueError, match="Missing required"):
        load_config(str(path))


def test_overrides_applied(config_file):
    cfg = load_config(config_file, overrides={"general": {"hostname": "override"}})
    assert cfg["general"]["hostname"] == "override"


def test_defaults_applied(config_file):
    cfg = load_config(config_file)
    assert "credentials" in cfg
    assert "excluded_hosts" in cfg


def test_no_vlans_raises(tmp_path):
    bad = {**MINIMAL_CONFIG, "vlans": []}
    path = tmp_path / "novlan.yml"
    path.write_text(yaml.dump(bad))
    with pytest.raises(ValueError, match="at least one VLAN"):
        load_config(str(path))
