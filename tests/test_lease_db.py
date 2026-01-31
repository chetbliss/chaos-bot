"""Tests for lease DB CRUD operations."""

import pytest

from chaos_bot.lease_db import LeaseDB


@pytest.fixture
def db(tmp_path):
    return LeaseDB(db_path=tmp_path / "test.db")


def test_record_and_retrieve(db):
    row_id = db.record_lease(20, "10.20.0.100", "aa:bb:cc:dd:ee:ff", ["net_scanner"], 45.2)
    assert row_id == 1

    history = db.get_history()
    assert len(history) == 1
    assert history[0]["vlan_id"] == 20
    assert history[0]["ip"] == "10.20.0.100"


def test_filter_by_vlan(db):
    db.record_lease(20, "10.20.0.1", "aa:bb:cc:dd:ee:01", ["net_scanner"], 10.0)
    db.record_lease(30, "10.30.0.1", "aa:bb:cc:dd:ee:02", ["auth_prober"], 20.0)
    db.record_lease(20, "10.20.0.2", "aa:bb:cc:dd:ee:03", ["dns_noise"], 15.0)

    vlan20 = db.get_history(vlan_id=20)
    assert len(vlan20) == 2
    assert all(r["vlan_id"] == 20 for r in vlan20)

    vlan30 = db.get_history(vlan_id=30)
    assert len(vlan30) == 1


def test_check_duplicate(db):
    db.record_lease(20, "10.20.0.100", "aa:bb:cc:dd:ee:ff", ["scan"], 10.0)
    assert db.check_duplicate(20, "10.20.0.100") is True
    assert db.check_duplicate(20, "10.20.0.200") is False
    assert db.check_duplicate(30, "10.20.0.100") is False


def test_clear(db):
    db.record_lease(20, "10.20.0.1", "mac", ["m"], 1.0)
    db.record_lease(20, "10.20.0.2", "mac", ["m"], 1.0)
    count = db.clear()
    assert count == 2
    assert len(db.get_history()) == 0


def test_last_limit(db):
    for i in range(10):
        db.record_lease(20, f"10.20.0.{i}", "mac", ["m"], 1.0)

    last5 = db.get_history(last=5)
    assert len(last5) == 5
    # Should be most recent first
    assert last5[0]["ip"] == "10.20.0.9"
