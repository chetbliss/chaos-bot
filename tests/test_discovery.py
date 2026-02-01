"""Tests for host discovery utilities."""

from unittest.mock import patch, MagicMock

from chaos_bot.discovery import gateway_to_subnet, discover_hosts


def test_gateway_to_subnet():
    assert gateway_to_subnet("172.16.40.1") == "172.16.40.0/24"
    assert gateway_to_subnet("10.30.30.1") == "10.30.30.0/24"
    assert gateway_to_subnet("192.168.1.254") == "192.168.1.0/24"


def test_discover_hosts_dry_run():
    result = discover_hosts(
        subnet="172.16.40.0/24",
        interface="eth1.40",
        source_ip="172.16.40.10",
        dry_run=True,
    )
    assert result == []


@patch("chaos_bot.discovery.subprocess.run")
def test_discover_hosts_excludes_self(mock_run):
    mock_run.return_value = MagicMock(
        stdout=(
            "Starting Nmap 7.94SVN\n"
            "Nmap scan report for 172.16.40.1\n"
            "Host is up (0.001s latency).\n"
            "Nmap scan report for 172.16.40.10\n"
            "Host is up (0.001s latency).\n"
            "Nmap scan report for 172.16.40.20\n"
            "Host is up (0.001s latency).\n"
            "Nmap scan report for 172.16.40.50\n"
            "Host is up (0.001s latency).\n"
            "Nmap done: 256 IP addresses (4 hosts up)\n"
        ),
        returncode=0,
    )

    result = discover_hosts(
        subnet="172.16.40.0/24",
        interface="eth1.40",
        source_ip="172.16.40.10",
        excluded=["172.16.40.1"],  # gateway
        dry_run=False,
    )

    # Self (172.16.40.10) and gateway (172.16.40.1) should be excluded
    assert "172.16.40.10" not in result
    assert "172.16.40.1" not in result
    assert "172.16.40.20" in result
    assert "172.16.40.50" in result
    assert len(result) == 2
