# chaos-bot

Automated red-team traffic generator for home-lab security monitoring validation. Chaos-bot hops between VLANs via 802.1Q sub-interfaces and runs adversarial modules (port scans, failed auth, suspicious DNS, malicious HTTP) to exercise detection pipelines (Suricata, Wazuh, EveBox).

## Requirements

- Python 3.10+
- Root privileges (VLAN interface management, DHCP, policy routing)
- Dual-NIC host: management NIC + attack NIC (USB ethernet)
- nmap installed on the host

## Modules

| Module | Description |
|---|---|
| `net_scanner` | nmap SYN/service/OS scans with randomized targets |
| `auth_prober` | Failed auth attempts: SSH, RDP, SMB, HTTP basic, Kerberos, LDAP (max 2 per target per protocol per cycle) |
| `dns_noise` | DGA domains, known-bad lookups, C2 TXT queries |
| `http_probe` | SQLi/XSS payloads, path traversal, bad user-agents, honeypot paths |
| `exploit_spray` | CVE exploit payloads: Shellshock, Log4Shell, Spring4Shell, SQLi, command injection, SSRF, XXE, webshells |

## C2 Web UI

Served on management NIC (default `10.10.10.4:8880`). Proxied via Caddy at `https://chaosbot.lab.chettv.com`.

- **Dashboard** — current state (idle/attacking/hopping/cooldown), VLAN, source IP, cycle count
- **Attack Card** — VLAN dropdown, module checkboxes, Run Attack / Hop to VLAN / Stop buttons. Run Attack hops to the selected VLAN, discovers live hosts via nmap ARP sweep, and attacks from the VLAN IP
- **Daemon Mode** — VLAN checkboxes for continuous hopping, Start/Stop Daemon buttons
- **Suricata Alerts** — alert counts from EveBox API (last hour / 24h / 7d), grouped alert table, link to EveBox UI
- **Live Activity** — real-time log stream via SSE
- **History** — lease history with VLAN/IP/duration filtering
- **Config** — view and reload config without restart
- **Logs** — full JSON log stream page

### API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/status` | Current state, VLAN, IP, module results |
| POST | `/api/v1/start` | Start daemon loop (accepts optional `{"vlans": [30,40]}` for VLAN filtering) |
| POST | `/api/v1/stop` | Graceful stop |
| POST | `/api/v1/hop` | Trigger single hop cycle |
| GET | `/api/v1/modules` | Available modules and enabled state |
| GET | `/api/v1/targets` | All targets grouped by VLAN |
| POST | `/api/v1/trigger` | Hop to VLAN, discover live hosts, run selected modules from VLAN IP (body: `{"modules": [...], "vlan_id": 40}`) |
| GET | `/api/v1/alerts` | Proxy Suricata alerts from EveBox (query param: `time_range=86400s`) |
| GET | `/api/v1/history` | Lease history JSON |
| GET | `/api/v1/config` | Current config |
| PUT | `/api/v1/config` | Update and reload config |
| GET | `/api/v1/logs` | SSE log stream |

### State Validation

The API enforces state transitions:

| Endpoint | Rejected when |
|---|---|
| `POST /api/v1/start` | State is not `idle` or `cooldown` (409) |
| `POST /api/v1/hop` | State is `attacking` or `hopping` (409) |
| `POST /api/v1/trigger` | State is `attacking` or `hopping` (409) |
| `PUT /api/v1/config` | State is `attacking` (409) |
| `POST /api/v1/stop` | Always allowed |

## Notifications

Apprise notifications via `http://10.10.10.3:8800/notify`. Sends alerts for:

- **Cycle complete** — VLAN, IP, duration, modules run (both daemon and manual trigger)
- **Errors** — hop failures, no hosts found, exceptions during trigger

Configured in `config.yml` under `notifications`. Requires `enabled: true`.

## Metrics

Prometheus metrics exposed on port 9100 (management NIC). Scrape target: `http://10.10.10.4:9100/metrics`.

## Config

See `config.yml` for the default lab configuration. Key sections: `vlans`, `modules`, `schedule`, `credentials`, `notifications`, `metrics`, `web`, `evebox`.

## Host Discovery

Before attacking, chaos-bot runs an nmap ARP sweep (`nmap -sn -PR`) on the VLAN subnet to find live hosts. This applies to both manual trigger and daemon mode. The discovery process:

1. Hop to VLAN (create 802.1Q sub-interface, obtain DHCP lease, set up policy routing)
2. Run ARP sweep on /24 subnet from the VLAN IP (90s timeout)
3. Exclude gateway and self from results
4. Fall back to static targets from config if discovery finds nothing
5. Skip attack if no targets at all

This is critical for VLANs with DHCP hosts (e.g., VLAN 40 honeypot with metasploitable VMs) where IPs change between boots.

## VLAN Targets

| VLAN | Name | Subnet | Discovery |
|---|---|---|---|
| 1 | management | 10.10.10.0/24 | ARP discovery, static fallback (t420, pve01, pve02, pbs01, jenkins, aihub) |
| 30 | servers | 10.30.30.0/24 | ARP discovery, static fallback (dc1, dc2, secdocker) |
| 31 | users | 10.31.31.0/24 | ARP discovery only |
| 32 | paw | 10.32.32.0/24 | ARP discovery only |
| 40 | honeypot | 172.16.40.0/24 | ARP discovery only (DHCP hosts, IPs change) |
| 50 | untrusted | 172.16.50.0/24 | ARP discovery only (DHCP hosts, IPs change) |

VLANs 20 (Corosync) and 21 (Replication) are excluded — never target cluster traffic.

## Deployment

Deployed via Ansible from the `chaosbot-stack` deployment in the homelab-migration repo. The Ansible role pulls the `chaosbot` branch of this repo.

The Ansible role clones this repo (branch `chaosbot`) to `/home/cbliss/chaos-bot`, creates a venv, installs the package, templates the config from inventory vars, and manages the systemd service. Code changes are auto-deployed: the git clone task and pip install both trigger a service restart via handler.

```bash
cd deployments/chaosbot-stack/ansible
ANSIBLE_ROLES_PATH=./roles ansible-playbook playbooks/deploy-chaosbot.yml -i inventory/hosts.yml
```

## Tests

```bash
source .venv/bin/activate
pytest tests/ -v
```

31 tests covering config loading, lease DB, module dry-run, host discovery, and web API endpoints.

## Version History

| Version | Date | Changes |
|---|---|---|
| 0.1.6 | 2026-02-09 | New `exploit_spray` module for red team simulation. Sends CVE payloads (Shellshock, Log4Shell, Spring4Shell, SQLi, command injection, XSS, SSRF, XXE, PHP injection, webshell access, malware user-agents) to trigger Suricata/ET Open rules. Configurable intensity (low/medium/high). |
| 0.1.5 | 2026-02-01 | Apprise notifications for manual trigger (cycle summary on success, error on failure/no hosts). Increased nmap ARP discovery timeout to 90s for /24 subnets. Stale VLAN interface cleanup on hop (prevents crash if previous run left eth1.X behind). |
| 0.1.4 | 2026-02-01 | Manual trigger hops to selected VLAN and attacks from VLAN IP (not management IP). Nmap ARP sweep discovers live hosts before attacking. Daemon mode also gets host discovery. New `discovery.py` module. Trigger API accepts `vlan_id` instead of `targets`. |
| 0.1.3 | 2026-02-01 | CIDR target expansion for auth_prober and http_probe (random sample of 5 IPs from /24 subnets). Fixed Ansible handler: git clone now triggers service restart so code changes take effect immediately. |
| 0.1.2 | 2026-01-31 | Redesigned dashboard (VLAN dropdown, module checkboxes, attack/daemon cards). Added VLAN 1 management targets. CIDR /24 subnet scanning. 28-port nmap at high intensity. Fixed source IP binding during VLAN hops. |
| 0.1.1 | 2026-01-31 | C2 dashboard: module/VLAN/target pickers, manual trigger, Suricata alerts (EveBox), state validation, VLAN filter for daemon |
| 0.1.0 | 2026-01-31 | Initial release: core framework, 4 modules, VLAN hopper, web UI, metrics, notifications, lease history |
