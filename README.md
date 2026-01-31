# chaos-bot

Automated red-team traffic generator for home-lab security monitoring validation. Chaos-bot hops between VLANs via 802.1Q sub-interfaces and runs adversarial modules (port scans, failed auth, suspicious DNS, malicious HTTP) to exercise detection pipelines (Suricata, Wazuh, EveBox).

## Requirements

- Python 3.10+
- Root privileges (VLAN interface management, DHCP, policy routing)
- Dual-NIC host: management NIC + attack NIC (USB ethernet)
- nmap installed on the host

## Install

```bash
git clone https://github.com/chetbliss/chaos-bot.git
cd chaos-bot
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## CLI

```bash
# Start C2 web UI (hopper idle until started from dashboard)
sudo chaos-bot serve --config /etc/chaos-bot/config.yml

# Single hop cycle (one VLAN, run modules, teardown)
sudo chaos-bot hop --once --config config.yml

# Dry run (no network changes)
sudo chaos-bot hop --once --dry-run

# Daemon mode (continuous VLAN hopping)
sudo chaos-bot hop --daemon

# Run modules without hopping (uses current interface)
chaos-bot run --once --modules net_scanner,dns_noise

# View lease history
chaos-bot history --last 10

# Show resolved config
chaos-bot config --show
```

## Modules (v0.1.0)

| Module | Description |
|---|---|
| `net_scanner` | nmap SYN/service/OS scans with randomized targets |
| `auth_prober` | Failed auth attempts: SSH, RDP, SMB, HTTP basic, Kerberos, LDAP (max 2 per target per protocol per cycle) |
| `dns_noise` | DGA domains, known-bad lookups, C2 TXT queries |
| `http_probe` | SQLi/XSS payloads, path traversal, bad user-agents, honeypot paths |

## C2 Web UI

Served on management NIC (default `10.10.10.4:8880`). Proxied via Caddy at `https://chaosbot.lab.chettv.com`.

- **Dashboard** — current state (idle/attacking/hopping/cooldown), VLAN, source IP, cycle summaries
- **Module Picker** — checkboxes to select which modules to run
- **VLAN Picker** — select VLANs for daemon hopping
- **Target Picker** — select targets grouped by VLAN (expand/collapse, select all)
- **Manual Trigger** — run selected modules against selected targets without hopping
- **Suricata Alerts** — live alert counts from EveBox API (last hour / 24h / 7d), link to EveBox UI
- **Controls** — start/stop hopper, trigger single hop (state-aware: buttons disabled when busy)
- **History** — lease history with VLAN/IP/duration filtering
- **Config** — view and reload config without restart
- **Logs** — live JSON log stream via SSE

### API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/status` | Current state, VLAN, IP, module results |
| POST | `/api/v1/start` | Start daemon loop (accepts optional `{"vlans": [30,40]}` for VLAN filtering) |
| POST | `/api/v1/stop` | Graceful stop |
| POST | `/api/v1/hop` | Trigger single hop cycle |
| GET | `/api/v1/modules` | Available modules and enabled state |
| GET | `/api/v1/targets` | All targets grouped by VLAN |
| POST | `/api/v1/trigger` | Run selected modules on selected targets (body: `{"modules": [...], "targets": [...]}`) |
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

## Metrics

Prometheus metrics exposed on port 9100 (management NIC). Scrape target: `http://10.10.10.4:9100/metrics`.

## Config

See `config.yml` for the default lab configuration. Key sections: `vlans`, `modules`, `schedule`, `credentials`, `notifications`, `metrics`, `web`, `evebox`.

## VLAN Targets

| VLAN | Name | Subnet |
|---|---|---|
| 30 | servers | 10.30.30.0/24 |
| 31 | users | 10.31.31.0/24 |
| 32 | paw | 10.32.32.0/24 |
| 40 | honeypot | 10.40.40.0/24 |
| 50 | untrusted | 10.50.50.0/24 |

VLANs 20 (Corosync) and 21 (Replication) are excluded — never target cluster traffic.

## Deployment

Deployed via Ansible from the `chaosbot-stack` deployment in the homelab-migration repo. Jenkins job `chaosbot-stack` with `ACTION=setup` runs the playbook.

The Ansible role clones this repo to `/home/cbliss/chaos-bot`, creates a venv, installs the package, templates the config from inventory vars, and manages the systemd service. Code changes are auto-deployed: the git clone task and pip install both trigger a service restart via handler.

## Tests

```bash
source .venv/bin/activate
pytest tests/ -v
```

27 tests covering config loading, lease DB, module dry-run, and web API endpoints.

## Version History

| Version | Date | Changes |
|---|---|---|
| 0.1.1 | 2026-01-31 | C2 dashboard: module/VLAN/target pickers, manual trigger, Suricata alerts (EveBox), state validation, VLAN filter for daemon |
| 0.1.0 | 2026-01-31 | Initial release: core framework, 4 modules, VLAN hopper, web UI, metrics, notifications, lease history |
