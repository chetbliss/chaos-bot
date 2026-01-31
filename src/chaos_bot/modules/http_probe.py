"""HTTP probe module — malicious HTTP requests for security monitoring."""

import random
import time

import requests
from requests.adapters import HTTPAdapter

from chaos_bot.modules.base import BaseModule

# Malicious user-agents
BAD_USER_AGENTS = [
    "sqlmap/1.7#stable (https://sqlmap.org)",
    "nikto/2.5.0",
    "gobuster/3.6",
    "dirbuster/1.0",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "masscan/1.3 (https://github.com/robertdavidgraham/masscan)",
    "Wget/1.21",
    "curl/7.88.0",
    "python-requests/2.31.0",
    "Java/11.0.2",
]

# Path traversal payloads
PATH_TRAVERSALS = [
    "/../../etc/passwd",
    "/..%2f..%2fetc%2fpasswd",
    "/%2e%2e/%2e%2e/etc/passwd",
    "/....//....//etc/passwd",
    "/..\\..\\windows\\system32\\config\\sam",
]

# SQLi test strings
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' UNION SELECT NULL--",
    "1; DROP TABLE users--",
    "admin'--",
    "' OR 1=1#",
]

# XSS test payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
    "<svg onload=alert(1)>",
]

# Honeypot / common enumeration paths
HONEYPOT_PATHS = [
    "/admin",
    "/wp-login.php",
    "/wp-admin/",
    "/.env",
    "/.git/HEAD",
    "/.git/config",
    "/server-status",
    "/server-info",
    "/phpinfo.php",
    "/actuator/env",
    "/api/v1/admin",
    "/console",
    "/debug",
    "/.aws/credentials",
    "/config.json",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
]


class SourceIPAdapter(HTTPAdapter):
    """HTTPAdapter that binds to a specific source IP."""

    def __init__(self, source_address: str, **kwargs):
        self._source_address = source_address
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["source_address"] = (self._source_address, 0)
        super().init_poolmanager(*args, **kwargs)


class HttpProbe(BaseModule):
    """Send malicious HTTP requests to test WAF/IDS detection."""

    def run(self, targets: list[str]) -> dict:
        mod_cfg = self.config.get("modules", {}).get("http_probe", {})
        extra_paths = mod_cfg.get("paths", [])

        session = requests.Session()
        if self.source_ip and self.source_ip != "0.0.0.0":
            adapter = SourceIPAdapter(self.source_ip)
            session.mount("http://", adapter)
            session.mount("https://", adapter)

        # Disable SSL warnings for probe traffic
        requests.packages.urllib3.disable_warnings()

        shuffled = list(targets)
        random.shuffle(shuffled)
        results = []

        for target in shuffled:
            base_url = f"http://{target}"
            probes = self._build_probes(base_url, extra_paths)
            random.shuffle(probes)

            for probe in probes:
                self.log.info(
                    f"HTTP probe: {probe['type']} → {target}",
                    extra={"bot_module": "http_probe", "target_ip": target,
                           "source_ip": self.source_ip},
                )

                if self.dry_run:
                    results.append({
                        "target": target, "probe_type": probe["type"],
                        "url": probe["url"], "status": "dry-run",
                    })
                    continue

                try:
                    result = self._send_probe(session, probe)
                    results.append(result)

                    if self.metrics:
                        self.metrics.http_probes_total.labels(
                            probe_type=probe["type"]
                        ).inc()
                except Exception as e:
                    results.append({
                        "target": target, "probe_type": probe["type"],
                        "status": "error", "message": str(e),
                    })

                time.sleep(random.uniform(0.3, 2.0))

        return {
            "status": "complete",
            "summary": f"Sent {len(results)} HTTP probes to {len(shuffled)} targets",
            "details": results,
        }

    def _build_probes(self, base_url: str, extra_paths: list[str]) -> list[dict]:
        """Build a list of probe requests."""
        probes = []

        # Bad user-agent requests
        ua = random.choice(BAD_USER_AGENTS)
        probes.append({
            "type": "bad_useragent",
            "url": base_url + "/",
            "headers": {"User-Agent": ua},
            "method": "GET",
        })

        # Path traversal
        path = random.choice(PATH_TRAVERSALS)
        probes.append({
            "type": "path_traversal",
            "url": base_url + path,
            "headers": {},
            "method": "GET",
        })

        # SQLi in query params
        sqli = random.choice(SQLI_PAYLOADS)
        probes.append({
            "type": "sqli",
            "url": base_url + f"/search?q={sqli}&id=1",
            "headers": {},
            "method": "GET",
        })

        # XSS payload
        xss = random.choice(XSS_PAYLOADS)
        probes.append({
            "type": "xss",
            "url": base_url + f"/search?q={xss}",
            "headers": {},
            "method": "GET",
        })

        # Honeypot/enumeration paths
        paths = HONEYPOT_PATHS + extra_paths
        for hp in random.sample(paths, min(5, len(paths))):
            probes.append({
                "type": "honeypot_path",
                "url": base_url + hp,
                "headers": {},
                "method": "GET",
            })

        # Direct IP / wrong SNI probe
        probes.append({
            "type": "reverse_proxy_probe",
            "url": base_url + "/",
            "headers": {"Host": "internal.admin.local"},
            "method": "GET",
        })

        return probes

    def _send_probe(self, session: requests.Session, probe: dict) -> dict:
        """Execute a single HTTP probe."""
        try:
            resp = session.request(
                method=probe.get("method", "GET"),
                url=probe["url"],
                headers=probe.get("headers", {}),
                timeout=5,
                verify=False,
                allow_redirects=False,
            )
            return {
                "target": probe["url"],
                "probe_type": probe["type"],
                "status_code": resp.status_code,
                "content_length": len(resp.content),
                "status": "complete",
            }
        except requests.RequestException as e:
            return {
                "target": probe["url"],
                "probe_type": probe["type"],
                "status": "error",
                "message": str(e),
            }
