"""Authentication prober — generates failed login attempts for security monitoring.

Limited to max 2 attempts per target per protocol per cycle.
"""

import random
import subprocess
import time

import paramiko
import requests

from chaos_bot.modules.base import BaseModule


class AuthProber(BaseModule):
    """Probe authentication services with intentionally failing credentials."""

    def run(self, targets: list[str]) -> dict:
        mod_cfg = self.config.get("modules", {}).get("auth_prober", {})
        max_attempts = mod_cfg.get("max_attempts", 2)
        protocols = mod_cfg.get("protocols", ["ssh", "rdp", "smb", "http_basic"])
        creds = self.config.get("credentials", {})
        username = creds.get("username", "chaos-bot")
        password = creds.get("password", "NotARealPassword")

        shuffled = list(targets)
        random.shuffle(shuffled)
        results = []

        for target in shuffled:
            for proto in protocols:
                for attempt in range(1, max_attempts + 1):
                    self.log.info(
                        f"Auth probe {proto} → {target} (attempt {attempt}/{max_attempts})",
                        extra={"bot_module": "auth_prober", "target_ip": target,
                               "source_ip": self.source_ip},
                    )

                    if self.dry_run:
                        results.append({
                            "target": target, "protocol": proto,
                            "attempt": attempt, "status": "dry-run",
                        })
                        continue

                    try:
                        result = self._probe(proto, target, username, password)
                        result["attempt"] = attempt
                        results.append(result)

                        if self.metrics:
                            self.metrics.auth_attempts_total.labels(
                                protocol=proto, result=result.get("auth_result", "unknown"),
                            ).inc()
                    except Exception as e:
                        self.log.error(
                            f"Auth probe {proto} → {target} failed: {e}",
                            extra={"bot_module": "auth_prober", "target_ip": target},
                        )
                        results.append({
                            "target": target, "protocol": proto,
                            "attempt": attempt, "status": "error", "message": str(e),
                        })

                    time.sleep(random.uniform(0.5, 2.0))

        return {
            "status": "complete",
            "summary": f"Auth probed {len(shuffled)} targets, {len(results)} attempts",
            "details": results,
        }

    def _probe(self, proto: str, target: str, username: str, password: str) -> dict:
        handler = {
            "ssh": self._probe_ssh,
            "rdp": self._probe_rdp,
            "smb": self._probe_smb,
            "http_basic": self._probe_http_basic,
            "kerberos": self._probe_kerberos,
            "ldap": self._probe_ldap,
        }.get(proto)

        if not handler:
            return {"target": target, "protocol": proto, "status": "unsupported"}
        return handler(target, username, password)

    def _probe_ssh(self, target: str, username: str, password: str) -> dict:
        """Failed SSH login via paramiko."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                target, port=22, username=username, password=password,
                timeout=5, look_for_keys=False, allow_agent=False,
                banner_timeout=5,
            )
            auth_result = "success"  # Unexpected but possible
        except paramiko.AuthenticationException:
            auth_result = "rejected"
        except Exception as e:
            auth_result = f"error:{type(e).__name__}"
        finally:
            client.close()

        return {"target": target, "protocol": "ssh", "auth_result": auth_result, "status": "complete"}

    def _probe_rdp(self, target: str, username: str, password: str) -> dict:
        """Failed RDP login via xfreerdp."""
        cmd = [
            "xfreerdp", f"/v:{target}", f"/u:{username}", f"/p:{password}",
            "/cert:ignore", "+auth-only", "/timeout:5000",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        auth_result = "rejected" if proc.returncode != 0 else "success"
        return {"target": target, "protocol": "rdp", "auth_result": auth_result, "status": "complete"}

    def _probe_smb(self, target: str, username: str, password: str) -> dict:
        """Failed SMB login via impacket."""
        try:
            from impacket.smbconnection import SMBConnection
            conn = SMBConnection(target, target, sess_port=445, timeout=5)
            try:
                conn.login(username, password)
                auth_result = "success"
            except Exception:
                auth_result = "rejected"
            finally:
                conn.close()
        except Exception as e:
            auth_result = f"error:{type(e).__name__}"
        return {"target": target, "protocol": "smb", "auth_result": auth_result, "status": "complete"}

    def _probe_http_basic(self, target: str, username: str, password: str) -> dict:
        """Failed HTTP basic auth."""
        try:
            resp = requests.get(
                f"http://{target}/",
                auth=(username, password),
                timeout=5,
                verify=False,
            )
            auth_result = "rejected" if resp.status_code == 401 else f"http_{resp.status_code}"
        except requests.RequestException as e:
            auth_result = f"error:{type(e).__name__}"
        return {"target": target, "protocol": "http_basic", "auth_result": auth_result, "status": "complete"}

    def _probe_kerberos(self, target: str, username: str, password: str) -> dict:
        """Kerberos pre-auth attempt via impacket."""
        try:
            from impacket.krb5.kerberosv5 import getKerberosTGT
            from impacket.krb5.types import Principal
            client_name = Principal(username, type=1)
            getKerberosTGT(client_name, password, "", target, None, None)
            auth_result = "success"
        except Exception as e:
            err_name = type(e).__name__
            if "KDC_ERR" in str(e) or "KRB" in err_name:
                auth_result = "rejected"
            else:
                auth_result = f"error:{err_name}"
        return {"target": target, "protocol": "kerberos", "auth_result": auth_result, "status": "complete"}

    def _probe_ldap(self, target: str, username: str, password: str) -> dict:
        """LDAP simple bind via impacket."""
        try:
            from impacket.ldap.ldap import LDAPConnection
            conn = LDAPConnection(f"ldap://{target}")
            try:
                conn.login(username, "", password)
                auth_result = "success"
            except Exception:
                auth_result = "rejected"
        except Exception as e:
            auth_result = f"error:{type(e).__name__}"
        return {"target": target, "protocol": "ldap", "auth_result": auth_result, "status": "complete"}
