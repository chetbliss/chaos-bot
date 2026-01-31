"""DNS noise generator — suspicious DNS queries for security monitoring."""

import random
import string
import time

import dns.message
import dns.query
import dns.rdatatype

from chaos_bot.modules.base import BaseModule

# Known-bad test domains (EICAR-style, commonly flagged by threat intel)
BAD_DOMAINS = [
    "malware.testcategory.com",
    "botnet.testcategory.com",
    "phishing.testcategory.com",
    "coinminer.testcategory.com",
    "ransomware.testcategory.com",
    "exploit.testcategory.com",
    "bad-actor.example.com",
    "c2-callback.example.com",
    "exfil-data.example.com",
    "tor-exit-node.example.com",
]

# TLDs commonly associated with DGA domains
DGA_TLDS = [".com", ".net", ".org", ".info", ".xyz", ".top", ".biz"]


class DnsNoise(BaseModule):
    """Generate suspicious DNS queries to trigger threat detection."""

    def run(self, targets: list[str]) -> dict:
        mod_cfg = self.config.get("modules", {}).get("dns_noise", {})
        resolver = mod_cfg.get("resolver", "10.10.10.2")
        query_count = mod_cfg.get("query_count", 10)

        queries = self._build_query_list(query_count)
        results = []

        for qname, qtype, category in queries:
            self.log.info(
                f"DNS query: {qname} ({qtype}) [{category}]",
                extra={"bot_module": "dns_noise", "source_ip": self.source_ip},
            )

            if self.dry_run:
                results.append({
                    "query": qname, "type": qtype,
                    "category": category, "status": "dry-run",
                })
                continue

            try:
                result = self._send_query(resolver, qname, qtype)
                result["category"] = category
                results.append(result)

                if self.metrics:
                    self.metrics.dns_queries_total.labels(query_type=category).inc()
            except Exception as e:
                self.log.error(
                    f"DNS query failed: {qname}: {e}",
                    extra={"bot_module": "dns_noise"},
                )
                results.append({
                    "query": qname, "type": qtype,
                    "category": category, "status": "error", "message": str(e),
                })

            time.sleep(random.uniform(0.2, 1.5))

        return {
            "status": "complete",
            "summary": f"Sent {len(queries)} DNS queries",
            "details": results,
        }

    def _build_query_list(self, count: int) -> list[tuple[str, str, str]]:
        """Build a mix of suspicious DNS queries."""
        queries = []

        # Known-bad domains (A records)
        bad_count = min(count // 3, len(BAD_DOMAINS))
        for domain in random.sample(BAD_DOMAINS, bad_count):
            queries.append((domain, "A", "known_bad"))

        # DGA-pattern domains
        dga_count = count // 3
        for _ in range(dga_count):
            length = random.randint(8, 24)
            label = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
            tld = random.choice(DGA_TLDS)
            queries.append((label + tld, "A", "dga"))

        # C2-style TXT record queries with encoded payloads
        txt_count = count - len(queries)
        for _ in range(txt_count):
            # Simulate encoded C2 beacon in subdomain
            payload = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
            domain = f"{payload}.beacon.example.com"
            queries.append((domain, "TXT", "c2_txt"))

        random.shuffle(queries)
        return queries

    def _send_query(self, resolver: str, qname: str, qtype: str) -> dict:
        """Send a DNS query and return result."""
        rdtype = getattr(dns.rdatatype.RdataType, qtype, dns.rdatatype.RdataType.A)
        msg = dns.message.make_query(qname, rdtype)

        try:
            response = dns.query.udp(
                msg, resolver,
                timeout=5,
                source=self.source_ip,
            )
            rcode = response.rcode()
            answer_count = len(response.answer)
        except dns.exception.Timeout:
            return {"query": qname, "type": qtype, "status": "timeout"}
        except Exception as e:
            return {"query": qname, "type": qtype, "status": "error", "message": str(e)}

        return {
            "query": qname,
            "type": qtype,
            "rcode": dns.rcode.to_text(rcode),
            "answers": answer_count,
            "status": "complete",
        }
