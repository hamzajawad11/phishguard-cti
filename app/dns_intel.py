from typing import Any

import dns.exception
import dns.resolver

from app.config import DNS_LIFETIME, DNS_TIMEOUT


RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT")


def lookup_dns_intel(domain: str) -> dict[str, Any]:
    if not domain:
        return {
            "source": "DNS",
            "status": "not_applicable",
            "detail": "DNS lookup requires a domain.",
            "records": {},
            "resolved_ips": [],
            "warnings": ["No domain supplied."],
        }

    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = DNS_LIFETIME
    resolver.timeout = DNS_TIMEOUT

    records: dict[str, list[str]] = {}
    errors: dict[str, str] = {}
    warnings: list[str] = []

    for record_type in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, record_type, raise_on_no_answer=True)
            records[record_type] = [_format_answer(record_type, answer) for answer in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
            records[record_type] = []
            errors[record_type] = exc.__class__.__name__

    if not records.get("A") and not records.get("AAAA"):
        warnings.append("Domain does not resolve to A or AAAA records.")
    if not records.get("NS"):
        warnings.append("Domain has no visible NS records.")
    if not records.get("MX"):
        warnings.append("Domain has no MX records.")

    status = "ok"
    detail = "DNS records were resolved."
    if not records.get("A") and not records.get("AAAA"):
        status = "suspicious"
        detail = "Domain did not resolve to an IP address."
    if all(not values for values in records.values()):
        status = "unavailable"
        detail = "No DNS records could be resolved."

    return {
        "source": "DNS",
        "status": status,
        "detail": detail,
        "records": records,
        "resolved_ips": sorted(set(records.get("A", []) + records.get("AAAA", []))),
        "warnings": warnings,
        "errors": errors,
        "no_ns": not records.get("NS"),
    }


def _format_answer(record_type: str, answer: Any) -> str:
    if record_type == "MX":
        return f"{answer.preference} {str(answer.exchange).rstrip('.')}"
    if record_type == "TXT":
        return " ".join(part.decode("utf-8", errors="replace") for part in answer.strings)
    return str(answer).rstrip(".")
