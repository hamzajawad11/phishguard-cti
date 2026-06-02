import hashlib
import ipaddress
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from app.config import MAX_SCAN_TARGETS


SUSPICIOUS_KEYWORDS = {
    "account",
    "admin",
    "bank",
    "billing",
    "confirm",
    "credential",
    "login",
    "mfa",
    "oauth",
    "password",
    "payment",
    "recover",
    "secure",
    "signin",
    "sso",
    "support",
    "update",
    "verify",
    "wallet",
}

BRAND_KEYWORDS = {
    "adobe",
    "amazon",
    "apple",
    "binance",
    "dhl",
    "dropbox",
    "facebook",
    "google",
    "instagram",
    "microsoft",
    "netflix",
    "office",
    "onedrive",
    "paypal",
    "telegram",
    "whatsapp",
}

RISKY_TLDS = {
    "beauty",
    "buzz",
    "cam",
    "cfd",
    "click",
    "cyou",
    "fit",
    "gq",
    "icu",
    "loan",
    "ml",
    "mom",
    "monster",
    "quest",
    "rest",
    "sbs",
    "shop",
    "tk",
    "top",
    "work",
    "xyz",
}

SHORTENERS = {
    "bit.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "lnkd.in",
    "rebrand.ly",
    "s.id",
    "t.co",
    "tinyurl.com",
    "trib.al",
}

IP_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
URL_PATTERN = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>'\"]+")
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
HASH_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}\b")


@dataclass
class Finding:
    label: str
    weight: int
    detail: str


def normalize_url(raw: str) -> str:
    value = raw.strip().strip("<>").strip()
    if value.startswith("www."):
        return f"https://{value}"
    if not re.match(r"(?i)^https?://", value):
        return f"https://{value}"
    return value


def _domain_from_url(normalized_url: str) -> str:
    parsed = urlparse(normalized_url)
    return (parsed.hostname or "").lower().strip(".")


def extract_domain(raw: str) -> str:
    """Return the lowercased host for a raw URL or domain string."""
    return _domain_from_url(normalize_url(raw))


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _registrable_hint(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _add_finding(findings: list[Finding], label: str, weight: int, detail: str) -> None:
    findings.append(Finding(label=label, weight=weight, detail=detail))


def extract_iocs(text: str) -> dict[str, list[str]]:
    urls = sorted({normalize_url(match.rstrip(".,);]")) for match in URL_PATTERN.findall(text)})
    ips = sorted(set(IP_PATTERN.findall(text)))
    hashes = sorted({item.lower() for item in HASH_PATTERN.findall(text)})
    cves = sorted({item.upper() for item in CVE_PATTERN.findall(text)})

    domains = set()
    for match in DOMAIN_PATTERN.findall(text):
        domain = match.lower().strip(".")
        if not _is_ip(domain) and not domain.startswith("www."):
            domains.add(domain)
    for url in urls:
        domain = _domain_from_url(url)
        if domain and not _is_ip(domain):
            domains.add(domain)

    return {
        "urls": urls,
        "domains": sorted(domains),
        "ips": ips,
        "hashes": hashes,
        "cves": cves,
    }


def extract_scan_targets(text: str) -> list[str]:
    targets: list[str] = []
    seen: set[str] = set()

    for url in URL_PATTERN.findall(text):
        value = url.rstrip(".,);]")
        key = value.lower()
        if key not in seen:
            seen.add(key)
            targets.append(value)

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for line in lines:
        compact = line.strip().strip("<>").strip().rstrip(".,);]")
        if " " in compact or "\t" in compact:
            for match in DOMAIN_PATTERN.findall(line):
                domain = match.lower().strip(".").rstrip(".,);]")
                if _is_ip(domain) or domain.endswith(".local"):
                    continue
                key = domain.lower()
                if key not in seen and not _is_ip(domain):
                    seen.add(key)
                    targets.append(domain)
            continue
        if CVE_PATTERN.fullmatch(compact) or HASH_PATTERN.fullmatch(compact) or IP_PATTERN.fullmatch(compact):
            continue
        if DOMAIN_PATTERN.fullmatch(compact):
            key = compact.lower()
            if key not in seen:
                seen.add(key)
                targets.append(compact)

    return targets[:MAX_SCAN_TARGETS]


def analyze_url(raw: str, enrichment: dict[str, Any] | None = None) -> dict[str, Any]:
    normalized = normalize_url(raw)
    parsed = urlparse(normalized)
    domain = _domain_from_url(normalized)
    decoded_url = unquote(normalized)
    path = parsed.path or ""
    query = parsed.query or ""
    full_lower = decoded_url.lower()
    domain_lower = domain.lower()
    findings: list[Finding] = []

    if not domain:
        _add_finding(findings, "Invalid or incomplete URL", 30, "The input could not be parsed into a valid domain.")

    if parsed.scheme != "https":
        _add_finding(findings, "No HTTPS", 12, "The URL does not use HTTPS.")

    if domain and _is_ip(domain):
        _add_finding(findings, "IP address used as host", 25, "The URL uses a raw IP address instead of a domain name.")

    if "xn--" in domain_lower:
        _add_finding(findings, "Punycode domain", 22, "The domain contains punycode, which can indicate homograph impersonation.")

    tld = domain_lower.rsplit(".", 1)[-1] if "." in domain_lower else ""
    if tld in RISKY_TLDS:
        _add_finding(findings, "Risky top-level domain", 12, f"The .{tld} TLD is commonly abused in phishing campaigns.")

    if _registrable_hint(domain_lower) in SHORTENERS:
        _add_finding(findings, "URL shortener", 18, "Shortened links can hide the final destination.")

    if len(normalized) > 120:
        _add_finding(findings, "Long URL", 10, "The URL length is abnormal and may hide tracking or redirection data.")

    if path.count("/") >= 4:
        _add_finding(findings, "Deep path nesting", 8, "The URL has many path levels.")

    if "@" in normalized:
        _add_finding(findings, "At-sign in URL", 18, "The URL contains @, which can obscure the real host.")

    if normalized.count("-") >= 4:
        _add_finding(findings, "Many hyphens", 8, "The URL contains many hyphens, a common trait in throwaway domains.")

    if re.search(r"%[0-9a-fA-F]{2}", normalized):
        _add_finding(findings, "Encoded characters", 8, "The URL contains percent-encoded characters.")

    keyword_hits = sorted({word for word in SUSPICIOUS_KEYWORDS if word in full_lower})
    if keyword_hits:
        _add_finding(
            findings,
            "Phishing keywords",
            min(24, 6 + len(keyword_hits) * 3),
            f"Suspicious terms found: {', '.join(keyword_hits[:8])}.",
        )

    brand_hits = sorted({word for word in BRAND_KEYWORDS if word in full_lower})
    if brand_hits and domain_lower and not any(domain_lower.endswith(f"{brand}.com") for brand in brand_hits):
        _add_finding(
            findings,
            "Brand impersonation signal",
            min(22, 10 + len(brand_hits) * 4),
            f"Brand names appear outside official-looking domains: {', '.join(brand_hits[:6])}.",
        )

    query_params = parse_qs(query)
    redirect_params = {"redirect", "redirect_uri", "return", "returnurl", "url", "next", "continue", "dest"}
    if redirect_params.intersection({key.lower() for key in query_params}):
        _add_finding(findings, "Redirect parameter", 12, "The query string includes a redirect-style parameter.")

    if IP_PATTERN.search(path + "?" + query):
        _add_finding(findings, "Embedded IP indicator", 12, "An IP address appears inside the URL path or query.")

    if enrichment:
        domain_intel = enrichment.get("domain_intel", {})
        if domain_intel.get("status") == "ok":
            age_days = domain_intel.get("age_days")
            if isinstance(age_days, int):
                if age_days <= 7:
                    _add_finding(findings, "Very new domain", 25, f"The domain appears to be {age_days} days old.")
                elif age_days <= 30:
                    _add_finding(findings, "Newly registered domain", 18, f"The domain appears to be {age_days} days old.")
                elif age_days <= 90:
                    _add_finding(findings, "Recently registered domain", 10, f"The domain appears to be {age_days} days old.")

        dns = enrichment.get("dns", {})
        if dns.get("status") == "suspicious":
            _add_finding(findings, "DNS resolution gap", 20, dns.get("detail", "DNS lookup returned suspicious results."))
        elif dns.get("status") == "unavailable":
            _add_finding(findings, "DNS unavailable", 8, "DNS records could not be resolved for this domain.")
        if dns.get("no_ns") and not dns.get("resolved_ips"):
            _add_finding(findings, "Missing NS records", 10, "The domain has no visible nameserver records.")

        redirects = enrichment.get("redirects", {})
        if redirects.get("cross_domain"):
            _add_finding(
                findings,
                "Cross-domain redirect",
                18,
                f"The URL redirects from {domain_lower or 'the submitted host'} to {redirects.get('final_domain')}.",
            )
        if redirects.get("redirect_count", 0) >= 3:
            _add_finding(findings, "Long redirect chain", 10, "The URL uses three or more redirects.")
        final_url = str(redirects.get("final_url") or "")
        if final_url.startswith("http://") and parsed.scheme == "https":
            _add_finding(findings, "HTTPS downgraded after redirect", 12, "The redirect chain ends on HTTP.")

        phishstats = enrichment.get("phishstats", {})
        if phishstats.get("status") == "matched":
            _add_finding(findings, "PhishStats verified phishing feed hit", 45, phishstats.get("detail", "PhishStats has records for this indicator."))
        elif phishstats.get("status") == "host_matched":
            _add_finding(findings, "PhishStats host match", 18, phishstats.get("detail", "PhishStats has records for this host."))

        urlhaus = enrichment.get("urlhaus", {})
        if urlhaus.get("status") == "malicious":
            _add_finding(findings, "URLHaus malicious hit", 45, "URLHaus has community intelligence for this URL.")
        elif urlhaus.get("status") == "host_malicious":
            _add_finding(findings, "URLHaus host hit", 35, "URLHaus has community intelligence for this host.")

        kev = enrichment.get("cisa_kev", {})
        if kev.get("matches"):
            _add_finding(findings, "Known exploited CVE reference", 25, "The input references CVEs in the CISA KEV catalog.")

        optional_sources = enrichment.get("optional_sources", {})
        _score_optional_sources(findings, optional_sources)

    score = min(100, sum(item.weight for item in findings))
    severity = severity_from_score(score)
    iocs = extract_iocs(raw)
    if normalized not in iocs["urls"]:
        iocs["urls"].insert(0, normalized)
    if domain and not _is_ip(domain) and domain not in iocs["domains"]:
        iocs["domains"].insert(0, domain)
    if domain and _is_ip(domain) and domain not in iocs["ips"]:
        iocs["ips"].insert(0, domain)

    return {
        "original_input": raw,
        "normalized_url": normalized,
        "domain": domain,
        "score": score,
        "severity": severity,
        "reasons": [finding.__dict__ for finding in findings],
        "iocs": iocs,
        "fingerprint": hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
    }


def severity_from_score(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def _score_optional_sources(findings: list[Finding], optional_sources: dict[str, Any]) -> None:
    vt = optional_sources.get("virustotal", {}) if isinstance(optional_sources, dict) else {}
    if vt.get("status") == "malicious":
        _add_finding(findings, "VirusTotal malicious detections", 35, vt.get("detail", "VirusTotal reported malicious detections."))
    elif vt.get("status") == "suspicious":
        _add_finding(findings, "VirusTotal suspicious detections", 8, vt.get("detail", "VirusTotal reported suspicious detections."))

    abuse = optional_sources.get("abuseipdb", {}) if isinstance(optional_sources, dict) else {}
    if abuse.get("status") == "malicious":
        _add_finding(findings, "AbuseIPDB malicious IP reputation", 30, abuse.get("detail", "AbuseIPDB reported malicious IP reputation."))
    elif abuse.get("status") == "suspicious":
        _add_finding(findings, "AbuseIPDB suspicious IP reputation", 16, abuse.get("detail", "AbuseIPDB reported suspicious IP reputation."))

    otx = optional_sources.get("otx", {}) if isinstance(optional_sources, dict) else {}
    if otx.get("status") == "matched":
        _add_finding(findings, "AlienVault OTX pulse match", 22, otx.get("detail", "OTX pulses reference this indicator."))

    urlscan = optional_sources.get("urlscan", {}) if isinstance(optional_sources, dict) else {}
    if urlscan.get("status") == "malicious":
        _add_finding(findings, "urlscan.io malicious scan", 25, urlscan.get("detail", "urlscan.io has malicious scan results."))
    elif urlscan.get("status") == "downloads_found":
        _add_finding(findings, "urlscan.io download observed", 12, urlscan.get("detail", "urlscan.io observed a file download during dynamic scanning."))

    vt_files = optional_sources.get("virustotal_files", {}) if isinstance(optional_sources, dict) else {}
    if vt_files.get("status") == "malicious":
        _add_finding(findings, "VirusTotal malicious downloaded file", 45, vt_files.get("detail", "A downloaded file hash was reported malicious by VirusTotal."))
    elif vt_files.get("status") == "suspicious":
        _add_finding(findings, "VirusTotal suspicious downloaded file", 18, vt_files.get("detail", "A downloaded file hash was reported suspicious by VirusTotal."))
