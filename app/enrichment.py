import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any

import requests
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analyzer import CVE_PATTERN
from app.config import FEED_TIMEOUT
from app.dns_intel import lookup_dns_intel
from app.domain_intel import lookup_domain_intel, registered_domain
from app.models import FeedCache
from app.optional_sources import lookup_optional_sources
from app.redirects import trace_redirects


URLHAUS_URL_LOOKUP = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST_LOOKUP = "https://urlhaus-api.abuse.ch/v1/host/"
PHISHSTATS_LOOKUP = "https://api.phishstats.info/api/phishing"
CISA_KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REQUEST_TIMEOUT = FEED_TIMEOUT
# Characters that would corrupt the PhishStats "(field,op,value)" filter DSL.
_PHISHSTATS_UNSAFE = set("(),")


def enrich_url(
    normalized_url: str,
    domain: str,
    original_text: str,
    db: Session,
    url_resolution: dict[str, Any] | None = None,
) -> dict[str, Any]:
    # These lookups are independent, network-bound calls, so they run
    # concurrently. CISA KEV uses the request-scoped DB session (not safe to
    # share across threads), so it stays on this thread and runs while the
    # pool is in flight.
    with ThreadPoolExecutor(max_workers=5) as pool:
        future_domain = pool.submit(lookup_domain_intel, domain)
        future_dns = pool.submit(lookup_dns_intel, domain)
        future_redirects = pool.submit(trace_redirects, normalized_url, domain)
        future_phishstats = pool.submit(lookup_phishstats, normalized_url, domain)
        future_urlhaus = pool.submit(lookup_urlhaus, normalized_url, domain)

        cisa_kev = lookup_cisa_kev(original_text, db)

        domain_intel = future_domain.result()
        dns_intel = future_dns.result()
        redirects = future_redirects.result()
        phishstats = future_phishstats.result()
        urlhaus = future_urlhaus.result()

    # Optional sources need the resolved IPs from the DNS lookup, so they run
    # once DNS has completed.
    optional_sources = lookup_optional_sources(normalized_url, domain, original_text, dns_intel)

    return {
        "url_resolution": url_resolution or {},
        "domain_intel": domain_intel,
        "dns": dns_intel,
        "redirects": redirects,
        "phishstats": phishstats,
        "urlhaus": urlhaus,
        "cisa_kev": cisa_kev,
        "optional_sources": optional_sources,
    }


def lookup_urlhaus(normalized_url: str, domain: str) -> dict[str, Any]:
    result = {
        "source": "URLHaus",
        "status": "unavailable",
        "detail": "Lookup not completed.",
        "matches": [],
    }

    try:
        response = requests.post(URLHAUS_URL_LOOKUP, data={"url": normalized_url}, timeout=REQUEST_TIMEOUT)
        if response.ok:
            payload = response.json()
            query_status = payload.get("query_status")
            if query_status == "ok":
                result.update(
                    {
                        "status": "malicious",
                        "detail": payload.get("threat") or "URL present in URLHaus.",
                        "matches": [
                            {
                                "url_status": payload.get("url_status"),
                                "threat": payload.get("threat"),
                                "tags": payload.get("tags") or [],
                            }
                        ],
                    }
                )
                return result
            if query_status == "no_results":
                result.update({"status": "clean", "detail": "URLHaus returned no result for this URL."})
        else:
            result["detail"] = f"URL lookup returned HTTP {response.status_code}."

        if domain:
            host_response = requests.post(URLHAUS_HOST_LOOKUP, data={"host": domain}, timeout=REQUEST_TIMEOUT)
            if host_response.ok:
                host_payload = host_response.json()
                if host_payload.get("query_status") == "ok":
                    urls = host_payload.get("urls") or []
                    result.update(
                        {
                            "status": "host_malicious",
                            "detail": "URLHaus has malicious URL history for this host.",
                            "matches": urls[:5],
                        }
                    )
                elif result["status"] == "unavailable":
                    result.update({"status": "clean", "detail": "URLHaus returned no result for this host."})
    except requests.RequestException as exc:
        result["detail"] = f"URLHaus lookup unavailable: {exc.__class__.__name__}."
    except ValueError:
        result["detail"] = "URLHaus returned an unreadable response."

    return result


def lookup_phishstats(normalized_url: str, domain: str) -> dict[str, Any]:
    result = {
        "source": "PhishStats",
        "status": "unavailable",
        "detail": "PhishStats lookup not completed.",
        "matches": [],
    }

    matched_by = None
    lookup_domain = registered_domain(domain)
    try:
        matches = []
        # Only query by full URL when it cannot corrupt the filter DSL.
        if not _PHISHSTATS_UNSAFE.intersection(normalized_url):
            response = requests.get(
                PHISHSTATS_LOOKUP,
                params={"_where": f"(url,eq,{normalized_url})", "_sort": "-date", "_size": "5"},
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            matches = response.json()
            if isinstance(matches, list) and matches:
                matched_by = "url"
        if not matches and lookup_domain and not _PHISHSTATS_UNSAFE.intersection(lookup_domain):
            response = requests.get(
                PHISHSTATS_LOOKUP,
                params={"_where": f"(host,eq,{lookup_domain})", "_sort": "-date", "_size": "5"},
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            matches = response.json()
            if isinstance(matches, list) and matches:
                matched_by = "host"
    except requests.RequestException as exc:
        result["detail"] = f"PhishStats lookup unavailable: {exc.__class__.__name__}."
        return result
    except ValueError:
        result["detail"] = "PhishStats returned an unreadable response."
        return result

    if not isinstance(matches, list):
        result.update({"status": "unavailable", "detail": "PhishStats returned an unexpected response."})
        return result

    if matches:
        # A full-URL match is a strong signal; a host-only match is much
        # weaker (shared and benign hosts also appear in the community feed),
        # so the two are reported separately and scored differently.
        if matched_by == "url":
            status = "matched"
            detail = f"PhishStats has {len(matches)} record(s) matching this exact URL."
        else:
            status = "host_matched"
            detail = f"PhishStats has {len(matches)} record(s) for the host {lookup_domain}."
        result.update(
            {
                "status": status,
                "detail": detail,
                "matches": [
                    {
                        "id": item.get("id"),
                        "url": item.get("url"),
                        "host": item.get("host"),
                        "ip": item.get("ip"),
                        "date": item.get("date"),
                        "score": item.get("score"),
                        "title": item.get("title"),
                    }
                    for item in matches[:5]
                ],
            }
        )
    else:
        result.update({"status": "clean", "detail": "No PhishStats records found for this URL or host."})

    return result


def lookup_cisa_kev(text: str, db: Session) -> dict[str, Any]:
    cves = sorted({match.upper() for match in CVE_PATTERN.findall(text)})
    if not cves:
        return {
            "source": "CISA KEV",
            "status": "not_applicable",
            "detail": "No CVEs were found in the submitted text.",
            "matches": [],
        }

    catalog = _get_cached_json(db, "cisa_kev_catalog", max_age=timedelta(hours=24))
    if catalog is None:
        return {
            "source": "CISA KEV",
            "status": "unavailable",
            "detail": "CISA KEV catalog could not be fetched.",
            "matches": [],
        }

    vulnerabilities = catalog.get("vulnerabilities", [])
    cve_set = set(cves)
    matches = [
        {
            "cveID": item.get("cveID"),
            "vendorProject": item.get("vendorProject"),
            "product": item.get("product"),
            "knownRansomwareCampaignUse": item.get("knownRansomwareCampaignUse"),
            "dueDate": item.get("dueDate"),
        }
        for item in vulnerabilities
        if item.get("cveID", "").upper() in cve_set
    ]
    return {
        "source": "CISA KEV",
        "status": "matched" if matches else "no_match",
        "detail": "Known exploited CVEs found." if matches else "CVEs were found, but not in CISA KEV.",
        "matches": matches,
    }


def _get_cached_json(db: Session, source_name: str, max_age: timedelta) -> dict[str, Any] | None:
    now = datetime.now(timezone.utc)
    cache = db.scalar(select(FeedCache).where(FeedCache.source_name == source_name))
    if cache and cache.fetched_at:
        fetched_at = cache.fetched_at
        if fetched_at.tzinfo is None:
            fetched_at = fetched_at.replace(tzinfo=timezone.utc)
        if now - fetched_at < max_age:
            return json.loads(cache.cached_json)

    try:
        response = requests.get(CISA_KEV_JSON, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError):
        return json.loads(cache.cached_json) if cache else None

    if cache is None:
        cache = FeedCache(source_name=source_name, cached_json=json.dumps(payload), fetched_at=now)
        db.add(cache)
    else:
        cache.cached_json = json.dumps(payload)
        cache.fetched_at = now
    db.commit()
    return payload
