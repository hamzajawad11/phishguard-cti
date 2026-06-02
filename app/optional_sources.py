import base64
import hashlib
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import quote

import requests

from app.analyzer import extract_iocs
from app.config import OPTIONAL_API_TIMEOUT
from app.security import is_safe_url


REQUEST_TIMEOUT = OPTIONAL_API_TIMEOUT
URLSCAN_SCAN_URL = "https://urlscan.io/api/v1/scan/"
URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/"
URLSCAN_RESULT_URL = "https://urlscan.io/api/v1/result/{uuid}/"
HASH_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
MAX_FILE_HASH_LOOKUPS = 5

# Human-readable detail for each error state surfaced by _safe_get_json.
_ERROR_DETAIL = {
    "unauthorized": "API key was rejected.",
    "rate_limited": "Provider rate limit reached.",
    "unavailable": "Provider could not be reached.",
    "unreadable": "Provider returned an unreadable response.",
}


def _dominant_error(matches: list[dict[str, Any]]) -> str | None:
    """Return an error status if no lookup succeeded, else None.

    A lookup counts as successful when its status is "ok" or "not_found"
    (a 404 just means the indicator is not on file, which is not an error).
    """
    statuses = [match.get("status") for match in matches]
    if not statuses or any(status in {"ok", "not_found"} for status in statuses):
        return None
    for status in ("unauthorized", "rate_limited", "unavailable", "unreadable"):
        if status in statuses:
            return status
    return None


def lookup_optional_sources(normalized_url: str, domain: str, original_text: str, dns_intel: dict[str, Any]) -> dict[str, Any]:
    iocs = extract_iocs(original_text)
    resolved_ips = dns_intel.get("resolved_ips", []) if isinstance(dns_intel, dict) else []
    ips = sorted(set(iocs.get("ips", []) + resolved_ips))
    hashes = iocs.get("hashes", [])

    # The four providers are independent of one another, so query them in
    # parallel. Each provider returns a self-contained result dict.
    with ThreadPoolExecutor(max_workers=4) as pool:
        future_vt = pool.submit(lookup_virustotal, normalized_url, domain, ips, hashes)
        future_abuse = pool.submit(lookup_abuseipdb, ips)
        future_otx = pool.submit(lookup_otx, normalized_url, domain, ips, hashes, iocs.get("cves", []))
        future_urlscan = pool.submit(lookup_urlscan, domain, normalized_url)
        virustotal = future_vt.result()
        abuseipdb = future_abuse.result()
        otx = future_otx.result()
        urlscan = future_urlscan.result()

        vt_file_hashes = urlscan.get("downloaded_file_hashes", []) if isinstance(urlscan, dict) else []
        virustotal_files = lookup_virustotal_files(vt_file_hashes)

        return {
            "virustotal": virustotal,
            "abuseipdb": abuseipdb,
            "otx": otx,
            "urlscan": urlscan,
            "virustotal_files": virustotal_files,
        }


def provider_not_configured(source: str, env_name: str) -> dict[str, Any]:
    return {
        "source": source,
        "status": "not_configured",
        "detail": f"{env_name} is not set.",
        "matches": [],
    }


def lookup_virustotal(url: str, domain: str, ips: list[str], hashes: list[str]) -> dict[str, Any]:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return provider_not_configured("VirusTotal", "VIRUSTOTAL_API_KEY")

    headers = {"x-apikey": api_key}
    lookups = []
    candidates = [
        ("url", _vt_url_id(url), "urls"),
        ("domain", domain, "domains"),
    ]
    candidates.extend(("ip", ip, "ip_addresses") for ip in ips[:3])
    candidates.extend(("hash", value, "files") for value in hashes[:3])

    for indicator_type, indicator, endpoint in candidates:
        if not indicator:
            continue
        payload = _safe_get_json(f"https://www.virustotal.com/api/v3/{endpoint}/{indicator}", headers=headers)
        lookups.append(_vt_summary(indicator_type, indicator, payload))

    error = _dominant_error(lookups)
    if error:
        return {
            "source": "VirusTotal",
            "status": error,
            "detail": _ERROR_DETAIL.get(error, "Lookup failed."),
            "matches": lookups,
        }

    max_malicious = max((item.get("malicious", 0) for item in lookups), default=0)
    max_suspicious = max((item.get("suspicious", 0) for item in lookups), default=0)
    status = "malicious" if max_malicious >= 3 else "suspicious" if max_malicious or max_suspicious else "clean"
    return {
        "source": "VirusTotal",
        "status": status,
        "detail": f"Highest detections: {max_malicious} malicious, {max_suspicious} suspicious.",
        "matches": lookups,
    }


def lookup_virustotal_files(file_hashes: list[str]) -> dict[str, Any]:
    hashes = sorted({value.lower() for value in file_hashes if HASH_PATTERN.fullmatch(str(value))})
    if not hashes:
        return {
            "source": "VirusTotal Downloaded Files",
            "status": "not_applicable",
            "detail": "No downloaded file hashes were observed by urlscan.io.",
            "matches": [],
        }

    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return provider_not_configured("VirusTotal Downloaded Files", "VIRUSTOTAL_API_KEY")

    headers = {"x-apikey": api_key}
    matches = []
    for file_hash in hashes[:MAX_FILE_HASH_LOOKUPS]:
        payload = _safe_get_json(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers)
        matches.append(_vt_file_summary(file_hash, payload))

    error = _dominant_error(matches)
    if error:
        return {
            "source": "VirusTotal Downloaded Files",
            "status": error,
            "detail": _ERROR_DETAIL.get(error, "Lookup failed."),
            "matches": matches,
        }

    found = [item for item in matches if item.get("status") == "ok"]
    max_malicious = max((item.get("malicious", 0) for item in found), default=0)
    max_suspicious = max((item.get("suspicious", 0) for item in found), default=0)
    if max_malicious >= 3:
        status = "malicious"
    elif max_malicious or max_suspicious:
        status = "suspicious"
    elif found:
        status = "clean"
    else:
        status = "not_found"

    return {
        "source": "VirusTotal Downloaded Files",
        "status": status,
        "detail": f"Checked {len(matches)} downloaded file hash(es): highest detections {max_malicious} malicious, {max_suspicious} suspicious.",
        "matches": matches,
    }


def lookup_abuseipdb(ips: list[str]) -> dict[str, Any]:
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return provider_not_configured("AbuseIPDB", "ABUSEIPDB_API_KEY")
    if not ips:
        return {"source": "AbuseIPDB", "status": "not_applicable", "detail": "No IPs available for lookup.", "matches": []}

    headers = {"Key": api_key, "Accept": "application/json"}
    matches = []
    for ip in ips[:5]:
        payload = _safe_get_json(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""},
        )
        data = payload.get("data") if isinstance(payload, dict) else None
        matches.append(
            {
                "indicator": ip,
                "status": payload.get("_status", "ok") if isinstance(payload, dict) else "unavailable",
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0) if data else 0,
                "total_reports": data.get("totalReports", 0) if data else 0,
                "country_code": data.get("countryCode") if data else None,
                "isp": data.get("isp") if data else None,
            }
        )

    error = _dominant_error(matches)
    if error:
        return {
            "source": "AbuseIPDB",
            "status": error,
            "detail": _ERROR_DETAIL.get(error, "Lookup failed."),
            "matches": matches,
        }

    max_confidence = max((item.get("abuse_confidence_score", 0) for item in matches), default=0)
    status = "malicious" if max_confidence >= 75 else "suspicious" if max_confidence >= 25 else "clean"
    return {
        "source": "AbuseIPDB",
        "status": status,
        "detail": f"Highest abuse confidence score: {max_confidence}.",
        "matches": matches,
    }


def lookup_otx(url: str, domain: str, ips: list[str], hashes: list[str], cves: list[str]) -> dict[str, Any]:
    api_key = os.getenv("OTX_API_KEY")
    if not api_key:
        return provider_not_configured("AlienVault OTX", "OTX_API_KEY")

    headers = {"X-OTX-API-KEY": api_key}
    candidates = [("URL", url), ("domain", domain)]
    candidates.extend(("IPv4", ip) for ip in ips[:3])
    candidates.extend(("file", value) for value in hashes[:3])
    candidates.extend(("CVE", cve) for cve in cves[:3])
    matches = []

    for indicator_type, indicator in candidates:
        if not indicator:
            continue
        encoded_indicator = quote(indicator, safe="")
        payload = _safe_get_json(f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{encoded_indicator}/general", headers=headers)
        pulse_info = payload.get("pulse_info", {}) if isinstance(payload, dict) else {}
        count = pulse_info.get("count", 0) if isinstance(pulse_info, dict) else 0
        matches.append(
            {
                "indicator_type": indicator_type,
                "indicator": indicator,
                "status": payload.get("_status", "ok") if isinstance(payload, dict) else "unavailable",
                "pulse_count": count,
            }
        )

    error = _dominant_error(matches)
    if error:
        return {
            "source": "AlienVault OTX",
            "status": error,
            "detail": _ERROR_DETAIL.get(error, "Lookup failed."),
            "matches": matches,
        }

    max_pulses = max((item.get("pulse_count", 0) for item in matches), default=0)
    status = "matched" if max_pulses else "clean"
    return {
        "source": "AlienVault OTX",
        "status": status,
        "detail": f"Highest OTX pulse count: {max_pulses}.",
        "matches": matches,
    }


def lookup_urlscan(domain: str, url: str) -> dict[str, Any]:
    api_key = os.getenv("URLSCAN_API_KEY")
    if not api_key:
        return provider_not_configured("urlscan.io", "URLSCAN_API_KEY")
    if not domain:
        return {"source": "urlscan.io", "status": "not_applicable", "detail": "No domain available.", "matches": []}
    if not is_safe_url(url):
        return {
            "source": "urlscan.io",
            "status": "blocked",
            "detail": "URL resolves to a private or internal address, so it was not submitted to urlscan.io.",
            "matches": [],
            "submission_enabled": os.getenv("ENABLE_URLSCAN_SUBMISSION", "false").lower() == "true",
        }

    if os.getenv("ENABLE_URLSCAN_SUBMISSION", "false").lower() == "true":
        return _lookup_urlscan_dynamic(api_key, domain, url)

    return _lookup_urlscan_search(api_key, domain)


def _lookup_urlscan_search(api_key: str, domain: str) -> dict[str, Any]:
    headers = {"API-Key": api_key}
    payload = _safe_get_json(URLSCAN_SEARCH_URL, headers=headers, params={"q": f"domain:{domain}", "size": "5"})
    status = payload.get("_status") if isinstance(payload, dict) else "unavailable"
    if status in _ERROR_DETAIL:
        return {
            "source": "urlscan.io",
            "status": status,
            "detail": _ERROR_DETAIL[status],
            "matches": [],
        }
    results = payload.get("results", []) if isinstance(payload, dict) else []
    malicious = [
        item
        for item in results
        if item.get("verdicts", {}).get("overall", {}).get("malicious")
        or item.get("verdicts", {}).get("overall", {}).get("score", 0) >= 50
    ]
    return {
        "source": "urlscan.io",
        "mode": "passive_search",
        "status": "malicious" if malicious else "clean",
        "detail": f"Found {len(results)} public scan results; {len(malicious)} flagged malicious.",
        "matches": [
            {
                "task_time": item.get("task", {}).get("time"),
                "page_url": item.get("page", {}).get("url"),
                "result": item.get("result"),
                "score": item.get("verdicts", {}).get("overall", {}).get("score"),
                "malicious": item.get("verdicts", {}).get("overall", {}).get("malicious"),
            }
            for item in results[:5]
        ],
        "submission_enabled": os.getenv("ENABLE_URLSCAN_SUBMISSION", "false").lower() == "true",
    }


def _lookup_urlscan_dynamic(api_key: str, domain: str, url: str) -> dict[str, Any]:
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    visibility = _urlscan_visibility()
    submit_payload = {
        "url": url,
        "visibility": visibility,
        "tags": ["phishguard", "dynamic-analysis"],
    }
    try:
        response = requests.post(URLSCAN_SCAN_URL, headers=headers, json=submit_payload, timeout=REQUEST_TIMEOUT)
        if response.status_code in {401, 403}:
            return _urlscan_error("unauthorized", "API key was rejected.")
        if response.status_code == 429:
            return _urlscan_error("rate_limited", "Provider rate limit reached.")
        if not response.ok:
            return _urlscan_error("unavailable", _response_detail(response, "urlscan.io submission failed."))
        submission = response.json()
    except requests.RequestException as exc:
        return _urlscan_error("unavailable", f"urlscan.io submission unavailable: {exc.__class__.__name__}.")
    except ValueError:
        return _urlscan_error("unreadable", "urlscan.io submission returned an unreadable response.")

    uuid = submission.get("uuid")
    result_api = submission.get("api") or (URLSCAN_RESULT_URL.format(uuid=uuid) if uuid else "")
    if not uuid or not result_api:
        return _urlscan_error("unreadable", "urlscan.io did not return a scan UUID.", submission=submission)

    result_payload = _poll_urlscan_result(result_api, api_key)
    if result_payload.get("status") != "ok":
        result_payload["submission"] = _urlscan_submission_summary(submission, visibility)
        uuid_for_links = str(uuid)
        result_payload["screenshot_url"] = f"https://urlscan.io/screenshots/{uuid_for_links}.png"
        result_payload["dom_url"] = f"https://urlscan.io/dom/{uuid_for_links}/"
        return result_payload

    result = result_payload["result"]
    page = result.get("page", {}) if isinstance(result, dict) else {}
    verdict = _urlscan_verdict(result)
    downloads = _extract_urlscan_downloads(result)
    downloaded_hashes = sorted({hash_value for item in downloads for hash_value in item.get("hashes", [])})
    uuid = str(uuid)
    malicious = bool(verdict.get("malicious")) or int(verdict.get("score") or 0) >= 50
    if malicious:
        status = "malicious"
    elif downloads:
        status = "downloads_found"
    else:
        status = "clean"

    final_url = page.get("url") or url
    download_detail = f"{len(downloads)} download(s) detected" if downloads else "no downloads observed"
    return {
        "source": "urlscan.io",
        "mode": "dynamic_submission",
        "status": status,
        "detail": f"Dynamic scan completed for {final_url}; {download_detail}.",
        "matches": [
            {
                "task_time": result.get("task", {}).get("time"),
                "page_url": final_url,
                "result": submission.get("result"),
                "score": verdict.get("score"),
                "malicious": verdict.get("malicious"),
            }
        ],
        "submission_enabled": True,
        "submission": _urlscan_submission_summary(submission, visibility),
        "page": {
            "url": final_url,
            "domain": page.get("domain") or domain,
            "ip": page.get("ip"),
            "country": page.get("country"),
            "status": page.get("status"),
            "title": page.get("title"),
        },
        "verdict": verdict,
        "downloads": downloads,
        "downloaded_file_hashes": downloaded_hashes,
        "screenshot_url": f"https://urlscan.io/screenshots/{uuid}.png",
        "dom_url": f"https://urlscan.io/dom/{uuid}/",
    }


def _poll_urlscan_result(result_api: str, api_key: str) -> dict[str, Any]:
    initial_wait = _env_float("URLSCAN_INITIAL_WAIT_SECONDS", 10)
    poll_timeout = _env_float("URLSCAN_POLL_TIMEOUT_SECONDS", 45)
    poll_interval = _env_float("URLSCAN_POLL_INTERVAL_SECONDS", 5)
    headers = {"API-Key": api_key}

    if initial_wait > 0:
        time.sleep(initial_wait)

    deadline = time.monotonic() + poll_timeout
    while True:
        try:
            response = requests.get(result_api, headers=headers, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                return {"status": "ok", "result": response.json()}
            if response.status_code == 404:
                if time.monotonic() >= deadline:
                    return _urlscan_error("pending", "urlscan.io scan was submitted but the result was not ready before the local timeout.")
            elif response.status_code == 410:
                return _urlscan_error("unavailable", "urlscan.io scan result was deleted.")
            elif response.status_code in {401, 403}:
                return _urlscan_error("unauthorized", "API key was rejected.")
            elif response.status_code == 429:
                return _urlscan_error("rate_limited", "Provider rate limit reached.")
            else:
                return _urlscan_error("unavailable", _response_detail(response, "urlscan.io result lookup failed."))
        except requests.RequestException as exc:
            return _urlscan_error("unavailable", f"urlscan.io result lookup unavailable: {exc.__class__.__name__}.")
        except ValueError:
            return _urlscan_error("unreadable", "urlscan.io result endpoint returned unreadable JSON.")

        sleep_for = min(max(poll_interval, 0), max(deadline - time.monotonic(), 0))
        if sleep_for <= 0:
            return _urlscan_error("pending", "urlscan.io scan was submitted but the result was not ready before the local timeout.")
        time.sleep(sleep_for)


def _urlscan_error(status: str, detail: str, submission: dict[str, Any] | None = None) -> dict[str, Any]:
    result = {
        "source": "urlscan.io",
        "mode": "dynamic_submission",
        "status": status,
        "detail": detail,
        "matches": [],
        "submission_enabled": True,
    }
    if submission:
        result["submission"] = submission
    return result


def _urlscan_submission_summary(submission: dict[str, Any], visibility: str) -> dict[str, Any]:
    return {
        "uuid": submission.get("uuid"),
        "result": submission.get("result"),
        "api": submission.get("api"),
        "visibility": submission.get("visibility") or visibility,
        "url": submission.get("url"),
    }


def _urlscan_visibility() -> str:
    visibility = os.getenv("URLSCAN_VISIBILITY", "unlisted").strip().lower()
    if visibility in {"public", "unlisted", "private"}:
        return visibility
    return "unlisted"


def _urlscan_verdict(result: dict[str, Any]) -> dict[str, Any]:
    verdicts = result.get("verdicts", {}) if isinstance(result, dict) else {}
    overall = verdicts.get("overall", {}) if isinstance(verdicts, dict) else {}
    urlscan = verdicts.get("urlscan", {}) if isinstance(verdicts, dict) else {}
    overall = overall if isinstance(overall, dict) else {}
    urlscan = urlscan if isinstance(urlscan, dict) else {}
    score = overall.get("score", urlscan.get("score", 0))
    try:
        score = int(score or 0)
    except (TypeError, ValueError):
        score = 0
    malicious = overall.get("malicious") if isinstance(overall, dict) else None
    if malicious is None:
        malicious = score >= 50
    return {
        "score": score,
        "malicious": bool(malicious),
        "categories": overall.get("categories") or urlscan.get("categories") or [],
        "brands": urlscan.get("brands") or overall.get("brands") or [],
    }


def _extract_urlscan_downloads(result: dict[str, Any]) -> list[dict[str, Any]]:
    meta = result.get("meta", {}) if isinstance(result, dict) else {}
    processors = meta.get("processors", {}) if isinstance(meta, dict) else {}
    download = processors.get("download", {}) if isinstance(processors, dict) else {}
    download_data = download.get("data") if isinstance(download, dict) else None
    records = []
    seen = set()

    for item in _download_items(download_data):
        hashes = sorted(_hashes_from_object(item))
        if not hashes:
            continue
        key = tuple(hashes)
        if key in seen:
            continue
        seen.add(key)
        records.append(
            {
                "filename": _first_value(item, ("filename", "fileName", "name", "suggestedFilename")),
                "url": _first_value(item, ("url", "requestUrl", "href")),
                "mime_type": _first_value(item, ("mimeType", "mime", "contentType")),
                "size": _first_value(item, ("size", "contentLength", "length")),
                "hashes": hashes,
            }
        )

    return records[:MAX_FILE_HASH_LOOKUPS]


def _download_items(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        items = []
        for item in value:
            items.extend(_download_items(item))
        return items
    if not isinstance(value, dict):
        return []

    direct_keys = {"sha256", "sha1", "md5", "hash", "filename", "fileName", "name", "url", "mimeType", "size"}
    if direct_keys.intersection(value):
        return [value]

    items = []
    for key, child in value.items():
        if isinstance(child, dict):
            item = dict(child)
            if HASH_PATTERN.fullmatch(str(key)):
                item.setdefault("hash", str(key))
            items.append(item)
        elif isinstance(child, list):
            items.extend(_download_items(child))
        elif HASH_PATTERN.fullmatch(str(key)):
            items.append({"hash": str(key), "value": child})
        elif HASH_PATTERN.fullmatch(str(child)):
            items.append({"hash": str(child), "field": key})
    return items


def _hashes_from_object(value: Any) -> set[str]:
    hashes = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if HASH_PATTERN.fullmatch(str(key)):
                hashes.add(str(key).lower())
            hashes.update(_hashes_from_object(child))
    elif isinstance(value, list):
        for item in value:
            hashes.update(_hashes_from_object(item))
    elif isinstance(value, str) and HASH_PATTERN.fullmatch(value):
        hashes.add(value.lower())
    return hashes


def _first_value(item: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        value = item.get(key)
        if value is not None and value != "":
            return value
    return None


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def _response_detail(response: requests.Response, fallback: str) -> str:
    try:
        payload = response.json()
    except ValueError:
        return f"{fallback} HTTP {response.status_code}."
    if isinstance(payload, dict):
        detail = payload.get("description") or payload.get("message") or payload.get("detail")
        if detail:
            return str(detail)
    return f"{fallback} HTTP {response.status_code}."


def _safe_get_json(url: str, headers: dict[str, str], params: dict[str, str] | None = None) -> dict[str, Any]:
    try:
        response = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
        if response.status_code in {401, 403}:
            return {"_status": "unauthorized", "_detail": "API key was rejected."}
        if response.status_code == 404:
            return {"_status": "not_found"}
        if response.status_code == 429:
            return {"_status": "rate_limited", "_detail": "Provider rate limit reached."}
        response.raise_for_status()
        payload = response.json()
        if isinstance(payload, dict):
            payload["_status"] = "ok"
        return payload
    except requests.RequestException as exc:
        return {"_status": "unavailable", "_detail": exc.__class__.__name__}
    except ValueError:
        return {"_status": "unreadable", "_detail": "Provider returned unreadable JSON."}


def _vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def _vt_file_summary(file_hash: str, payload: dict[str, Any]) -> dict[str, Any]:
    status = payload.get("_status", "ok") if isinstance(payload, dict) else "unavailable"
    if status != "ok":
        return {
            "indicator_type": "file",
            "indicator": file_hash,
            "status": status,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "fingerprint": hashlib.sha256(file_hash.encode("utf-8")).hexdigest()[:16],
        }

    data = payload.get("data", {}) if isinstance(payload, dict) else {}
    attrs = data.get("attributes", {}) if isinstance(data, dict) else {}
    stats = attrs.get("last_analysis_stats", {}) if isinstance(attrs, dict) else {}
    names = attrs.get("names", []) if isinstance(attrs, dict) else []
    return {
        "indicator_type": "file",
        "indicator": file_hash,
        "status": status,
        "sha256": attrs.get("sha256") or data.get("id") or file_hash,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "meaningful_name": attrs.get("meaningful_name"),
        "names": names[:3] if isinstance(names, list) else [],
        "type_description": attrs.get("type_description"),
        "size": attrs.get("size"),
        "threat_verdict": attrs.get("threat_verdict"),
        "fingerprint": hashlib.sha256(file_hash.encode("utf-8")).hexdigest()[:16],
    }


def _vt_summary(indicator_type: str, indicator: str, payload: dict[str, Any]) -> dict[str, Any]:
    attrs = payload.get("data", {}).get("attributes", {}) if isinstance(payload, dict) else {}
    stats = attrs.get("last_analysis_stats", {}) if isinstance(attrs, dict) else {}
    return {
        "indicator_type": indicator_type,
        "indicator": indicator,
        "status": payload.get("_status", "ok") if isinstance(payload, dict) else "unavailable",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "reputation": attrs.get("reputation"),
        "fingerprint": hashlib.sha256(indicator.encode("utf-8")).hexdigest()[:16],
    }
