from datetime import UTC, datetime, timedelta

from app import dns_intel, optional_sources, redirects
from app.analyzer import analyze_url
from app.domain_intel import lookup_domain_intel


class FakeResponse:
    def __init__(self, payload=None, status_code=200, url="https://example.test", history=None):
        self._payload = payload or {}
        self.status_code = status_code
        self.url = url
        self.history = history or []
        self.headers = {}

    @property
    def ok(self):
        return 200 <= self.status_code < 300

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("HTTP error")

    def close(self):
        return None


def test_domain_intel_parses_rdap_response(monkeypatch):
    created = (datetime.now(UTC) - timedelta(days=5)).isoformat()
    payload = {
        "events": [{"eventAction": "registration", "eventDate": created}],
        "nameservers": [{"ldhName": "ns1.example.test"}],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
            }
        ],
    }

    monkeypatch.setattr("app.domain_intel.requests.get", lambda *args, **kwargs: FakeResponse(payload))
    result = lookup_domain_intel("login.example.test")

    assert result["status"] == "ok"
    assert result["age_days"] <= 5
    assert result["new_domain"] is True
    assert result["registrar"] == "Example Registrar"


def test_new_domain_enrichment_increases_score():
    enrichment = {
        "domain_intel": {"status": "ok", "age_days": 3},
        "dns": {"status": "ok", "warnings": []},
        "redirects": {"redirect_count": 0, "cross_domain": False},
    }
    result = analyze_url("https://login.example.test", enrichment=enrichment)
    labels = {item["label"] for item in result["reasons"]}
    assert "Very new domain" in labels


def test_dns_no_domain_is_not_applicable():
    result = dns_intel.lookup_dns_intel("")
    assert result["status"] == "not_applicable"
    assert "No domain supplied." in result["warnings"]


def test_redirect_trace_detects_cross_domain(monkeypatch):
    # The trace now follows each hop manually (so it can SSRF-check every
    # location), so the fake session returns one response per request.
    hop = FakeResponse(status_code=302, url="http://start.example/login")
    hop.headers = {"Location": "https://other.example/final"}
    final = FakeResponse(status_code=200, url="https://other.example/final")
    responses = iter([hop, final])

    class FakeSession:
        def get(self, *args, **kwargs):
            return next(responses)

    monkeypatch.setattr(redirects.requests, "Session", lambda: FakeSession())
    result = redirects.trace_redirects("http://start.example/login", "start.example")
    assert result["status"] == "suspicious"
    assert result["cross_domain"] is True
    assert result["redirect_count"] == 1


def test_optional_sources_without_keys(monkeypatch):
    for key in ["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY", "URLSCAN_API_KEY"]:
        monkeypatch.delenv(key, raising=False)

    result = optional_sources.lookup_optional_sources("https://example.test", "example.test", "https://example.test", {"resolved_ips": []})

    assert result["virustotal"]["status"] == "not_configured"
    assert result["abuseipdb"]["status"] == "not_configured"
    assert result["otx"]["status"] == "not_configured"
    assert result["urlscan"]["status"] == "not_configured"
    assert result["virustotal_files"]["status"] == "not_applicable"


def test_urlscan_dynamic_submission_extracts_download_hash(monkeypatch):
    file_hash = "a" * 64
    monkeypatch.setenv("URLSCAN_API_KEY", "test-key")
    monkeypatch.setenv("ENABLE_URLSCAN_SUBMISSION", "true")
    monkeypatch.setenv("URLSCAN_INITIAL_WAIT_SECONDS", "0")
    monkeypatch.setenv("URLSCAN_POLL_INTERVAL_SECONDS", "0")
    monkeypatch.setenv("URLSCAN_POLL_TIMEOUT_SECONDS", "1")

    def fake_post(*args, **kwargs):
        return FakeResponse(
            {
                "uuid": "scan-uuid",
                "api": "https://urlscan.io/api/v1/result/scan-uuid/",
                "result": "https://urlscan.io/result/scan-uuid/",
                "visibility": "unlisted",
                "url": "https://example.test",
            }
        )

    def fake_get(*args, **kwargs):
        return FakeResponse(
            {
                "task": {"time": "2026-06-02T12:00:00Z"},
                "page": {
                    "url": "https://example.test/download",
                    "domain": "example.test",
                    "ip": "203.0.113.10",
                    "title": "Download",
                },
                "verdicts": {"overall": {"score": 0, "malicious": False}},
                "meta": {
                    "processors": {
                        "download": {
                            "data": [
                                {
                                    "filename": "invoice.exe",
                                    "url": "https://example.test/invoice.exe",
                                    "mimeType": "application/octet-stream",
                                    "size": 123,
                                    "sha256": file_hash,
                                }
                            ]
                        }
                    }
                },
            }
        )

    monkeypatch.setattr(optional_sources.requests, "post", fake_post)
    monkeypatch.setattr(optional_sources.requests, "get", fake_get)

    result = optional_sources.lookup_urlscan("example.test", "https://example.test")

    assert result["mode"] == "dynamic_submission"
    assert result["status"] == "downloads_found"
    assert result["downloads"][0]["filename"] == "invoice.exe"
    assert result["downloaded_file_hashes"] == [file_hash]


def test_urlscan_blocks_internal_urls_before_submission(monkeypatch):
    monkeypatch.setenv("URLSCAN_API_KEY", "test-key")
    monkeypatch.setenv("ENABLE_URLSCAN_SUBMISSION", "true")

    def fake_post(*args, **kwargs):
        raise AssertionError("internal URL should not be submitted")

    monkeypatch.setattr(optional_sources.requests, "post", fake_post)

    result = optional_sources.lookup_urlscan("127.0.0.1", "http://127.0.0.1/admin")

    assert result["status"] == "blocked"
    assert result["matches"] == []


def test_virustotal_downloaded_file_lookup_reports_malicious(monkeypatch):
    file_hash = "b" * 64
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(*args, **kwargs):
        return FakeResponse(
            {
                "data": {
                    "id": file_hash,
                    "attributes": {
                        "sha256": file_hash,
                        "meaningful_name": "payload.exe",
                        "type_description": "Win32 EXE",
                        "last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 20},
                    },
                }
            }
        )

    monkeypatch.setattr(optional_sources.requests, "get", fake_get)

    result = optional_sources.lookup_virustotal_files([file_hash])

    assert result["status"] == "malicious"
    assert result["matches"][0]["malicious"] == 5
    assert result["matches"][0]["meaningful_name"] == "payload.exe"


def test_phishstats_host_match_scores_lower_than_url_match():
    host = analyze_url("https://example.com", enrichment={"phishstats": {"status": "host_matched", "detail": "Host on file."}})
    url = analyze_url("https://example.com", enrichment={"phishstats": {"status": "matched", "detail": "Exact URL on file."}})
    host_labels = {item["label"] for item in host["reasons"]}
    assert "PhishStats host match" in host_labels
    assert "PhishStats verified phishing feed hit" not in host_labels
    # A benign domain with only a noisy host-level feed match must stay Low.
    assert host["severity"] == "Low"
    assert url["score"] > host["score"]


def test_optional_sources_are_scored_when_malicious():
    enrichment = {
        "domain_intel": {},
        "dns": {},
        "redirects": {},
        "optional_sources": {
            "virustotal": {"status": "malicious", "detail": "2 malicious detections."},
            "abuseipdb": {"status": "malicious", "detail": "Score 100."},
            "otx": {"status": "matched", "detail": "Pulse match."},
            "urlscan": {"status": "downloads_found", "detail": "Dynamic scan found a download."},
            "virustotal_files": {"status": "malicious", "detail": "Downloaded file was malicious."},
        },
    }
    result = analyze_url("https://example.test", enrichment=enrichment)
    labels = {item["label"] for item in result["reasons"]}
    assert "VirusTotal malicious detections" in labels
    assert "AbuseIPDB malicious IP reputation" in labels
    assert "AlienVault OTX pulse match" in labels
    assert "urlscan.io download observed" in labels
    assert "VirusTotal malicious downloaded file" in labels
