from app.analyzer import analyze_url, extract_iocs, extract_scan_targets, normalize_url


def test_normalize_url_adds_scheme():
    assert normalize_url("example.com/login") == "https://example.com/login"
    assert normalize_url("www.example.com") == "https://www.example.com"


def test_benign_url_scores_low():
    result = analyze_url("https://www.microsoft.com/security")
    assert result["severity"] == "Low"
    assert result["score"] < 25


def test_suspicious_url_scores_high_or_critical():
    result = analyze_url("http://login-microsoft-security-update.xyz/verify/account?redirect=http://192.168.10.20")
    assert result["severity"] in {"High", "Critical"}
    labels = {item["label"] for item in result["reasons"]}
    assert "No HTTPS" in labels
    assert "Phishing keywords" in labels
    assert "Brand impersonation signal" in labels


def test_extract_iocs_from_mixed_text():
    text = "Visit http://evil.example/login from 8.8.8.8 CVE-2023-34362 hash d41d8cd98f00b204e9800998ecf8427e"
    iocs = extract_iocs(text)
    assert "http://evil.example/login" in iocs["urls"]
    assert "evil.example" in iocs["domains"]
    assert "8.8.8.8" in iocs["ips"]
    assert "CVE-2023-34362" in iocs["cves"]
    assert "d41d8cd98f00b204e9800998ecf8427e" in iocs["hashes"]


def test_extract_scan_targets_is_url_domain_first():
    text = """
    google.com
    CVE-2023-34362
    d41d8cd98f00b204e9800998ecf8427e
    http://login.example.test/path
    8.8.8.8
    """
    assert extract_scan_targets(text) == ["http://login.example.test/path", "google.com"]


def test_extract_scan_targets_from_email_body_text():
    text = "Confirm your mailbox at micros0ft-login-security.com/verify today."
    assert "micros0ft-login-security.com" in extract_scan_targets(text)


def test_urlhaus_enrichment_raises_score():
    clean = analyze_url("https://example.com/path")
    enriched = analyze_url("https://example.com/path", enrichment={"urlhaus": {"status": "malicious"}})
    assert enriched["score"] > clean["score"]
    assert enriched["severity"] in {"Medium", "High", "Critical"}


def test_phishstats_enrichment_raises_score():
    enriched = analyze_url("https://example.test", enrichment={"phishstats": {"status": "matched", "detail": "Feed hit."}})
    labels = {item["label"] for item in enriched["reasons"]}
    assert "PhishStats verified phishing feed hit" in labels
