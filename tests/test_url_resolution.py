from app.url_resolution import resolve_live_url


class FakeResponse:
    def __init__(self, status_code):
        self.status_code = status_code

    def close(self):
        return None


def test_resolve_live_url_uses_provided_scheme():
    result = resolve_live_url("http://example.com")
    assert result["status"] == "provided"
    assert result["url"] == "http://example.com"


def test_resolve_live_url_prefers_reachable_https(monkeypatch):
    def fake_head(url, **kwargs):
        if url.startswith("https://"):
            return FakeResponse(200)
        return FakeResponse(200)

    monkeypatch.setattr("app.url_resolution.requests.head", fake_head)
    result = resolve_live_url("example.com")
    assert result["status"] == "resolved"
    assert result["url"] == "https://example.com"


def test_resolve_live_url_falls_back_to_http_when_https_fails(monkeypatch):
    def fake_head(url, **kwargs):
        if url.startswith("https://"):
            raise Exception("TLS failed")
        return FakeResponse(200)

    monkeypatch.setattr("app.url_resolution.requests.head", fake_head)
    monkeypatch.setattr("app.url_resolution.requests.RequestException", Exception)
    result = resolve_live_url("example.com")
    assert result["status"] == "resolved"
    assert result["url"] == "http://example.com"
