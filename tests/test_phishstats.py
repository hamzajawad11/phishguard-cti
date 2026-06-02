from app.enrichment import lookup_phishstats


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def test_phishstats_falls_back_to_registered_domain(monkeypatch):
    calls = []

    def fake_get(url, params, timeout):
        calls.append(params["_where"])
        if "url,eq" in params["_where"]:
            return FakeResponse([])
        return FakeResponse([{"id": 1, "url": "https://sub.example.com/login", "host": "example.com"}])

    monkeypatch.setattr("app.enrichment.requests.get", fake_get)
    result = lookup_phishstats("https://sub.example.com/login", "sub.example.com")

    # A host-only fallback match is the weaker signal and is reported as such.
    assert result["status"] == "host_matched"
    assert "(host,eq,example.com)" in calls


def test_phishstats_exact_url_match_is_strong(monkeypatch):
    def fake_get(url, params, timeout):
        return FakeResponse([{"id": 2, "url": "https://sub.example.com/login", "host": "sub.example.com"}])

    monkeypatch.setattr("app.enrichment.requests.get", fake_get)
    result = lookup_phishstats("https://sub.example.com/login", "sub.example.com")

    assert result["status"] == "matched"
