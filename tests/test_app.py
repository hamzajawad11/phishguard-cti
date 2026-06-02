import json

import pytest
from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import Analysis


@pytest.fixture(scope="module")
def client():
    # Using TestClient as a context manager runs the lifespan handler, which
    # initializes the database before any request is served.
    with TestClient(app) as test_client:
        yield test_client


def test_dashboard_renders(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "Phishing Intelligence Dashboard" in response.text


def test_analyze_page_renders(client):
    response = client.get("/analyze")
    assert response.status_code == 200
    assert "Analyze Suspicious URLs" in response.text


def test_history_page_renders(client):
    response = client.get("/history")
    assert response.status_code == 200
    assert "Analysis History" in response.text


def test_history_filter_query_is_accepted(client):
    response = client.get("/history", params={"q": "example", "severity": "High"})
    assert response.status_code == 200


def test_csv_export_returns_header_row(client):
    response = client.get("/export/csv")
    assert response.status_code == 200
    assert "id,created_at,severity,score,domain,url" in response.text


def test_missing_analysis_returns_404(client):
    response = client.get("/analysis/99999999")
    assert response.status_code == 404


def test_report_renders_partial_dynamic_sandbox_result(client):
    enrichment = {
        "url_resolution": {"status": "provided", "url": "https://www.google.com", "detail": "Input already included a URL scheme."},
        "domain_intel": {"status": "ok", "domain": "google.com"},
        "dns": {"status": "ok", "records": {}},
        "redirects": {"status": "ok", "final_url": "https://www.google.com", "redirect_count": 0},
        "optional_sources": {
            "urlscan": {
                "source": "urlscan.io",
                "mode": "dynamic_submission",
                "status": "unavailable",
                "detail": "The submitted URL was blocked from scanning.",
                "matches": [],
                "submission_enabled": True,
            },
            "virustotal_files": {"status": "not_applicable", "detail": "No downloaded file hashes were available."},
        },
    }
    with SessionLocal() as db:
        record = Analysis(
            original_input="https://www.google.com",
            normalized_url="https://www.google.com",
            domain="www.google.com",
            severity="Medium",
            score=30,
            reasons_json=json.dumps([]),
            iocs_json=json.dumps({}),
            enrichment_json=json.dumps(enrichment),
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        analysis_id = record.id

    response = client.get(f"/analysis/{analysis_id}")

    assert response.status_code == 200
    assert "Dynamic Sandbox Analysis" in response.text
    assert "unavailable" in response.text
