import pytest
from fastapi.testclient import TestClient

from app.main import app


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
