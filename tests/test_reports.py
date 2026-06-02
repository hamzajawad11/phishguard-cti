import json

from app.models import Analysis
from app.reports import analysis_to_dict, render_html_report


def test_report_conversion_and_html_rendering():
    analysis = Analysis(
        id=1,
        original_input="http://login.example.test",
        normalized_url="http://login.example.test",
        domain="login.example.test",
        severity="Medium",
        score=35,
        reasons_json=json.dumps([{"label": "No HTTPS", "weight": 12, "detail": "The URL does not use HTTPS."}]),
        iocs_json=json.dumps({"urls": ["http://login.example.test"], "domains": ["login.example.test"]}),
        enrichment_json=json.dumps({"urlhaus": {"source": "URLHaus", "status": "clean", "detail": "No result."}}),
    )
    data = analysis_to_dict(analysis)
    html = render_html_report(analysis)
    assert data["severity"] == "Medium"
    assert "PhishGuard CTI Report" in html
    assert "login.example.test" in html
