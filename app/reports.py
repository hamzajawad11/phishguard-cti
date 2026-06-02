import csv
import io
import json
from datetime import UTC, datetime
from html import escape

from app.models import Analysis


def loads_json(value: str):
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return {}


def analysis_to_dict(analysis: Analysis) -> dict:
    return {
        "id": analysis.id,
        "original_input": analysis.original_input,
        "normalized_url": analysis.normalized_url,
        "domain": analysis.domain,
        "severity": analysis.severity,
        "score": analysis.score,
        "reasons": loads_json(analysis.reasons_json),
        "iocs": loads_json(analysis.iocs_json),
        "enrichment": loads_json(analysis.enrichment_json),
        "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
    }


def analyses_to_csv(analyses: list[Analysis]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "created_at", "severity", "score", "domain", "url"])
    for item in analyses:
        writer.writerow(
            [
                item.id,
                item.created_at.isoformat() if item.created_at else "",
                item.severity,
                item.score,
                item.domain,
                item.normalized_url,
            ]
        )
    return output.getvalue()


def render_html_report(analysis: Analysis) -> str:
    data = analysis_to_dict(analysis)
    reasons = data["reasons"] if isinstance(data["reasons"], list) else []
    iocs = data["iocs"] if isinstance(data["iocs"], dict) else {}
    enrichment = data["enrichment"] if isinstance(data["enrichment"], dict) else {}
    url_resolution = enrichment.get("url_resolution", {}) if isinstance(enrichment.get("url_resolution"), dict) else {}
    domain_intel = enrichment.get("domain_intel", {}) if isinstance(enrichment.get("domain_intel"), dict) else {}
    dns = enrichment.get("dns", {}) if isinstance(enrichment.get("dns"), dict) else {}
    redirects = enrichment.get("redirects", {}) if isinstance(enrichment.get("redirects"), dict) else {}
    optional_sources = enrichment.get("optional_sources", {}) if isinstance(enrichment.get("optional_sources"), dict) else {}
    sandbox = optional_sources.get("urlscan", {}) if isinstance(optional_sources.get("urlscan"), dict) else {}
    vt_files = optional_sources.get("virustotal_files", {}) if isinstance(optional_sources.get("virustotal_files"), dict) else {}
    reasons_html = "".join(
        f"<li><strong>{escape(item.get('label', 'Finding'))}</strong>: "
        f"{escape(item.get('detail', ''))} (+{escape(str(item.get('weight', '')))} points)</li>"
        for item in reasons
    )
    ioc_html = "".join(
        f"<h3>{escape(key.upper())}</h3><ul>"
        + "".join(f"<li>{escape(str(value))}</li>" for value in values)
        + "</ul>"
        for key, values in iocs.items()
        if values
    )
    dns_html = "".join(
        f"<h3>{escape(record_type)}</h3><ul>"
        + "".join(f"<li>{escape(str(value))}</li>" for value in values)
        + "</ul>"
        for record_type, values in (dns.get("records") or {}).items()
    )
    redirect_html = "".join(
        f"<li>{escape(str(hop.get('status_code')))} - {escape(str(hop.get('domain')))} - "
        f"{escape(str(hop.get('location') or hop.get('url')))}</li>"
        for hop in redirects.get("chain", [])
    )
    resolution_html = "".join(
        f"<li>{escape(str(attempt.get('url')))} - "
        f"{escape(str(attempt.get('status_code') or attempt.get('error') or 'No response'))} - "
        f"{'Reachable' if attempt.get('reachable') else 'Not reachable'}</li>"
        for attempt in url_resolution.get("attempts", [])
    )
    enrichment_html = "".join(
        f"<h3>{escape(str(value.get('source', key)))}</h3>"
        f"<p>Status: <strong>{escape(str(value.get('status', 'unknown')))}</strong></p>"
        f"<p>{escape(str(value.get('detail', '')))}</p>"
        for key, value in enrichment.items()
        if isinstance(value, dict) and key != "optional_sources"
    )
    optional_html = "".join(
        f"<h3>{escape(str(value.get('source', key)))}</h3>"
        f"<p>Status: <strong>{escape(str(value.get('status', 'unknown')))}</strong></p>"
        f"<p>{escape(str(value.get('detail', '')))}</p>"
        for key, value in optional_sources.items()
        if isinstance(value, dict)
    )
    download_html = "".join(
        f"<li><strong>{escape(str(item.get('filename') or 'Downloaded file'))}</strong> "
        f"{escape(str(item.get('url') or ''))}<br>"
        + "".join(f"<code>{escape(str(hash_value))}</code> " for hash_value in item.get("hashes", []))
        + "</li>"
        for item in sandbox.get("downloads", [])
        if isinstance(item, dict)
    )
    vt_file_html = "".join(
        f"<li><strong>{escape(str(item.get('meaningful_name') or item.get('type_description') or 'file hash'))}</strong>: "
        f"{escape(str(item.get('malicious', 0)))} malicious / "
        f"{escape(str(item.get('suspicious', 0)))} suspicious / "
        f"{escape(str(item.get('harmless', 0)))} harmless<br>"
        f"<code>{escape(str(item.get('sha256') or item.get('indicator') or ''))}</code></li>"
        for item in vt_files.get("matches", [])
        if isinstance(item, dict)
    )
    sandbox_html = ""
    if sandbox.get("mode") == "dynamic_submission":
        page = sandbox.get("page", {}) if isinstance(sandbox.get("page"), dict) else {}
        verdict = sandbox.get("verdict", {}) if isinstance(sandbox.get("verdict"), dict) else {}
        submission = sandbox.get("submission", {}) if isinstance(sandbox.get("submission"), dict) else {}
        sandbox_html = f"""
  <h2>Dynamic Sandbox Analysis</h2>
  <table>
    <tr><th>Status</th><td>{escape(str(sandbox.get('status') or 'unknown'))}</td></tr>
    <tr><th>Visibility</th><td>{escape(str(submission.get('visibility') or 'unlisted'))}</td></tr>
    <tr><th>Final URL</th><td>{escape(str(page.get('url') or data['normalized_url']))}</td></tr>
    <tr><th>Page Title</th><td>{escape(str(page.get('title') or 'Unknown'))}</td></tr>
    <tr><th>urlscan Score</th><td>{escape(str(verdict.get('score') or 0))}</td></tr>
    <tr><th>urlscan Result</th><td>{escape(str(submission.get('result') or 'Unavailable'))}</td></tr>
    <tr><th>Screenshot</th><td>{escape(str(sandbox.get('screenshot_url') or 'Unavailable'))}</td></tr>
  </table>
  <h3>Observed Downloads</h3>
  <ul>{download_html or '<li>No downloads observed.</li>'}</ul>
  <h3>VirusTotal File Verdicts</h3>
  <ul>{vt_file_html or '<li>No downloaded file hashes were checked.</li>'}</ul>
"""

    generated_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>PhishGuard Report #{analysis.id}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #172033; }}
    header {{ border-bottom: 3px solid #2f80ed; margin-bottom: 24px; padding-bottom: 12px; }}
    h1, h2 {{ margin-bottom: 8px; }}
    .badge {{ display: inline-block; padding: 6px 10px; border-radius: 6px; background: #172033; color: white; }}
    table {{ border-collapse: collapse; width: 100%; margin: 16px 0; }}
    th, td {{ border: 1px solid #d6dbe6; padding: 9px; text-align: left; }}
    th {{ background: #eef3fb; }}
  </style>
</head>
<body>
  <header>
    <h1>PhishGuard CTI Report</h1>
    <p>Generated {escape(generated_at)}</p>
  </header>
  <h2>Executive Summary</h2>
  <table>
    <tr><th>URL</th><td>{escape(data['normalized_url'])}</td></tr>
    <tr><th>Domain</th><td>{escape(data['domain'])}</td></tr>
    <tr><th>Severity</th><td><span class="badge">{escape(data['severity'])}</span></td></tr>
    <tr><th>Score</th><td>{escape(str(data['score']))}/100</td></tr>
  </table>
  <h2>Risk Evidence</h2>
  <ul>{reasons_html or '<li>No significant risk indicators were detected.</li>'}</ul>
  <h2>Extracted IOCs</h2>
  {ioc_html or '<p>No additional IOCs extracted.</p>'}
  <h2>Live URL Resolution</h2>
  <table>
    <tr><th>Status</th><td>{escape(str(url_resolution.get('status') or 'Unknown'))}</td></tr>
    <tr><th>Chosen URL</th><td>{escape(str(url_resolution.get('url') or data['normalized_url']))}</td></tr>
    <tr><th>Detail</th><td>{escape(str(url_resolution.get('detail') or 'No live resolution data.'))}</td></tr>
  </table>
  <ul>{resolution_html or '<li>No resolution attempts stored.</li>'}</ul>
  <h2>Domain Intelligence</h2>
  <table>
    <tr><th>Registered Domain</th><td>{escape(str(domain_intel.get('domain') or data['domain']))}</td></tr>
    <tr><th>Created</th><td>{escape(str(domain_intel.get('created_at') or 'Unknown'))}</td></tr>
    <tr><th>Age</th><td>{escape(str(domain_intel.get('age_days') or 'Unknown'))} days</td></tr>
    <tr><th>Registrar</th><td>{escape(str(domain_intel.get('registrar') or 'Unknown'))}</td></tr>
  </table>
  <h2>DNS Intelligence</h2>
  {dns_html or '<p>No DNS records available.</p>'}
  <h2>Redirect Trace</h2>
  <table>
    <tr><th>Final URL</th><td>{escape(str(redirects.get('final_url') or data['normalized_url']))}</td></tr>
    <tr><th>Redirect Count</th><td>{escape(str(redirects.get('redirect_count') or 0))}</td></tr>
    <tr><th>Cross-Domain</th><td>{'Yes' if redirects.get('cross_domain') else 'No'}</td></tr>
  </table>
  <ul>{redirect_html or '<li>No redirects observed or trace unavailable.</li>'}</ul>
  {sandbox_html}
  <h2>Threat Intelligence Enrichment</h2>
  {enrichment_html or '<p>No enrichment data available.</p>'}
  <h2>Optional API Sources</h2>
  {optional_html or '<p>No optional API sources configured.</p>'}
</body>
</html>"""
