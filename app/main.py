import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Annotated

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.analyzer import analyze_url, extract_domain, extract_scan_targets
from app.config import MAX_SCAN_TARGETS
from app.database import get_db, init_db
from app.enrichment import enrich_url
from app.models import Analysis
from app.reports import analyses_to_csv, analysis_to_dict, loads_json, render_html_report
from app.url_resolution import resolve_live_url


load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="PhishGuard", version="1.0.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Annotated[Session, Depends(get_db)]):
    total = db.scalar(select(func.count(Analysis.id))) or 0
    avg_score = round(db.scalar(select(func.avg(Analysis.score))) or 0)
    severity_rows = db.execute(select(Analysis.severity, func.count(Analysis.id)).group_by(Analysis.severity)).all()
    severity_counts = {severity: count for severity, count in severity_rows}
    recent = db.scalars(select(Analysis).order_by(Analysis.created_at.desc()).limit(8)).all()
    high_risk = db.scalars(
        select(Analysis)
        .where(Analysis.severity.in_(["High", "Critical"]))
        .order_by(Analysis.created_at.desc())
        .limit(6)
    ).all()
    all_recent = db.scalars(select(Analysis).order_by(Analysis.created_at.desc()).limit(250)).all()
    source_health = _source_health(all_recent)
    trend = _severity_trend(all_recent)
    top_domains = db.execute(
        select(Analysis.domain, func.count(Analysis.id).label("count"))
        .group_by(Analysis.domain)
        .order_by(func.count(Analysis.id).desc())
        .limit(6)
    ).all()

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "total": total,
            "avg_score": avg_score,
            "severity_counts": severity_counts,
            "recent": recent,
            "high_risk": high_risk,
            "top_domains": top_domains,
            "source_health": source_health,
            "trend": trend,
        },
    )


@app.get("/analyze", response_class=HTMLResponse)
def analyze_page(request: Request):
    return templates.TemplateResponse(request, "analyze.html", {"results": None, "input_text": ""})


@app.post("/analyze", response_class=HTMLResponse)
def analyze_submit(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    input_text: Annotated[str, Form()],
):
    entries = extract_scan_targets(input_text)

    results = []
    for entry in entries[:MAX_SCAN_TARGETS]:
        resolution = resolve_live_url(entry)
        resolved_url = resolution["url"]
        domain = extract_domain(resolved_url)
        enrichment = enrich_url(resolved_url, domain, entry, db, url_resolution=resolution)
        result = analyze_url(resolved_url, enrichment=enrichment)

        record = Analysis(
            original_input=entry,
            normalized_url=result["normalized_url"],
            domain=result["domain"],
            severity=result["severity"],
            score=result["score"],
            reasons_json=json.dumps(result["reasons"]),
            iocs_json=json.dumps(result["iocs"]),
            enrichment_json=json.dumps(enrichment),
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        results.append(record)

    return templates.TemplateResponse(
        request,
        "analyze.html",
        {"results": results, "input_text": input_text, "target_count": len(entries)},
    )


@app.get("/history", response_class=HTMLResponse)
def history(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    q: Annotated[str | None, Query()] = None,
    severity: Annotated[str | None, Query()] = None,
):
    query = select(Analysis)
    if q:
        like = f"%{q}%"
        query = query.where((Analysis.domain.like(like)) | (Analysis.normalized_url.like(like)))
    if severity:
        query = query.where(Analysis.severity == severity)
    analyses = db.scalars(query.order_by(Analysis.created_at.desc()).limit(250)).all()
    return templates.TemplateResponse(
        request,
        "history.html",
        {"analyses": analyses, "q": q or "", "severity": severity or ""},
    )


@app.get("/analysis/{analysis_id}", response_class=HTMLResponse)
def report_page(request: Request, analysis_id: int, db: Annotated[Session, Depends(get_db)]):
    analysis = db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return templates.TemplateResponse(
        request,
        "report.html",
        {
            "analysis": analysis,
            "data": analysis_to_dict(analysis),
            "reasons": loads_json(analysis.reasons_json),
            "iocs": loads_json(analysis.iocs_json),
            "enrichment": loads_json(analysis.enrichment_json),
            "recommendation": _recommendation(analysis.severity),
        },
    )


@app.get("/analysis/{analysis_id}/export/json")
def export_analysis_json(analysis_id: int, db: Annotated[Session, Depends(get_db)]):
    analysis = db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return JSONResponse(
        analysis_to_dict(analysis),
        headers={"Content-Disposition": f"attachment; filename=phishguard-analysis-{analysis_id}.json"},
    )


@app.get("/analysis/{analysis_id}/export/html", response_class=HTMLResponse)
def export_analysis_html(analysis_id: int, db: Annotated[Session, Depends(get_db)]):
    analysis = db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return HTMLResponse(
        render_html_report(analysis),
        headers={"Content-Disposition": f"attachment; filename=phishguard-report-{analysis_id}.html"},
    )


@app.get("/export/csv", response_class=PlainTextResponse)
def export_csv(db: Annotated[Session, Depends(get_db)]):
    analyses = db.scalars(select(Analysis).order_by(Analysis.created_at.desc())).all()
    return PlainTextResponse(
        analyses_to_csv(list(analyses)),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=phishguard-history.csv"},
    )


@app.get("/test-download", response_class=PlainTextResponse)
def test_download():
    content = (
        "PhishGuard safe download test file.\n"
        "This file is intentionally harmless and exists only to test download detection workflows.\n"
    )
    return PlainTextResponse(
        content,
        media_type="application/octet-stream",
        headers={"Content-Disposition": "attachment; filename=phishguard-safe-download-test.txt"},
    )


@app.get("/secure-login/account/verify/billing/update", response_class=HTMLResponse)
def demo_phishing_style_page():
    html = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow">
  <title>Secure Account Verification</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #07111f;
      --panel: rgba(11, 22, 38, 0.92);
      --line: rgba(54, 214, 255, 0.35);
      --text: #f5fbff;
      --muted: #9eb3c7;
      --cyan: #25f4ff;
      --pink: #ff4d8d;
      --green: #35f39b;
    }
    * { box-sizing: border-box; }
    body {
      min-height: 100vh;
      margin: 0;
      display: grid;
      place-items: center;
      background:
        linear-gradient(rgba(37, 244, 255, 0.08) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255, 77, 141, 0.08) 1px, transparent 1px),
        radial-gradient(circle at 20% 10%, rgba(37, 244, 255, 0.22), transparent 32%),
        radial-gradient(circle at 90% 90%, rgba(255, 77, 141, 0.22), transparent 30%),
        var(--bg);
      background-size: 46px 46px, 46px 46px, auto, auto, auto;
      color: var(--text);
      font-family: Inter, Segoe UI, Arial, sans-serif;
      letter-spacing: 0;
    }
    main {
      width: min(920px, calc(100vw - 32px));
      display: grid;
      grid-template-columns: 1.1fr 0.9fr;
      gap: 22px;
      align-items: stretch;
    }
    .card {
      border: 1px solid var(--line);
      border-radius: 10px;
      background: var(--panel);
      box-shadow: 0 24px 80px rgba(0, 0, 0, 0.45), 0 0 48px rgba(37, 244, 255, 0.12);
      padding: 28px;
      position: relative;
      overflow: hidden;
    }
    .card::before {
      content: "";
      position: absolute;
      inset: 0 0 auto;
      height: 3px;
      background: linear-gradient(90deg, var(--cyan), var(--pink), var(--green));
    }
    .eyebrow {
      color: var(--cyan);
      font-size: 12px;
      font-weight: 900;
      text-transform: uppercase;
    }
    h1 {
      margin: 16px 0 12px;
      font-size: clamp(34px, 6vw, 62px);
      line-height: 0.95;
    }
    p {
      color: var(--muted);
      font-size: 18px;
      line-height: 1.55;
    }
    .status {
      display: grid;
      gap: 12px;
      margin-top: 24px;
    }
    .status div {
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 8px;
      padding: 12px;
      background: rgba(255, 255, 255, 0.045);
    }
    .status strong {
      display: block;
      margin-bottom: 4px;
    }
    .download {
      display: inline-flex;
      margin-top: 24px;
      min-height: 46px;
      align-items: center;
      justify-content: center;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 0 18px;
      background: linear-gradient(135deg, rgba(37, 244, 255, 0.25), rgba(255, 77, 141, 0.22));
      color: white;
      font-weight: 900;
      text-decoration: none;
    }
    .side {
      display: grid;
      gap: 14px;
    }
    .badge {
      color: #07111f;
      background: var(--green);
      border-radius: 999px;
      display: inline-flex;
      font-weight: 900;
      padding: 6px 10px;
      width: fit-content;
    }
    .terminal {
      font-family: Consolas, monospace;
      color: #bdf8ff;
      white-space: pre-wrap;
      font-size: 14px;
    }
    @media (max-width: 760px) {
      main { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <main>
    <section class="card">
      <span class="eyebrow">Safe PhishGuard Demo Page</span>
      <h1>Secure account verification required</h1>
      <p>
        This page intentionally uses attacker-style wording and URL structure for sandbox,
        screenshot, redirect, keyword, and download-detection testing.
      </p>
      <div class="status">
        <div><strong>Verification status</strong><span>Pending document package download</span></div>
        <div><strong>Session type</strong><span>Training simulation only</span></div>
      </div>
      <a id="download-link" class="download" href="/secure-login/account/verify/billing/update/download">
        Download verification package
      </a>
    </section>
    <aside class="card side">
      <span class="badge">Harmless Demo</span>
      <p>No credentials are collected. No code is executed. The download is a plain text file.</p>
      <div class="terminal">Signals for CTI testing:
- login / verify / billing / update
- redirect-style query parameters
- visible screenshot target
- automatic safe file download</div>
    </aside>
  </main>
  <script>
    window.setTimeout(function () {
      document.getElementById("download-link").click();
    }, 1800);
  </script>
</body>
</html>
"""
    return HTMLResponse(html)


@app.get("/secure-login/account/verify/billing/update/download", response_class=PlainTextResponse)
def demo_phishing_style_download():
    content = (
        "PhishGuard attacker-style demo download.\n"
        "This is a harmless plain-text file for CTI and sandbox testing only.\n"
        "It does not collect credentials, execute code, or contain malware.\n"
    )
    return PlainTextResponse(
        content,
        media_type="application/octet-stream",
        headers={"Content-Disposition": "attachment; filename=security-update-verification-demo.txt"},
    )


@app.post("/sample-data")
def sample_data(db: Annotated[Session, Depends(get_db)]):
    samples = [
        "https://www.microsoft.com/security",
        "http://login-microsoft-security-update.xyz/verify/account?redirect=http://192.168.10.20",
        "http://paypal.com.account-verify-login.top/session/update",
        "https://example.org/news/CVE-2023-34362",
    ]
    for sample in samples:
        resolution = resolve_live_url(sample)
        resolved_url = resolution["url"]
        domain = extract_domain(resolved_url)
        enrichment = enrich_url(resolved_url, domain, sample, db, url_resolution=resolution)
        result = analyze_url(resolved_url, enrichment=enrichment)
        db.add(
            Analysis(
                original_input=sample,
                normalized_url=result["normalized_url"],
                domain=result["domain"],
                severity=result["severity"],
                score=result["score"],
                reasons_json=json.dumps(result["reasons"]),
                iocs_json=json.dumps(result["iocs"]),
                enrichment_json=json.dumps(enrichment),
            )
        )
    db.commit()
    return RedirectResponse("/", status_code=303)


def _source_health(analyses: list[Analysis]) -> list[dict[str, str | int]]:
    labels = {
        "domain_intel": "RDAP Domain Age",
        "dns": "DNS Intelligence",
        "redirects": "Redirect Trace",
        "urlhaus": "URLHaus",
        "phishstats": "PhishStats",
        "cisa_kev": "CISA KEV",
        "virustotal": "VirusTotal",
        "abuseipdb": "AbuseIPDB",
        "otx": "AlienVault OTX",
        "urlscan": "urlscan.io",
        "virustotal_files": "VT Downloaded Files",
    }
    status_map = {key: {"configured": 0, "hits": 0, "status": "No data"} for key in labels}

    for analysis in analyses:
        enrichment = loads_json(analysis.enrichment_json)
        flattened = dict(enrichment)
        flattened.update((enrichment.get("optional_sources") or {}) if isinstance(enrichment, dict) else {})
        for key in labels:
            source = flattened.get(key, {})
            if not isinstance(source, dict):
                continue
            status = source.get("status")
            if status and status != "not_configured":
                status_map[key]["configured"] += 1
            if status in {"malicious", "host_malicious", "matched", "host_matched", "suspicious", "downloads_found"} or source.get("matches"):
                status_map[key]["hits"] += 1
            status_map[key]["status"] = str(status or "No data").replace("_", " ").title()

    return [
        {"key": key, "label": label, **status_map[key]}
        for key, label in labels.items()
    ]


def _severity_trend(analyses: list[Analysis]) -> list[dict[str, str | int]]:
    today = datetime.now(UTC).date()
    days = [(today - timedelta(days=offset)) for offset in range(6, -1, -1)]
    rows = []
    for day in days:
        count = 0
        high = 0
        for analysis in analyses:
            created = analysis.created_at
            if not created:
                continue
            if created.tzinfo is None:
                created = created.replace(tzinfo=UTC)
            if created.date() != day:
                continue
            count += 1
            if analysis.severity in {"High", "Critical"}:
                high += 1
        rows.append({"label": day.strftime("%b %d"), "count": count, "high": high})
    max_count = max((int(row["count"]) for row in rows), default=0)
    scale = 104 / max_count if max_count else 0
    for row in rows:
        count = int(row["count"])
        high = int(row["high"])
        row["count_height"] = max(round(count * scale), 3) if count else 3
        row["high_height"] = max(round(high * scale), 3) if high else 3
    return rows


def _recommendation(severity: str) -> str:
    if severity == "Critical":
        return "Block the URL and domain immediately, escalate to incident response, and search logs for related IOCs."
    if severity == "High":
        return "Block or quarantine the URL, review related user activity, and monitor matching IOCs."
    if severity == "Medium":
        return "Treat as suspicious, validate business context, and monitor the extracted indicators."
    return "No immediate blocking action is required, but keep the record for correlation."
