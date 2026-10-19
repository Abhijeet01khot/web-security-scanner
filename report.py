
"""Generate JSON and HTML reports for Web Security Scanner."""

import html
import json
from datetime import datetime, timezone
from pathlib import Path


SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Informational": 4,
}


def generate_report(scan_result, output_dir="sample_reports"):
    """Save scan results as JSON and HTML files."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    result = dict(scan_result)
    result["scan_time_utc"] = datetime.now(timezone.utc).isoformat()

    findings = sorted(
        result.get("findings", []),
        key=lambda item: SEVERITY_ORDER.get(
            item.get("severity", "Informational"), 99
        ),
    )
    result["findings"] = findings

    json_path = output_path / "report.json"
    html_path = output_path / "report.html"

    with json_path.open("w", encoding="utf-8") as file:
        json.dump(result, file, indent=2, ensure_ascii=False)

    counts = {}
    for finding in findings:
        severity = finding.get("severity", "Informational")
        counts[severity] = counts.get(severity, 0) + 1

    severity_summary = "".join(
        f"<li><strong>{html.escape(level)}:</strong> {count}</li>"
        for level, count in sorted(
            counts.items(),
            key=lambda item: SEVERITY_ORDER.get(item[0], 99),
        )
    )

    finding_cards = []
    for finding in findings:
        severity = html.escape(
            str(finding.get("severity", "Informational"))
        )
        title = html.escape(str(finding.get("title", "Untitled finding")))
        evidence = html.escape(str(finding.get("evidence", "No evidence provided")))
        recommendation = html.escape(
            str(finding.get("recommendation", "Review this finding manually."))
        )
        finding_id = html.escape(str(finding.get("id", "N/A")))

        finding_cards.append(f"""
        <article class="finding">
          <p class="severity">{severity}</p>
          <h3>{title}</h3>
          <p><strong>ID:</strong> {finding_id}</p>
          <p><strong>Evidence:</strong> {evidence}</p>
          <p><strong>Recommendation:</strong> {recommendation}</p>
        </article>
        """)

    target = html.escape(str(result.get("target", "Unknown")))
    final_url = html.escape(str(result.get("final_url", "Unknown")))
    status = html.escape(str(result.get("http_status", "Unknown")))
    https = "Yes" if result.get("https_used") else "No"
    scan_time = html.escape(result["scan_time_utc"])

    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Web Security Scanner Report</title>
  <style>
    body {{
      font-family: Arial, sans-serif;
      max-width: 900px;
      margin: 40px auto;
      padding: 0 20px;
      line-height: 1.6;
      color: #202938;
      background: #f4f7fb;
    }}
    header, .summary, .finding {{
      background: white;
      padding: 22px;
      margin-bottom: 18px;
      border-radius: 10px;
      border: 1px solid #dbe3ee;
    }}
    h1 {{ margin-top: 0; }}
    .severity {{ font-weight: bold; }}
    .finding h3 {{ margin-bottom: 8px; }}
    code {{ overflow-wrap: anywhere; }}
    footer {{ color: #596579; font-size: 0.9rem; }}
  </style>
</head>
<body>
  <header>
    <h1>Web Security Scanner</h1>
    <p>Automated preliminary web security assessment</p>
    <p><strong>Target:</strong> <code>{target}</code></p>
    <p><strong>Final URL:</strong> <code>{final_url}</code></p>
    <p><strong>HTTP status:</strong> {status}</p>
    <p><strong>HTTPS used:</strong> {https}</p>
    <p><strong>Scan time (UTC):</strong> {scan_time}</p>
    <p><strong>Total findings:</strong> {len(findings)}</p>
  </header>
  <section class="summary">
    <h2>Severity summary</h2>
    <ul>{severity_summary or "<li>No findings.</li>"}</ul>
  </section>
  <main>
    <h2>Findings and recommendations</h2>
    {"".join(finding_cards) or "<p>No findings from configured checks.</p>"}
  </main>
  <footer>
    This report contains automated preliminary checks, not proof of exploitability.
    Review findings manually and validate them in the context of the application.
  </footer>
</body>
</html>
"""

    with html_path.open("w", encoding="utf-8") as file:
        file.write(document)

    return {"json": json_path, "html": html_path}
