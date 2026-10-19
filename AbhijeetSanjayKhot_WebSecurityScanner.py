
"""
Project: Web Security Scanner
Student: Abhijeet Sanjay Khot
Institution: MITWPU

Description:
A Python-based tool that performs preliminary web security
configuration checks on a user-provided website and generates
JSON and HTML reports.

Use this tool only on websites you own or have permission to test.
"""

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests


# ============================================================
# SECTION 1: SECURITY RULES
# ============================================================

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "Medium",
        "description": "HTTP Strict Transport Security header is missing.",
        "recommendation": (
            "For HTTPS websites, configure Strict-Transport-Security "
            "after confirming the domain and subdomain requirements."
        ),
    },
    "Content-Security-Policy": {
        "severity": "Medium",
        "description": "Content Security Policy header is missing.",
        "recommendation": (
            "Define a Content-Security-Policy suitable for the website. "
            "Test the policy before enforcing it."
        ),
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "description": "X-Content-Type-Options header is missing.",
        "recommendation": "Set X-Content-Type-Options to nosniff.",
    },
    "Referrer-Policy": {
        "severity": "Low",
        "description": "Referrer-Policy header is missing.",
        "recommendation": (
            "Configure an appropriate Referrer-Policy, such as "
            "strict-origin-when-cross-origin."
        ),
    },
    "Permissions-Policy": {
        "severity": "Informational",
        "description": "Permissions-Policy header is missing.",
        "recommendation": (
            "Consider restricting browser features that the website "
            "does not need."
        ),
    },
}

SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Informational": 4,
}


# ============================================================
# SECTION 2: URL VALIDATION
# ============================================================

def validate_url(url):
    """Validate that the supplied URL uses HTTP or HTTPS."""

    if not isinstance(url, str) or not url.strip():
        raise ValueError("Please enter a valid website URL.")

    url = url.strip()
    parsed = urlparse(url)

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("URL must begin with http:// or https://.")

    if not parsed.hostname:
        raise ValueError("The URL must contain a valid hostname.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not allowed.")

    return url


# ============================================================
# SECTION 3: FINDING HELPER
# ============================================================

def add_finding(findings, finding_id, title, severity,
                evidence, recommendation):
    """Add a finding to the scan results."""

    findings.append({
        "id": finding_id,
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "recommendation": recommendation,
    })


# ============================================================
# SECTION 4: WEBSITE SCANNER
# ============================================================

def scan_website(url):
    """
    Request a website and check selected HTTP security settings.

    This is a preliminary configuration scanner, not a full
    penetration-testing tool.
    """

    url = validate_url(url)
    findings = []

    headers = {
        "User-Agent": "WebShield-SecurityScanner/1.0"
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=10,
            allow_redirects=True,
            verify=True,
        )
    except requests.RequestException as exc:
        raise RuntimeError(
            f"Unable to scan the website: {exc}"
        ) from exc

    final_url = response.url
    final_parsed = urlparse(final_url)
    final_headers = response.headers

    https_used = final_parsed.scheme.lower() == "https"

    # Check whether the original URL used HTTP.
    original_scheme = urlparse(url).scheme.lower()

    if original_scheme == "http":
        if https_used:
            add_finding(
                findings,
                "WEB-001",
                "HTTP URL redirects to HTTPS",
                "Informational",
                "The requested HTTP URL ended at an HTTPS URL.",
                (
                    "Confirm that HTTP requests are consistently "
                    "redirected to HTTPS and that sensitive content "
                    "is never served over HTTP."
                ),
            )
        else:
            add_finding(
                findings,
                "WEB-001",
                "Website does not end on HTTPS",
                "High",
                f"Final URL uses the {final_parsed.scheme} scheme.",
                (
                    "Configure HTTPS with a valid certificate and "
                    "redirect HTTP requests to HTTPS."
                ),
            )

    # Check the final URL and final response headers.
    for header_name, rule in SECURITY_HEADERS.items():
        header_value = final_headers.get(header_name)

        # HSTS is relevant to HTTPS responses.
        if header_name == "Strict-Transport-Security" and not https_used:
            continue

        if not header_value:
            add_finding(
                findings,
                f"HEADER-{header_name.upper().replace('-', '_')}",
                f"Missing {header_name} header",
                rule["severity"],
                f"The response does not contain {header_name}.",
                rule["recommendation"],
            )

        elif (
            header_name == "X-Content-Type-Options"
            and header_value.strip().lower() != "nosniff"
        ):
            add_finding(
                findings,
                "HEADER-X_CONTENT_TYPE_OPTIONS",
                "Unexpected X-Content-Type-Options value",
                "Low",
                f"Observed value: {header_value}",
                "Set X-Content-Type-Options to nosniff.",
            )

    # Check for wildcard CORS configuration.
    cors_origin = final_headers.get("Access-Control-Allow-Origin", "")
    cors_credentials = final_headers.get(
        "Access-Control-Allow-Credentials", ""
    )

    if cors_origin.strip() == "*":
        if cors_credentials.strip().lower() == "true":
            cors_severity = "Medium"
            cors_recommendation = (
                "Review the CORS configuration and restrict allowed "
                "origins where appropriate. Validate the actual "
                "browser behavior and application requirements."
            )
        else:
            cors_severity = "Informational"
            cors_recommendation = (
                "Confirm that wildcard CORS is intentional. It can be "
                "appropriate for public, non-sensitive resources."
            )

        add_finding(
            findings,
            "CORS-001",
            "Wildcard CORS origin detected",
            cors_severity,
            (
                "Access-Control-Allow-Origin is set to '*'. "
                f"Access-Control-Allow-Credentials: "
                f"{cors_credentials or 'not present'}."
            ),
            cors_recommendation,
        )

    return {
        "target": url,
        "final_url": final_url,
        "http_status": response.status_code,
        "https_used": https_used,
        "findings_count": len(findings),
        "findings": findings,
    }


# ============================================================
# SECTION 5: JSON AND HTML REPORT GENERATOR
# ============================================================

def generate_report(scan_result, output_dir="sample_reports"):
    """Generate JSON and HTML reports for the scan."""

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
    result["findings_count"] = len(findings)

    json_path = output_path / "report.json"
    html_path = output_path / "report.html"

    with json_path.open("w", encoding="utf-8") as file:
        json.dump(result, file, indent=2, ensure_ascii=False)

    severity_counts = {}
    for finding in findings:
        severity = finding.get("severity", "Informational")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    severity_summary = "".join(
        f"<li><strong>{html.escape(level)}:</strong> {count}</li>"
        for level, count in sorted(
            severity_counts.items(),
            key=lambda item: SEVERITY_ORDER.get(item[0], 99),
        )
    )

    finding_cards = []

    for finding in findings:
        severity = html.escape(
            str(finding.get("severity", "Informational"))
        )
        title = html.escape(
            str(finding.get("title", "Untitled finding"))
        )
        evidence = html.escape(
            str(finding.get("evidence", "No evidence provided"))
        )
        recommendation = html.escape(
            str(finding.get("recommendation", "Review manually."))
        )
        finding_id = html.escape(str(finding.get("id", "N/A")))

        finding_cards.append(
            f"""
            <article class="finding">
                <p class="severity">{severity}</p>
                <h3>{title}</h3>
                <p><strong>ID:</strong> {finding_id}</p>
                <p><strong>Evidence:</strong> {evidence}</p>
                <p><strong>Recommendation:</strong> {recommendation}</p>
            </article>
            """
        )

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
This report contains automated preliminary checks, not proof of
exploitability. Review findings manually and validate them in context.
</footer>
</body>
</html>
"""

    with html_path.open("w", encoding="utf-8") as file:
        file.write(document)

    return {"json": json_path, "html": html_path}


# ============================================================
# SECTION 6: DISPLAY RESULTS
# ============================================================

def display_results(scan_result):
    """Print scan information and findings to the terminal."""

    print("\n" + "=" * 60)
    print("WEB SECURITY SCANNER - RESULTS")
    print("=" * 60)
    print(f"Target URL     : {scan_result['target']}")
    print(f"Final URL      : {scan_result['final_url']}")
    print(f"HTTP status    : {scan_result['http_status']}")
    print(f"HTTPS used     : {scan_result['https_used']}")
    print(f"Total findings : {scan_result['findings_count']}")

    if not scan_result["findings"]:
        print("\nNo findings from the configured checks.")
    else:
        print("\nFindings:")
        for number, finding in enumerate(
            scan_result["findings"], start=1
        ):
            print(f"\n{number}. {finding['title']}")
            print(f"   ID             : {finding['id']}")
            print(f"   Severity       : {finding['severity']}")
            print(f"   Evidence       : {finding['evidence']}")
            print(
                f"   Recommendation : {finding['recommendation']}"
            )

    print("\nNote: These are preliminary configuration findings.")
    print("They do not automatically prove an exploitable vulnerability.")


# ============================================================
# SECTION 7: MAIN PROGRAM
# ============================================================

def main():
    """Run the scanner and create reports."""

    print("Web Security Scanner")
    print("-" * 40)
    print("Scan only websites you own or are authorized to test.")

    url = input("Enter the website URL (including https://): ").strip()

    try:
        scan_result = scan_website(url)
        display_results(scan_result)

        report_paths = generate_report(scan_result)

        print("\nReports generated successfully:")
        print(f"JSON report: {report_paths['json']}")
        print(f"HTML report: {report_paths['html']}")

    except (ValueError, RuntimeError) as exc:
        print(f"\nScan could not be completed: {exc}")


if __name__ == "__main__":
    main()
