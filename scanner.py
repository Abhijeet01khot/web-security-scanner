
"""Main engine for the Web Security Scanner."""

from urllib.parse import urlparse

import requests

from rules import SECURITY_HEADERS
from report import generate_report


def validate_url(url):
    """Accept only valid HTTP or HTTPS URLs with a hostname."""
    try:
        parsed = urlparse(url)

        return (
            parsed.scheme in ("http", "https")
            and bool(parsed.hostname)
            and not parsed.username
            and not parsed.password
        )
    except (ValueError, TypeError):
        return False


def scan_website(url):
    """Check HTTPS usage, security headers, and basic CORS behavior."""
    if not validate_url(url):
        raise ValueError(
            "Invalid URL. Enter a complete HTTP or HTTPS URL."
        )

    findings = []
    parsed_url = urlparse(url)

    # Check whether the submitted URL uses HTTPS.
    if parsed_url.scheme != "https":
        findings.append({
            "id": "HTTPS-001",
            "severity": "High",
            "title": "HTTPS is not being used",
            "evidence": (
                f"Submitted URL uses {parsed_url.scheme.upper()}."
            ),
            "recommendation": (
                "Use HTTPS with a valid TLS certificate."
            ),
        })

    # Request the website and follow redirects.
    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            verify=True,
            headers={
                "User-Agent": "WebShield-SecurityScanner/1.0"
            },
        )
    except requests.RequestException as exc:
        raise RuntimeError(
            f"Could not retrieve the website: {exc}"
        ) from exc

    headers = response.headers

    # Inspect the final destination after redirects.
    final_url = response.url
    final_scheme = urlparse(final_url).scheme.lower()

    if parsed_url.scheme == "https" and final_scheme != "https":
        findings.append({
            "id": "HTTPS-002",
            "severity": "High",
            "title": "HTTPS request ended on a non-HTTPS URL",
            "evidence": f"Final URL: {final_url}",
            "recommendation": (
                "Ensure redirects remain on HTTPS."
            ),
        })

    # Check configured security headers.
    for header, rule in SECURITY_HEADERS.items():
        value = headers.get(header)

        if not value:
            findings.append({
                "id": f"HEADER-{header.upper().replace('-', '_')}",
                "severity": rule["severity"],
                "title": f"Missing security header: {header}",
                "evidence": (
                    f"{header} was not present in the response."
                ),
                "recommendation": rule["recommendation"],
            })

        elif header == "X-Content-Type-Options":
            if value.strip().lower() != "nosniff":
                findings.append({
                    "id": "HEADER-X_CONTENT_TYPE_OPTIONS",
                    "severity": "Low",
                    "title": (
                        "Unexpected X-Content-Type-Options value"
                    ),
                    "evidence": f"Received value: {value}",
                    "recommendation": "Set the header to: nosniff",
                })

    # Basic CORS screening.
    # This check does not prove that a vulnerability exists.
    allow_origin = headers.get(
        "Access-Control-Allow-Origin"
    )

    allow_credentials = headers.get(
        "Access-Control-Allow-Credentials", ""
    ).strip().lower()

    if allow_origin == "*":
        severity = (
            "Informational"
            if allow_credentials != "true"
            else "Medium"
        )

        findings.append({
            "id": "CORS-001",
            "severity": severity,
            "title": "Wildcard CORS origin detected",
            "evidence": (
                "Access-Control-Allow-Origin: *; "
                "Access-Control-Allow-Credentials: "
                f"{allow_credentials or '(not set)'}"
            ),
            "recommendation": (
                "Verify that public cross-origin access is intentional. "
                "Use an explicit origin allowlist for sensitive resources."
            ),
        })

    # Return structured results for the console and report generator.
    return {
        "target": url,
        "final_url": final_url,
        "http_status": response.status_code,
        "https_used": final_scheme == "https",
        "findings_count": len(findings),
        "findings": findings,
    }


def main():
    """Run a scan and generate JSON and HTML reports."""
    url = input(
        "Enter a website URL you are authorized to test: "
    ).strip()

    try:
        result = scan_website(url)

    except (ValueError, RuntimeError) as exc:
        print(f"\nScan failed: {exc}")
        return

    print("\n===== WEB SECURITY SCANNER =====")
    print(f"Target: {result['target']}")
    print(f"Final URL: {result['final_url']}")
    print(f"HTTP status: {result['http_status']}")
    print(f"HTTPS used: {result['https_used']}")
    print(f"Findings: {result['findings_count']}")

    if not result["findings"]:
        print("\nNo configured checks produced findings.")

    for finding in result["findings"]:
        print(
            f"\n[{finding['severity']}] "
            f"{finding['title']}"
        )
        print(f"Evidence: {finding['evidence']}")
        print(
            f"Recommendation: {finding['recommendation']}"
        )

    # Generate the JSON and HTML reports.
    try:
        paths = generate_report(result)

        print("\n===== REPORTS GENERATED =====")
        print(f"JSON report: {paths['json']}")
        print(f"HTML report: {paths['html']}")

    except (OSError, TypeError, ValueError) as exc:
        print(f"\nCould not generate reports: {exc}")


if __name__ == "__main__":
    main()
