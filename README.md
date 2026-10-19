# Web Security Scanner

A Python-based educational tool that performs preliminary web security configuration checks and generates JSON and HTML reports.

**Author:** Abhijeet Sanjay Khot  
**Institution:** MITWPU

## Features

- Validates HTTP and HTTPS URLs.
- Checks selected HTTP security headers: Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
- Notes HTTP-to-HTTPS redirect behavior.
- Detects wildcard `Access-Control-Allow-Origin` responses for review.
- Creates JSON and HTML scan reports.
- Includes automated tests for the modular implementation.

## Requirements

- Python 3.10+ (developed/tested in a Python 3 environment)
- `requests`
- `pytest` for tests

## Setup

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Run the modular version

From the project directory:

```powershell
python scanner.py
```

Enter a website URL when prompted. Reports are written to `sample_reports/report.json` and `sample_reports/report.html`.

## Single-file submission version

The bootcamp submission file is `AbhijeetSanjayKhot_WebSecurityScanner.py`. To run it:

```powershell
python AbhijeetSanjayKhot_WebSecurityScanner.py
```

The single-file version also needs `requests` installed and writes reports to `sample_reports/`.

## Run tests

```powershell
python -m pytest -v
```

The development modular project previously recorded 14 passing tests. Test the single-file submission independently before relying on any test claim about that version.

## Output

- `sample_reports/report.json` — structured findings.
- `sample_reports/report.html` — browser-readable report.

The repository also contains screenshots of development execution and report output.

## Dataset

No conventional training dataset is used. The scanner inspects HTTP response headers from a user-specified website that the user is authorized to test.

## Limitations

This is a preliminary configuration checker, not a full vulnerability scanner or penetration-testing tool. A missing security header or wildcard CORS setting is not automatically proof of an exploitable vulnerability; findings require manual review in context. The tool does not crawl a site or test application logic such as SQL injection, cross-site scripting, or authentication flaws.

## Responsible use

Use only against websites you own or have explicit permission to assess. Follow applicable policies and laws.

## Project structure

```text
web-security-scanner/
├── scanner.py
├── rules.py
├── report.py
├── AbhijeetSanjayKhot_WebSecurityScanner.py
├── Abhijeet_Sanjay_Khot_ProjectReport.docx
├── Abhijeet_Sanjay_Khot_Web_Security_Scanner_Report.pdf
├── tests/
├── sample_reports/
├── screenshots/
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
```
