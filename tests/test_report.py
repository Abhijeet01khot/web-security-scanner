
import json

from report import generate_report


def sample_result():
    return {
        "target": "https://example.com/",
        "final_url": "https://example.com/",
        "http_status": 200,
        "https_used": True,
        "findings_count": 1,
        "findings": [
            {
                "id": "HEADER-CSP",
                "severity": "Medium",
                "title": "Missing Content-Security-Policy",
                "evidence": "Header was not present.",
                "recommendation": "Configure a suitable CSP.",
            }
        ],
    }


def test_report_generates_json_and_html(tmp_path):
    result = sample_result()

    paths = generate_report(result, output_dir=tmp_path)

    assert paths["json"].exists()
    assert paths["html"].exists()


def test_json_report_contains_scan_results(tmp_path):
    result = sample_result()

    paths = generate_report(result, output_dir=tmp_path)

    with paths["json"].open(encoding="utf-8") as file:
        saved = json.load(file)

    assert saved["target"] == "https://example.com/"
    assert saved["http_status"] == 200
    assert saved["findings_count"] == 1
    assert saved["findings"][0]["severity"] == "Medium"
    assert "scan_time_utc" in saved


def test_html_report_contains_finding_and_recommendation(tmp_path):
    result = sample_result()

    paths = generate_report(result, output_dir=tmp_path)
    content = paths["html"].read_text(encoding="utf-8")

    assert "Web Security Scanner" in content
    assert "Missing Content-Security-Policy" in content
    assert "Configure a suitable CSP." in content
    assert "Severity summary" in content


def test_html_report_escapes_untrusted_text(tmp_path):
    result = sample_result()
    result["target"] = "https://example.com/?q=<script>alert(1)</script>"
    result["findings"][0]["title"] = "<script>alert(1)</script>"

    paths = generate_report(result, output_dir=tmp_path)
    content = paths["html"].read_text(encoding="utf-8")

    assert "<script>alert(1)</script>" not in content
    assert "&lt;script&gt;" in content


def test_report_handles_no_findings(tmp_path):
    result = sample_result()
    result["findings"] = []
    result["findings_count"] = 0

    paths = generate_report(result, output_dir=tmp_path)
    content = paths["html"].read_text(encoding="utf-8")

    with paths["json"].open(encoding="utf-8") as file:
        saved = json.load(file)

    assert saved["findings"] == []
    assert "No findings." in content
