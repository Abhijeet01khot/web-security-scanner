
import pytest

from scanner import scan_website, validate_url


def test_validate_url_accepts_https():
    assert validate_url("https://example.com")


def test_validate_url_accepts_http():
    assert validate_url("http://example.com")


@pytest.mark.parametrize(
    "url",
    [
        "example.com",
        "ftp://example.com",
        "",
        "https://",
    ],
)
def test_validate_url_rejects_invalid_urls(url):
    assert not validate_url(url)


def test_scan_detects_missing_security_headers(monkeypatch):
    class FakeResponse:
        url = "https://example.com/"
        status_code = 200
        headers = {}

    def fake_get(*args, **kwargs):
        return FakeResponse()

    monkeypatch.setattr("scanner.requests.get", fake_get)

    result = scan_website("https://example.com/")

    titles = [finding["title"] for finding in result["findings"]]

    assert result["http_status"] == 200
    assert result["https_used"] is True
    assert any(
        title == "Missing security header: Content-Security-Policy"
        for title in titles
    )
    assert any(
        title == "Missing security header: X-Content-Type-Options"
        for title in titles
    )


def test_scan_detects_wildcard_cors(monkeypatch):
    class FakeResponse:
        url = "https://example.com/"
        status_code = 200
        headers = {
            "Access-Control-Allow-Origin": "*",
        }

    def fake_get(*args, **kwargs):
        return FakeResponse()

    monkeypatch.setattr("scanner.requests.get", fake_get)

    result = scan_website("https://example.com/")

    cors_findings = [
        finding for finding in result["findings"]
        if finding["id"] == "CORS-001"
    ]

    assert len(cors_findings) == 1
    assert cors_findings[0]["severity"] == "Informational"


def test_scan_rejects_invalid_url():
    with pytest.raises(ValueError):
        scan_website("not-a-valid-url")
