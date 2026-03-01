"""
Browser Agent
Headless Chrome automation for web security testing.
Inspired by hexstrike-ai browser agent and pentagi web intelligence.
"""

import html.parser
import json
import re
import urllib.error
import urllib.request
from typing import Any, Optional
from urllib.parse import urljoin, urlparse


# ── Lightweight HTML helpers ─────────────────────────────────────────────────


class _TagParser(html.parser.HTMLParser):
    """Minimal HTML parser that collects tags and attributes."""

    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, Optional[str]]]] = []
        self._current_data: list[str] = []
        self._current_tag: Optional[str] = None
        self._current_attrs: dict[str, Optional[str]] = {}
        self.title: str = ""
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        attr_dict = dict(attrs)
        self.tags.append((tag, attr_dict))
        if tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data


def _fetch_url(url: str, timeout: int = 15) -> tuple[bytes, dict[str, str]]:
    """Fetch a URL using only the standard library.  Returns (body, headers)."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "CyberSentry-BrowserAgent/1.0"},
    )
    resp = urllib.request.urlopen(req, timeout=timeout)  # noqa: S310
    headers = {k.lower(): v for k, v in resp.headers.items()}
    body = resp.read()
    return body, headers


# ── Technology signatures ────────────────────────────────────────────────────

_TECH_SIGNATURES: dict[str, list[str]] = {
    "jQuery": ["jquery", "jquery.min.js"],
    "React": ["react.production.min.js", "react-dom", "__NEXT_DATA__"],
    "Angular": ["ng-version", "angular.min.js", "ng-app"],
    "Vue.js": ["vue.min.js", "vue.js", "__vue__"],
    "Bootstrap": ["bootstrap.min.css", "bootstrap.min.js"],
    "WordPress": ["wp-content", "wp-includes"],
    "Drupal": ["drupal.js", "Drupal.settings"],
    "Joomla": ["/media/jui/", "Joomla!"],
    "nginx": ["nginx"],
    "Apache": ["apache", "httpd"],
    "PHP": [".php", "PHPSESSID"],
    "ASP.NET": ["__VIEWSTATE", "asp.net", "X-AspNet-Version"],
    "Google Analytics": ["google-analytics.com", "gtag"],
    "Cloudflare": ["cloudflare", "cf-ray"],
}

# ── Security-header definitions ──────────────────────────────────────────────

_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
]


class BrowserAgent:
    """
    Web-page analysis agent.

    Works entirely with :mod:`urllib.request` from the standard library so
    that no external dependencies are required.  When *selenium* is available
    additional capabilities (screenshots, full JS rendering) are unlocked.
    """

    def __init__(self) -> None:
        self._selenium_available: Optional[bool] = None

    # ── Availability ─────────────────────────────────────────────────────────

    def check_available(self) -> bool:
        """Return ``True`` if selenium + a Chrome driver can be imported."""
        if self._selenium_available is None:
            try:
                from selenium import webdriver  # noqa: F401
                from selenium.webdriver.chrome.options import Options  # noqa: F401

                self._selenium_available = True
            except Exception:
                self._selenium_available = False
        return self._selenium_available

    # ── Screenshot (selenium only) ───────────────────────────────────────────

    def capture_screenshot(self, url: str, output_path: str) -> str:
        """
        Capture a screenshot of *url* and save it to *output_path*.

        Requires selenium + Chrome.  Returns the output path on success.
        """
        if not self.check_available():
            return f"[error] selenium/chrome not available – cannot capture screenshot of {url}"

        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options

        opts = Options()
        opts.add_argument("--headless")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        driver = webdriver.Chrome(options=opts)
        try:
            driver.get(url)
            driver.save_screenshot(output_path)
            return output_path
        finally:
            driver.quit()

    # ── Page source ──────────────────────────────────────────────────────────

    def get_page_source(self, url: str) -> str:
        """Return the raw HTML source of *url*."""
        body, _ = _fetch_url(url)
        return body.decode("utf-8", errors="replace")

    # ── Security headers ─────────────────────────────────────────────────────

    def analyze_security_headers(self, url: str) -> dict[str, Any]:
        """
        Check which recommended security headers are present at *url*.

        Returns a dict with ``present``, ``missing``, and ``grade`` keys.
        """
        _, headers = _fetch_url(url)

        present: dict[str, str] = {}
        missing: list[str] = []
        for hdr in _SECURITY_HEADERS:
            value = headers.get(hdr)
            if value:
                present[hdr] = value
            else:
                missing.append(hdr)

        total = len(_SECURITY_HEADERS)
        found = len(present)
        ratio = found / total if total else 0
        if ratio >= 0.8:
            grade = "A"
        elif ratio >= 0.6:
            grade = "B"
        elif ratio >= 0.4:
            grade = "C"
        elif ratio >= 0.2:
            grade = "D"
        else:
            grade = "F"

        return {
            "url": url,
            "present": present,
            "missing": missing,
            "grade": grade,
            "score": f"{found}/{total}",
        }

    # ── Technology detection ─────────────────────────────────────────────────

    def detect_technologies(self, url: str) -> dict[str, bool]:
        """
        Detect well-known technologies by inspecting page source and headers.
        """
        body, headers = _fetch_url(url)
        source = body.decode("utf-8", errors="replace").lower()
        header_str = json.dumps(headers).lower()
        combined = source + header_str

        detected: dict[str, bool] = {}
        for tech, signatures in _TECH_SIGNATURES.items():
            detected[tech] = any(sig.lower() in combined for sig in signatures)
        return {k: v for k, v in detected.items() if v}

    # ── Form discovery ───────────────────────────────────────────────────────

    def find_forms(self, url: str) -> list[dict[str, Any]]:
        """
        Discover ``<form>`` elements and their ``<input>`` fields.
        """
        source = self.get_page_source(url)
        parser = _TagParser()
        parser.feed(source)

        forms: list[dict[str, Any]] = []
        current_form: Optional[dict[str, Any]] = None

        for tag, attrs in parser.tags:
            if tag == "form":
                if current_form is not None:
                    forms.append(current_form)
                current_form = {
                    "action": attrs.get("action", ""),
                    "method": (attrs.get("method") or "get").upper(),
                    "inputs": [],
                }
            elif tag == "input" and current_form is not None:
                current_form["inputs"].append(
                    {
                        "name": attrs.get("name", ""),
                        "type": attrs.get("type", "text"),
                        "value": attrs.get("value", ""),
                    }
                )
            elif tag == "textarea" and current_form is not None:
                current_form["inputs"].append(
                    {"name": attrs.get("name", ""), "type": "textarea", "value": ""}
                )
            elif tag == "select" and current_form is not None:
                current_form["inputs"].append(
                    {"name": attrs.get("name", ""), "type": "select", "value": ""}
                )

        if current_form is not None:
            forms.append(current_form)
        return forms

    # ── CORS check ───────────────────────────────────────────────────────────

    def check_cors(self, url: str) -> dict[str, Any]:
        """
        Test the CORS configuration of *url* by sending an ``Origin`` header.
        """
        parsed = urlparse(url)
        test_origin = f"{parsed.scheme}://evil.example.com"

        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "CyberSentry-BrowserAgent/1.0",
                "Origin": test_origin,
            },
        )
        try:
            resp = urllib.request.urlopen(req, timeout=15)  # noqa: S310
            headers = {k.lower(): v for k, v in resp.headers.items()}
        except urllib.error.URLError:
            return {"url": url, "error": "could not reach URL"}

        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")

        wildcard = acao == "*"
        reflects = acao == test_origin
        credentials = acac.lower() == "true"

        misconfigured = reflects or (wildcard and credentials)

        return {
            "url": url,
            "access_control_allow_origin": acao,
            "access_control_allow_credentials": credentials,
            "wildcard": wildcard,
            "reflects_origin": reflects,
            "misconfigured": misconfigured,
        }

    # ── Page info ────────────────────────────────────────────────────────────

    def get_page_info(self, url: str) -> dict[str, Any]:
        """
        Collect general metadata: title, meta tags, links, scripts.
        """
        body, headers = _fetch_url(url)
        source = body.decode("utf-8", errors="replace")
        parser = _TagParser()
        parser.feed(source)

        meta: list[dict[str, Optional[str]]] = []
        links: list[str] = []
        scripts: list[str] = []

        for tag, attrs in parser.tags:
            if tag == "meta":
                meta.append(attrs)
            elif tag == "a":
                href = attrs.get("href")
                if href:
                    links.append(urljoin(url, href))
            elif tag == "script":
                src = attrs.get("src")
                if src:
                    scripts.append(urljoin(url, src))

        return {
            "url": url,
            "title": parser.title.strip(),
            "meta": meta,
            "links": links,
            "scripts": scripts,
            "content_type": headers.get("content-type", ""),
            "server": headers.get("server", ""),
        }


# Module-level default instance
browser_agent = BrowserAgent()
