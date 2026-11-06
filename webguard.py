#!/usr/bin/env python3
"""WebGuard Lite: a passive HTTP security-header checker."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

USER_AGENT = "WebGuardLite/1.0 (passive security-header check)"


class NoRedirectHandler(HTTPRedirectHandler):
    """Keep a single request inside the exact URL scope supplied by the user."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_url(value: str) -> str:
    """Validate and return an HTTP(S) URL without embedded credentials."""
    value = value.strip()
    if not value or any(char in value for char in "\r\n\t"):
        raise ValueError("Enter a valid HTTP or HTTPS URL.")

    try:
        parsed = urlsplit(value)
        # Accessing .port validates malformed port values.
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("The URL or port is malformed.") from exc

    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("The URL must include an http:// or https:// scheme and a host.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Do not include a username or password in the URL.")
    return value


def display_url(value: str) -> str:
    """Avoid copying query strings or fragments (which may contain secrets) to reports."""
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))


def _has_header(headers: Mapping[str, str], name: str) -> bool:
    return any(key.lower() == name.lower() and bool(str(value).strip()) for key, value in headers.items())


def _has_frame_ancestors(headers: Mapping[str, str]) -> bool:
    for key, value in headers.items():
        if key.lower() == "content-security-policy":
            if re.search(r"(?:^|;)\s*frame-ancestors\s+[^;]+", str(value), re.IGNORECASE):
                return True
    return False


def analyze_headers(headers: Mapping[str, str], is_https: bool = True) -> list[dict[str, str]]:
    """Return simple presence checks; this is not a full policy-quality audit."""
    checks = [
        ("content-security-policy", "Content-Security-Policy", "Helps restrict sources a page can load."),
        ("x-content-type-options", "X-Content-Type-Options", "Helps prevent MIME-type sniffing when set to nosniff."),
        ("referrer-policy", "Referrer-Policy", "Controls how much referrer information browsers send."),
        ("permissions-policy", "Permissions-Policy", "Controls access to selected browser features."),
    ]
    results: list[dict[str, str]] = []
    for header, title, detail in checks:
        present = _has_header(headers, header)
        results.append({
            "id": header,
            "title": title,
            "status": "present" if present else "missing",
            "detail": detail if present else f"{detail} Header was not observed.",
        })

    framing_present = _has_header(headers, "x-frame-options") or _has_frame_ancestors(headers)
    results.append({
        "id": "framing-protection",
        "title": "Framing protection",
        "status": "present" if framing_present else "missing",
        "detail": (
            "X-Frame-Options or a Content-Security-Policy frame-ancestors directive was observed."
            if framing_present
            else "Neither X-Frame-Options nor a Content-Security-Policy frame-ancestors directive was observed."
        ),
    })

    if is_https:
        hsts_present = _has_header(headers, "strict-transport-security")
        results.append({
            "id": "strict-transport-security",
            "title": "Strict-Transport-Security",
            "status": "present" if hsts_present else "missing",
            "detail": (
                "The HTTPS response included Strict-Transport-Security."
                if hsts_present
                else "The HTTPS response did not include Strict-Transport-Security."
            ),
        })
    else:
        results.append({
            "id": "strict-transport-security",
            "title": "Strict-Transport-Security",
            "status": "not_applicable",
            "detail": "Not evaluated for an HTTP URL; HSTS is a browser policy delivered over HTTPS.",
        })
    return results


def fetch_headers(url: str, timeout: float = 8.0) -> tuple[int, Mapping[str, str]]:
    """Make exactly one GET request; redirects are not followed and the body is not read."""
    request = Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
    opener = build_opener(NoRedirectHandler())
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.headers
    except HTTPError as exc:
        # HTTP error responses still contain useful headers and status information.
        return exc.code, exc.headers
    except (URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise RuntimeError(f"Could not retrieve response headers: {reason}") from exc


def build_report(url: str, status_code: int, headers: Mapping[str, str]) -> dict:
    parsed = urlsplit(url)
    checks = analyze_headers(headers, is_https=parsed.scheme.lower() == "https")
    counts = {key: sum(check["status"] == key for check in checks) for key in ("present", "missing", "not_applicable")}
    return {
        "tool": "WebGuard Lite",
        "target": display_url(url),
        "http_status": status_code,
        "summary": counts,
        "checks": checks,
        "note": "Header presence is not a complete security assessment; review each policy for your application.",
    }


def print_report(report: dict) -> None:
    print("WebGuard Lite — passive response-header check")
    print(f"Target: {report['target']}")
    print(f"HTTP status: {report['http_status']}")
    for check in report["checks"]:
        label = {"present": "PASS", "missing": "REVIEW", "not_applicable": "SKIP"}[check["status"]]
        print(f"[{label}] {check['title']}: {check['detail']}")
    summary = report["summary"]
    print(f"Summary: {summary['present']} present, {summary['missing']} to review, {summary['not_applicable']} not applicable.")
    print(report["note"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check common HTTP security-header presence for one authorized URL."
    )
    parser.add_argument("url", help="One HTTP(S) URL you own or are authorized to assess")
    parser.add_argument("--timeout", type=float, default=8.0, help="Request timeout in seconds (0.5–30; default: 8)")
    parser.add_argument("--json", dest="json_path", metavar="FILE", help="Also save the report as JSON")
    args = parser.parse_args(argv)

    if not 0.5 <= args.timeout <= 30:
        parser.error("--timeout must be between 0.5 and 30 seconds")
    try:
        url = validate_url(args.url)
        status_code, headers = fetch_headers(url, timeout=args.timeout)
        report = build_report(url, status_code, headers)
    except (ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    print_report(report)
    if args.json_path:
        try:
            Path(args.json_path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"Error: could not write JSON report: {exc}", file=sys.stderr)
            return 2
        print(f"JSON report saved to {args.json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
