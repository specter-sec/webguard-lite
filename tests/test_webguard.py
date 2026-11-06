import unittest

from webguard import analyze_headers, build_report, display_url, validate_url


class ValidateUrlTests(unittest.TestCase):
    def test_accepts_http_and_https(self):
        self.assertEqual(validate_url("https://example.com/path"), "https://example.com/path")
        self.assertEqual(validate_url("http://example.com"), "http://example.com")

    def test_rejects_missing_scheme_and_non_http_scheme(self):
        for value in ("example.com", "ftp://example.com", "https:///path"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_url(value)

    def test_rejects_embedded_credentials_and_control_characters(self):
        for value in ("https://user:secret@example.com", "https://example.com\nX-Test: yes"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_url(value)

    def test_rejects_malformed_port(self):
        with self.assertRaises(ValueError):
            validate_url("https://example.com:bad")


class HeaderAnalysisTests(unittest.TestCase):
    def test_detects_present_headers_case_insensitively(self):
        headers = {
            "content-security-policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=()",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000",
        }
        result = analyze_headers(headers, is_https=True)
        self.assertEqual([item["status"] for item in result], ["present"] * 6)

    def test_csp_frame_ancestors_counts_as_framing_protection(self):
        result = analyze_headers({"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"})
        framing = next(item for item in result if item["id"] == "framing-protection")
        self.assertEqual(framing["status"], "present")

    def test_hsts_is_not_applicable_over_http(self):
        result = analyze_headers({}, is_https=False)
        hsts = next(item for item in result if item["id"] == "strict-transport-security")
        self.assertEqual(hsts["status"], "not_applicable")

    def test_report_omits_query_string_and_fragment(self):
        url = "https://example.com/path?token=secret#section"
        self.assertEqual(display_url(url), "https://example.com/path")
        report = build_report(url, 200, {})
        self.assertNotIn("secret", report["target"])
        self.assertEqual(report["summary"]["missing"], 6)


if __name__ == "__main__":
    unittest.main()
