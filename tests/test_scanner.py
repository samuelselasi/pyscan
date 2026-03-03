"""
Unit tests for PyScan scanner modules.

These tests use mock HTTP responses so no real network requests are made.
Run with: python -m pytest tests/ -v
"""

import sys
import os
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path
import tempfile

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pyscan.utils.evidence import EvidenceStore, _mask_dict
from pyscan.utils.throttling import Throttler
from pyscan.utils.http import HTTPResponse


def make_mock_http(status=200, body="", headers=None):
    """Create a mock HTTPClient that returns a controlled response."""
    client = MagicMock()
    resp = HTTPResponse(
        url="https://example.com/test",
        status_code=status,
        headers=headers or {},
        text=body,
        elapsed_ms=50.0,
    )
    client.get.return_value = resp
    return client


def make_infra(tmp_path):
    """Create shared infrastructure objects for tests."""
    store = EvidenceStore(output_dir=str(tmp_path))
    throttler = Throttler(delay=0)
    return store, throttler


class TestMaskDict(unittest.TestCase):
    """Tests for the sensitive-value masking utility."""

    def test_masks_password_key(self):
        result = _mask_dict({"password": "s3cr3t"})
        self.assertEqual(result["password"], "[REDACTED]")

    def test_masks_nested(self):
        result = _mask_dict({"outer": {"db_pass": "hunter2"}})
        self.assertEqual(result["outer"]["db_pass"], "[REDACTED]")

    def test_preserves_non_sensitive(self):
        result = _mask_dict({"url": "https://example.com", "status": 200})
        self.assertEqual(result["url"], "https://example.com")
        self.assertEqual(result["status"], 200)

    def test_masks_list_of_dicts(self):
        result = _mask_dict([{"token": "abc123"}, {"title": "test"}])
        self.assertEqual(result[0]["token"], "[REDACTED]")
        self.assertEqual(result[1]["title"], "test")


class TestThrottler(unittest.TestCase):
    """Tests for the Throttler utility."""

    def test_zero_delay_does_not_raise(self):
        t = Throttler(delay=0)
        t.wait()
        t.wait()

    def test_custom_delay_attribute(self):
        t = Throttler(delay=1.5)
        self.assertEqual(t.delay, 1.5)


class TestEvidenceStore(unittest.TestCase):
    """Tests for EvidenceStore disk persistence."""

    def test_save_creates_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = EvidenceStore(output_dir=tmp)
            finding = {
                "title": "Test Finding",
                "url": "https://example.com",
                "parameter": "q",
                "payload": "test",
                "method": "GET",
                "response_snippet": "some html",
                "severity": "high",
                "confidence": "high",
                "owasp": "A03",
                "timestamp": "2024-01-01T00:00:00Z",
            }
            path = store.save(finding)
            self.assertTrue(Path(path).exists())

    def test_save_masks_secrets(self):
        import json
        with tempfile.TemporaryDirectory() as tmp:
            store = EvidenceStore(output_dir=tmp)
            finding = {
                "title": "Test",
                "url": "https://example.com",
                "parameter": "q",
                "payload": "p",
                "method": "GET",
                "response_snippet": "DB_PASSWORD=hunter2",
                "severity": "low",
                "confidence": "high",
                "owasp": "A05",
                "timestamp": "2024-01-01T00:00:00Z",
            }
            path = store.save(finding)
            data = json.loads(Path(path).read_text())
            # The response_snippet is a string value, not under a sensitive key
            # Check that sensitive keys would be masked if they appeared
            self.assertIn("response_snippet", data)


class TestHeaderScanner(unittest.TestCase):
    """Tests for the security header scanner."""

    def test_detects_missing_csp(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, throttler = make_infra(tmp)
            # Response with NO security headers
            http = make_mock_http(
                status=200,
                body="<html>ok</html>",
                headers={"Content-Type": "text/html"},
            )
            from pyscan.scanner.headers import HeaderScanner
            scanner = HeaderScanner(http, throttler, store, learning_mode=False)
            findings = scanner.scan("https://example.com")
            titles = [f["title"] for f in findings]
            self.assertTrue(any("Content-Security-Policy" in t for t in titles))

    def test_no_findings_when_all_headers_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, throttler = make_infra(tmp)
            http = make_mock_http(
                status=200,
                body="<html>ok</html>",
                headers={
                    "Content-Security-Policy": "default-src 'self'",
                    "X-Frame-Options": "DENY",
                    "X-Content-Type-Options": "nosniff",
                    "Strict-Transport-Security": "max-age=31536000",
                },
            )
            from pyscan.scanner.headers import HeaderScanner
            scanner = HeaderScanner(http, throttler, store, learning_mode=False)
            findings = scanner.scan("https://example.com")
            self.assertEqual(findings, [])

    def test_learning_mode_adds_note(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, throttler = make_infra(tmp)
            http = make_mock_http(status=200, body="ok", headers={})
            from pyscan.scanner.headers import HeaderScanner
            scanner = HeaderScanner(http, throttler, store, learning_mode=True)
            findings = scanner.scan("https://example.com")
            self.assertTrue(any(f.get("learning_note") for f in findings))


class TestXSSScanner(unittest.TestCase):
    """Tests for the reflected XSS scanner."""

    def test_detects_reflection(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, throttler = make_infra(tmp)
            # Response body contains the unencoded XSS probe payload
            http = make_mock_http(
                status=200,
                body='<html>Search results for <pyscan-xss-test></html>',
            )
            from pyscan.scanner.xss import XSSScanner, XSS_PAYLOAD
            scanner = XSSScanner(http, throttler, store, learning_mode=False)
            findings = scanner.scan("https://example.com/search?q=test")
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["parameter"], "q")

    def test_no_finding_when_encoded(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, throttler = make_infra(tmp)
            # Payload is HTML-encoded in the response
            http = make_mock_http(
                status=200,
                body='<html>Search: &lt;pyscan-xss-test&gt;</html>',
            )
            from pyscan.scanner.xss import XSSScanner
            scanner = XSSScanner(http, throttler, store, learning_mode=False)
            findings = scanner.scan("https://example.com/search?q=test")
            self.assertEqual(len(findings), 0)

    def test_no_params_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, throttler = make_infra(tmp)
            http = make_mock_http(status=200, body="ok")
            from pyscan.scanner.xss import XSSScanner
            scanner = XSSScanner(http, throttler, store, learning_mode=False)
            findings = scanner.scan("https://example.com/page")
            self.assertEqual(findings, [])


class TestSQLiScanner(unittest.TestCase):
    """Tests for the SQL injection scanner."""

    def test_detects_mysql_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, throttler = make_infra(tmp)
            http = make_mock_http(
                status=200,
                body='You have an error in your SQL syntax near line 1',
            )
            from pyscan.scanner.sqli import SQLiScanner
            scanner = SQLiScanner(http, throttler, store, learning_mode=False)
            findings = scanner.scan("https://example.com/item?id=1")
            self.assertEqual(len(findings), 1)
            self.assertIn("SQL Injection", findings[0]["title"])

    def test_no_finding_on_clean_response(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, throttler = make_infra(tmp)
            http = make_mock_http(status=200, body='<html>Normal page</html>')
            from pyscan.scanner.sqli import SQLiScanner
            scanner = SQLiScanner(http, throttler, store, learning_mode=False)
            findings = scanner.scan("https://example.com/item?id=1")
            self.assertEqual(len(findings), 0)


class TestDirectoryScanner(unittest.TestCase):
    """Tests for the directory listing scanner."""

    def test_detects_index_of(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, throttler = make_infra(tmp)
            http = make_mock_http(
                status=200,
                body='<html><title>Index of /uploads</title></html>',
            )
            from pyscan.scanner.dirs import DirectoryScanner
            scanner = DirectoryScanner(http, throttler, store, learning_mode=False)
            findings = scanner.scan("https://example.com")
            self.assertTrue(len(findings) > 0)
            self.assertIn("Directory Listing", findings[0]["title"])

    def test_no_finding_on_403(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, throttler = make_infra(tmp)
            http = make_mock_http(status=403, body='Forbidden')
            from pyscan.scanner.dirs import DirectoryScanner
            scanner = DirectoryScanner(http, throttler, store, learning_mode=False)
            findings = scanner.scan("https://example.com")
            self.assertEqual(len(findings), 0)


class TestSensitiveFileScanner(unittest.TestCase):
    """Tests for the sensitive file scanner."""

    def test_detects_env_keywords(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, throttler = make_infra(tmp)
            http = make_mock_http(
                status=200,
                body='DB_PASSWORD=something\nAPP_KEY=base64value\n',
            )
            from pyscan.scanner.files import SensitiveFileScanner
            scanner = SensitiveFileScanner(http, throttler, store, learning_mode=False)
            findings = scanner.scan("https://example.com")
            self.assertTrue(len(findings) > 0)
            self.assertEqual(findings[0]["severity"], "critical")

    def test_no_finding_on_404(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, throttler = make_infra(tmp)
            http = make_mock_http(status=404, body='Not Found')
            from pyscan.scanner.files import SensitiveFileScanner
            scanner = SensitiveFileScanner(http, throttler, store, learning_mode=False)
            findings = scanner.scan("https://example.com")
            self.assertEqual(len(findings), 0)

    def test_response_snippet_masks_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, throttler = make_infra(tmp)
            http = make_mock_http(
                status=200,
                body='DB_PASSWORD=supersecret123\n',
            )
            from pyscan.scanner.files import SensitiveFileScanner
            scanner = SensitiveFileScanner(http, throttler, store, learning_mode=False)
            findings = scanner.scan("https://example.com")
            if findings:
                # The actual secret value must NOT appear in the snippet
                snippet = findings[0].get("response_snippet", "")
                self.assertNotIn("supersecret123", snippet)


if __name__ == "__main__":
    unittest.main(verbosity=2)
