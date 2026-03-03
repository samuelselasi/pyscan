"""Security Header Misconfiguration Scanner (OWASP A05)."""

from pyscan.scanner.base import BaseScanner

REQUIRED_HEADERS = {
    "Content-Security-Policy": {
        "severity": "medium",
        "description": "Prevents XSS and injection attacks by specifying allowed content sources.",
        "remediation": "Add a restrictive Content-Security-Policy header e.g. default-src 'self'",
        "owasp": "A05:2021 - Security Misconfiguration",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "Prevents clickjacking by blocking the page from being loaded in a frame.",
        "remediation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
        "owasp": "A05:2021 - Security Misconfiguration",
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "description": "Prevents MIME-type sniffing which can enable XSS via crafted files.",
        "remediation": "Add: X-Content-Type-Options: nosniff",
        "owasp": "A05:2021 - Security Misconfiguration",
    },
    "Strict-Transport-Security": {
        "severity": "medium",
        "description": "Forces HTTPS connections, preventing SSL-strip and downgrade attacks.",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "owasp": "A05:2021 - Security Misconfiguration",
    },
}


class HeaderScanner(BaseScanner):
    """Checks for missing HTTP security response headers."""

    name = "Security Header Scanner"
    owasp = "A05:2021 - Security Misconfiguration"

    def scan(self, url):
        """Request the target URL and check for missing security headers."""
        self.throttler.wait()
        findings = []

        resp = self.http.get(url)
        if resp is None:
            return findings

        lowered = {k.lower(): v for k, v in resp.headers.items()}

        for header, meta in REQUIRED_HEADERS.items():
            if header.lower() not in lowered:
                # HSTS is only applicable over HTTPS
                if header == "Strict-Transport-Security" and not url.startswith("https://"):
                    continue

                ln = None
                if self.learning_mode:
                    ln = (
                        "WHY: " + meta["description"] + " "
                        "HOW DETECTED: pyscan performed a GET request and inspected response headers. "
                        "The header " + header + " was completely absent from the server response. "
                        "REMEDIATION: " + meta["remediation"] + "."
                    )

                findings.append(self._make_finding(
                    title="Missing Security Header: " + header,
                    url=resp.url,
                    parameter="HTTP Response Header: " + header,
                    payload="(none - passive header check)",
                    method="GET",
                    response_snippet=str(dict(list(resp.headers.items())[:10])),
                    severity=meta["severity"],
                    confidence="high",
                    owasp=meta["owasp"],
                    learning_note=ln,
                ))

        return findings
