import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
from pyscan.scanner.base import BaseScanner


class TLSScanner(BaseScanner):
    name = "TLS/HTTPS Analyser"
    owasp = "A02:2021 - Cryptographic Failures"

    def scan(self, url):
        self.throttler.wait()
        findings = []
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.scheme != "https":
            ln = "WHY: HTTP transmits data in plaintext. REMEDIATION: Use HTTPS." if self.learning_mode else None
            findings.append(self._make_finding(
                title="Site Not Using HTTPS", url=url,
                parameter="URL scheme", payload="passive check",
                method="N/A", response_snippet="Scheme is http",
                severity="high", confidence="high",
                owasp="A02:2021 - Cryptographic Failures", learning_note=ln,
            ))
            return findings
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    not_after = ssl.cert_time_to_seconds(cert["notAfter"])
                    expiry_dt = datetime.fromtimestamp(not_after, tz=timezone.utc)
                    days_left = (expiry_dt - datetime.now(tz=timezone.utc)).days
                    if days_left < 0:
                        findings.append(self._make_finding(
                            title="TLS Certificate Expired", url=url,
                            parameter="TLS Certificate", payload="TLS handshake",
                            method="N/A", response_snippet="Expired: " + str(expiry_dt),
                            severity="critical", confidence="high",
                            owasp="A02:2021 - Cryptographic Failures",
                            learning_note="WHY: Expired cert breaks trust. Renew immediately." if self.learning_mode else None,
                        ))
                    elif days_left < 30:
                        findings.append(self._make_finding(
                            title="TLS Certificate Expiring Soon", url=url,
                            parameter="TLS Certificate", payload="TLS handshake",
                            method="N/A", response_snippet="Expires in " + str(days_left) + " days",
                            severity="medium", confidence="high",
                            owasp="A02:2021 - Cryptographic Failures",
                            learning_note="WHY: Expiring soon. Renew before expiry." if self.learning_mode else None,
                        ))
                    weak = ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]
                    if protocol in weak:
                        findings.append(self._make_finding(
                            title="Weak TLS Protocol: " + protocol, url=url,
                            parameter="TLS Protocol", payload="TLS handshake",
                            method="N/A", response_snippet="Negotiated: " + protocol,
                            severity="medium", confidence="high",
                            owasp="A02:2021 - Cryptographic Failures",
                            learning_note="WHY: TLS 1.0/1.1 are deprecated. Use TLS 1.2+." if self.learning_mode else None,
                        ))
        except ssl.SSLCertVerificationError as exc:
            findings.append(self._make_finding(
                title="TLS Cert Verification Failed", url=url,
                parameter="TLS Certificate", payload="TLS handshake",
                method="N/A", response_snippet=str(exc)[:200],
                severity="high", confidence="high",
                owasp="A02:2021 - Cryptographic Failures",
                learning_note="WHY: Untrusted cert. REMEDIATION: Use a CA-signed cert." if self.learning_mode else None,
            ))
        except Exception:
            pass
        return findings
