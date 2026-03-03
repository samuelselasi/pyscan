from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from pyscan.scanner.base import BaseScanner

XSS_PAYLOAD = chr(60) + chr(112) + chr(121) + chr(115) + chr(99) + chr(97) + chr(110) + chr(45) + chr(120) + chr(115) + chr(115) + chr(45) + chr(116) + chr(101) + chr(115) + chr(116) + chr(62)

class XSSScanner(BaseScanner):
    name = "Reflected XSS Scanner"
    owasp = "A03:2021 - Injection"

    def scan(self, url):
        self.throttler.wait()
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return findings
        for param_name in params:
            injected = dict(params)
            injected[param_name] = [XSS_PAYLOAD]
            test_url = urlunparse(parsed._replace(query=urlencode(injected, doseq=True)))
            self.throttler.wait()
            resp = self.http.get(test_url)
            if resp is None:
                continue
            if XSS_PAYLOAD in resp.text:
                idx = resp.text.find(XSS_PAYLOAD)
                snippet = resp.text[max(0,idx-100):idx+len(XSS_PAYLOAD)+100]
                ln = None
                if self.learning_mode:
                    ln = ("WHY: Reflected XSS occurs when user input is returned in HTML without encoding. "
                          "HOW: pyscan injected a custom tag into the URL parameter and found it unencoded in the response. "
                          "A real attacker could inject script tags to steal session cookies. "
                          "REMEDIATION: HTML-encode all user-supplied output. Implement a strict Content-Security-Policy.")
                findings.append(self._make_finding(
                    title="Reflected XSS in Parameter: " + param_name,
                    url=test_url,
                    parameter=param_name,
                    payload=XSS_PAYLOAD,
                    method="GET",
                    response_snippet=snippet,
                    severity="high",
                    confidence="high",
                    owasp="A03:2021 - Injection",
                    learning_note=ln,
                ))
        return findings
