from pyscan.scanner.base import BaseScanner

DIRECTORIES = ["/uploads","/backup","/test","/tmp","/files","/data","/admin","/logs"]

class DirectoryScanner(BaseScanner):
    name = "Directory Listing Scanner"
    owasp = "A05:2021 - Security Misconfiguration"

    def scan(self, url):
        self.throttler.wait()
        findings = []
        base = url.rstrip("/")
        for path in DIRECTORIES:
            self.throttler.wait()
            target = base + path
            resp = self.http.get(target)
            if resp is None:
                continue
            if resp.status_code == 200 and "index of /" in resp.text.lower():
                snippet = resp.text[:500]
                ln = None
                if self.learning_mode:
                    ln = ("WHY: Directory listing reveals web directory contents to visitors. "
                          "HOW: pyscan requested " + path + " and the server returned a directory index. "
                          "REMEDIATION: Disable directory indexing in web server config.")
                findings.append(self._make_finding(
                    title="Directory Listing Enabled: " + path,
                    url=target,
                    parameter=path,
                    payload="(none - direct GET)",
                    method="GET",
                    response_snippet=snippet,
                    severity="high",
                    confidence="high",
                    owasp="A05:2021 - Security Misconfiguration",
                    learning_note=ln,
                ))
        return findings
