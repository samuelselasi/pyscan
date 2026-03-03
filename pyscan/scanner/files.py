from pyscan.scanner.base import BaseScanner

SENSITIVE_FILES = [
    (".env", ["DB_PASSWORD","APP_KEY","SECRET_KEY"]),
    ("config.php", ["db_password","db_pass"]),
    ("backup.zip", ["PK"]),
    ("wp-config.php", ["DB_PASSWORD"]),
    ("database.yml", ["password:"]),
]


class SensitiveFileScanner(BaseScanner):
    name = "Sensitive File Exposure Scanner"
    owasp = "A05:2021 - Security Misconfiguration"

    def scan(self, url):
        self.throttler.wait()
        findings = []
        base = url.rstrip("/")
        for rel_path, keywords in SENSITIVE_FILES:
            self.throttler.wait()
            target = base + "/" + rel_path
            resp = self.http.get(target)
            if resp is None or resp.status_code != 200:
                continue
            matched = [kw for kw in keywords if kw.upper() in resp.text.upper()]
            if not matched:
                continue
            ln = None
            if self.learning_mode:
                ln = ("WHY: Exposed config files contain credentials giving attackers database access. "
                      "HOW: pyscan requested /" + rel_path + " and found keywords ("
                      + ", ".join(matched) + ") in the response body. "
                      "NOTE: pyscan does NOT read or store actual secret values. "
                      "REMEDIATION: Move config files outside the web root and rotate exposed credentials.")
            findings.append(self._make_finding(
                title="Sensitive File Exposed: /" + rel_path,
                url=target,
                parameter="/" + rel_path,
                payload="(none - direct GET request)",
                method="GET",
                response_snippet="[Keywords: " + ", ".join(matched) + "] - values masked",
                severity="critical",
                confidence="high",
                owasp="A05:2021 - Security Misconfiguration",
                learning_note=ln,
            ))
        return findings
