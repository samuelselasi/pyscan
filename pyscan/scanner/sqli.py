from pyscan.scanner.base import BaseScanner
import re

DB_ERRORS = {
    "MySQL": [
        "you have an error in your sql syntax",
        "warning: mysql_",
        "mysql_fetch_array()",
        "supplied argument is not a valid mysql",
    ],
    "PostgreSQL": [
        "pg_query()",
        "pg_exec()",
        "unterminated quoted string at or near",
        "postgresql query failed",
        "pg_connect()",
    ],
    "SQLite": [
        "sqlite3::query",
        "sqlite_array_query",
        "unrecognized token",
        "sqlite error",
    ],
    "Generic": [
        "sql syntax",
        "unclosed quotation mark",
        "odbc drivers error",
        "ora-01756",
        "quoted string not properly terminated",
    ],
}

SQL_PAYLOAD = chr(39)

class SQLiScanner(BaseScanner):
    name = "SQL Injection Scanner (Error-Based)"
    owasp = "A03:2021 - Injection"

    def scan(self, url):
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        self.throttler.wait()
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return findings
        for param_name in params:
            injected = dict(params)
            injected[param_name] = [SQL_PAYLOAD]
            test_url = urlunparse(parsed._replace(query=urlencode(injected, doseq=True)))
            self.throttler.wait()
            resp = self.http.get(test_url)
            if resp is None:
                continue
            body_lower = resp.text.lower()
            matched_db = None
            matched_error = None
            for db_type, patterns in DB_ERRORS.items():
                for pattern in patterns:
                    if pattern in body_lower:
                        matched_db = db_type
                        matched_error = pattern
                        break
                if matched_db:
                    break
            if matched_db:
                idx = body_lower.find(matched_error)
                snippet = resp.text[max(0,idx-50):idx+200]
                ln = None
                if self.learning_mode:
                    ln = ("WHY: SQL injection allows attackers to manipulate database queries. "
                          "HOW: pyscan injected a single-quote into the URL parameter. "
                          "The server returned a " + matched_db + " error message, confirming the input "
                          "is being interpolated directly into a SQL query without parameterisation. "
                          "REMEDIATION: Use parameterised queries (prepared statements). "
                          "Never concatenate user input into SQL strings.")
                findings.append(self._make_finding(
                    title="SQL Injection (Error-Based) in Parameter: " + param_name,
                    url=test_url,
                    parameter=param_name,
                    payload=SQL_PAYLOAD,
                    method="GET",
                    response_snippet=snippet,
                    severity="critical",
                    confidence="high",
                    owasp="A03:2021 - Injection",
                    learning_note=ln,
                ))
        return findings
