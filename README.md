# PyScan

An educational, proof-based web penetration testing command-line tool for authorized security assessments.

PyScan performs non-destructive vulnerability discovery against web targets, captures verifiable evidence from HTTP responses, and produces structured reports aligned with the OWASP Top 10. It is designed for use in authorized penetration tests, security coursework, and self-directed learning.

---

## Ethical and Legal Disclaimer

**PyScan is for authorized penetration testing and educational use only.**

By using this tool you confirm that:

1. You own the target system, or
2. You have explicit, written authorization from the system owner to perform security testing.

Unauthorized use of PyScan against any system you do not own or have explicit permission to test is illegal in most jurisdictions, including under the Computer Fraud and Abuse Act (United States), the Computer Misuse Act (United Kingdom), and equivalent legislation worldwide.

The authors of PyScan accept no liability for unauthorized, illegal, or unethical use of this software.

PyScan is non-destructive by design. It does not exploit vulnerabilities, extract data, execute payloads, or perform brute-force attacks. All checks are read-only and use safe, controlled proof-of-concept probes only.

---

## Features

- Six independent scanner modules covering common web vulnerability classes
- Proof-based findings: every result includes the URL, parameter, payload, and a captured response snippet
- OWASP Top 10 (2021) category mapping for all findings
- Severity and confidence ratings per finding
- Timestamped evidence files saved to disk with automatic sensitive value masking
- JSON report output suitable for programmatic processing or archiving
- HTML report output styled for client-ready or portfolio presentation
- Learning mode: optional inline explanations of why each vulnerability matters, how the payload works, and how to remediate it
- Configurable request throttling to avoid overloading target servers
- Mandatory authorization acknowledgement flag: the tool refuses to run without explicit confirmation

---

## Supported Vulnerabilities

### Reflected XSS (Severity: High — OWASP A03:2021)

Detects URL parameters that reflect user input without HTML encoding. A safe, non-executing custom HTML tag is injected into each parameter. If the tag appears unencoded in the response body, reflected XSS is confirmed without executing any JavaScript.

### Error-Based SQL Injection (Severity: Critical — OWASP A03:2021)

Injects a single-quote character into URL parameters and inspects the response for database error strings from MySQL, PostgreSQL, and SQLite. No data is read or extracted. The exact error string is captured as proof.

### Security Header Misconfiguration (Severity: Medium — OWASP A05:2021)

Performs a passive check of HTTP response headers and reports any of the following that are absent:

- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Strict-Transport-Security`

### Directory Listing (Severity: High — OWASP A05:2021)

Requests common directory paths including `/uploads`, `/backup`, `/test`, `/admin`, and `/logs`. A positive finding is confirmed only when the response contains a server-generated directory index page.

### Sensitive File Exposure (Severity: Critical — OWASP A05:2021)

Requests paths commonly associated with configuration and credential files, including `.env`, `wp-config.php`, `config.php`, `.git/config`, and `database.yml`. Detection is keyword-based only. Actual secret values are never read, printed, or stored.

### TLS and HTTPS Weaknesses (Severity: Low to High — OWASP A02:2021)

Checks whether the target uses HTTPS, validates the TLS certificate, reports the number of days until expiry, and flags negotiated protocol versions that are deprecated or known to be weak (TLS 1.0, TLS 1.1, SSLv2, SSLv3).

---

## Installation

### Requirements

- Python 3.10 or later
- pip

### From PyPI

```bash
pip install pyscan
```

### From Source

```bash
git clone https://github.com/example/pyscan.git
cd pyscan
pip install -e .
```

### Using requirements.txt

```bash
pip install -r requirements.txt
```

---

## Environment Setup

### Supported Operating Systems

pyscan runs on any platform with a supported Python installation: Linux, macOS, and Windows.

### Virtual Environment (Recommended)

Using a virtual environment prevents dependency conflicts with other Python projects.

```bash
python3 -m venv .venv
source .venv/bin/activate        # Linux and macOS
.venv\Scripts\activate.bat       # Windows

pip install -e .
```

### Dependencies

| Package  | Purpose                            |
|----------|------------------------------------|
| requests | HTTP request handling              |
| urllib3  | Connection pooling and retry logic |

No external binary dependencies are required.

---

## Usage

### Basic Scan

The `--i-have-permission` flag is required. pyscan will refuse to run without it.

```bash
pyscan https://your-authorized-target.example.com --i-have-permission
```

### Learning Mode

Adds inline explanations to each finding describing why the vulnerability is dangerous, how it was detected, and how to remediate it.

```bash
pyscan https://your-authorized-target.example.com --i-have-permission --learning-mode
```

### Output Formats

```bash
# JSON (default)
pyscan https://example.com --i-have-permission --output json

# HTML
pyscan https://example.com --i-have-permission --output html

# Both formats
pyscan https://example.com --i-have-permission --output both
```

### Severity Filtering

Report only findings at or above a minimum severity level.

```bash
pyscan https://example.com --i-have-permission --severity high
```

Valid values: `low`, `medium`, `high`, `critical`. Default is `low` (all findings included).

### Full Example

```bash
pyscan https://your-authorized-target.example.com \
  --i-have-permission \
  --learning-mode \
  --output both \
  --severity medium \
  --delay 1.0 \
  --timeout 15 \
  --output-dir ./results
```

### All Options

| Flag                | Default        | Description                                                |
|---------------------|----------------|------------------------------------------------------------|
| `--i-have-permission` | (required)   | Confirms written authorization to test the target.         |
| `--learning-mode`   | off            | Adds educational explanations to each finding.             |
| `--output`          | `json`         | Report format: `json`, `html`, or `both`.                  |
| `--severity`        | `low`          | Minimum severity level to include in the report.           |
| `--delay`           | `0.5`          | Seconds between HTTP requests.                             |
| `--timeout`         | `10`           | HTTP request timeout in seconds.                           |
| `--output-dir`      | `pyscan_results` | Directory for reports and evidence files.                |

---

## Example Output

### CLI Output

```
+===============================================================+
|                       P y S c a n                            |
|         Educational Web Penetration Testing CLI              |
|                      v1.0.0                                   |
+===============================================================+
|  WARNING: AUTHORIZED USE ONLY - ILLEGAL USE IS FORBIDDEN     |
+===============================================================+

[*] Target  : https://example.com
[*] Started : 2024-06-01T10:14:32Z
[*] Mode    : Learning

[->] Running: Security Header Scanner
    [!] 4 finding(s) detected.

[->] Running: Reflected XSS Scanner
    [!] 1 finding(s) detected.

[->] Running: SQL Injection Scanner (Error-Based)
    [!] 1 finding(s) detected.

[->] Running: Directory Listing Scanner
    [OK] No issues found.

[->] Running: Sensitive File Exposure Scanner
    [!] 1 finding(s) detected.

[->] Running: TLS/HTTPS Analyser
    [OK] No issues found.

======================================================================
  FINDINGS SUMMARY  (7 finding(s) at 'low' or above)
======================================================================

  [1] [CRITICAL] SQL Injection (Error-Based) in Parameter: id
       URL       : https://example.com/product?id=%27
       Parameter : id
       OWASP     : A03:2021 - Injection
       Confidence: high

       [LEARNING MODE]
          WHY: SQL injection allows attackers to manipulate database
          queries, potentially reading, modifying, or deleting data.
          HOW: pyscan injected a single-quote into parameter 'id' and
          the server returned a MySQL error string, confirming the input
          reaches a SQL query without parameterisation.
          REMEDIATION: Use parameterised queries (prepared statements).
          Never concatenate user input into SQL strings.

  [2] [HIGH] Reflected XSS in Parameter: search
       URL       : https://example.com/search?search=...
       Parameter : search
       OWASP     : A03:2021 - Injection
       Confidence: high

======================================================================

[OK] JSON report saved: pyscan_results/pyscan_report_20240601_101435.json
[OK] HTML report saved: pyscan_results/pyscan_report_20240601_101435.html

[*] Scan complete. 7 total finding(s).
```

### Sample JSON Finding

```json
{
  "title": "SQL Injection (Error-Based) in Parameter: id",
  "url": "https://example.com/product?id=%27",
  "parameter": "id",
  "payload": "'",
  "method": "GET",
  "response_snippet": "...You have an error in your SQL syntax near '...",
  "severity": "critical",
  "confidence": "high",
  "owasp": "A03:2021 - Injection",
  "timestamp": "2024-06-01T10:14:38Z",
  "learning_note": "WHY: SQL injection allows attackers to read or modify database data..."
}
```

### Proof-of-Concept Evidence

Every finding captures the exact URL, parameter, payload, and a trimmed snippet of the HTTP response that confirms the vulnerability. This constitutes verifiable, reproducible proof suitable for direct inclusion in a penetration test report without requiring re-execution of the scan.

---

## Learning Mode

When `--learning-mode` is enabled, each finding is supplemented with an inline note covering three areas:

- **WHY** — The security impact of the vulnerability and how an attacker would exploit it.
- **HOW** — The exact mechanism pyscan used to detect the issue, including the payload sent and the response pattern that confirmed the finding.
- **REMEDIATION** — Concrete, actionable steps to fix the vulnerability.

Learning mode is intended for students, developers reviewing their own applications, and anyone using pyscan to develop practical understanding of the OWASP Top 10. Learning mode notes appear in both JSON and HTML output when the flag is active.

---

## Evidence and Reporting

### Evidence Files

Each finding is written to an individual JSON file under `<output-dir>/evidence/<timestamp>/`. Files are numbered and named after the finding title. Evidence is saved automatically by every scanner module at detection time.

### Sensitive Value Masking

Before any evidence is written to disk, pyscan recursively inspects the finding data structure for keys matching common sensitive patterns, including `password`, `token`, `secret`, `api_key`, `credential`, `private_key`, and similar variants. Any matching string values are replaced with `[REDACTED]`. Actual credential values are never stored to disk.

For sensitive file exposure findings, only the names of detected keywords are recorded in evidence, not their values.

### JSON Reports

The JSON report contains a `scan_meta` block with the target URL, scan timestamp, pyscan version, and finding counts, followed by a `findings` array. The format is suitable for import into vulnerability management tools or further scripted processing.

### HTML Reports

The HTML report is a self-contained, styled document with severity badges, response snippet display, and an optional learning mode section per finding. It is suitable for sharing with clients or including in a security portfolio.

### Exit Codes

| Code | Meaning                                                          |
|------|------------------------------------------------------------------|
| `0`  | Scan completed with no high or critical findings.                |
| `2`  | Scan completed with one or more high or critical findings.       |

---

## Project Structure

```
pyscan/
├── pyscan/
│   ├── __init__.py           # Package version and metadata
│   ├── cli.py                # CLI entry point, argument parsing, scan orchestration
│   ├── scanner/
│   │   ├── base.py           # BaseScanner: shared finding construction and evidence saving
│   │   ├── headers.py        # Security header misconfiguration scanner
│   │   ├── xss.py            # Reflected XSS scanner
│   │   ├── sqli.py           # Error-based SQL injection scanner
│   │   ├── dirs.py           # Directory listing scanner
│   │   ├── files.py          # Sensitive file exposure scanner
│   │   └── tls.py            # TLS and HTTPS weakness analyser
│   ├── reports/
│   │   ├── json_report.py    # JSON report writer
│   │   └── html_report.py    # HTML report writer
│   └── utils/
│       ├── http.py           # Shared HTTP client with retry and response wrapper
│       ├── evidence.py       # Evidence store with automatic secret masking
│       └── throttling.py     # Request rate limiter
├── tests/
│   └── test_scanner.py       # Unit test suite (no live network calls)
├── pyproject.toml            # Build configuration and entry point definition
├── requirements.txt          # Runtime dependencies
├── LICENSE                   # MIT License
└── README.md
```

Each scanner module inherits from `BaseScanner`, which provides a shared `_make_finding()` method. This method constructs a standardised finding dictionary, saves it to the evidence store, and returns it. Adding a new scanner requires only subclassing `BaseScanner`, implementing `scan(url)`, and registering it in `cli.py`.

---

## Testing

The test suite is located in `tests/test_scanner.py` and uses the Python built-in `unittest` module with `unittest.mock`. All tests operate against mock HTTP responses. No live network requests are made during the test run.

### Running the Tests

```bash
python -m unittest tests.test_scanner -v
```

Or, if pytest is installed:

```bash
pytest tests/ -v
```

### Test Coverage

The test suite covers:

- Sensitive value masking logic (`_mask_dict`)
- Evidence file creation and on-disk persistence (`EvidenceStore`)
- Request throttling behaviour (`Throttler`)
- Each scanner module against controlled mock HTTP responses, verifying correct positive detection, correct negative detection on clean responses, and learning mode note generation
- JSON and HTML report writers
- CLI argument parsing and URL validation

---

## License

PyScan is released under the MIT License. See [LICENSE](LICENSE) for the full license text.
