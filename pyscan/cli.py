"""
PyScan CLI entry point.

LEGAL DISCLAIMER: This tool is for AUTHORIZED penetration testing ONLY.
Unauthorized use against systems you do not own or have explicit written
permission to test is illegal and unethical. The authors accept no liability
for misuse. Always obtain written authorization before testing.
"""

import argparse
import sys
import textwrap
from datetime import datetime
from urllib.parse import urlparse

from pyscan import __version__
from pyscan.scanner.headers import HeaderScanner
from pyscan.scanner.xss import XSSScanner
from pyscan.scanner.sqli import SQLiScanner
from pyscan.scanner.dirs import DirectoryScanner
from pyscan.scanner.files import SensitiveFileScanner
from pyscan.scanner.tls import TLSScanner
from pyscan.reports.json_report import JSONReporter
from pyscan.reports.html_report import HTMLReporter
from pyscan.utils.http import HTTPClient
from pyscan.utils.evidence import EvidenceStore
from pyscan.utils.throttling import Throttler

# Build the banner with plain string concatenation.
# Avoid .format() or f-strings on multi-line box art — any unintended
# brace pair causes:
#   IndexError: Replacement index 0 out of range for positional args tuple
_VER_LINE = ("v" + __version__).ljust(10)
BANNER = (
    "\n"
    "+===============================================================+\n"
    "|                       P y S c a n                            |\n"
    "|         Educational Web Penetration Testing CLI              |\n"
    "|                      " + _VER_LINE + "                           |\n"
    "+===============================================================+\n"
    "|  WARNING: AUTHORIZED USE ONLY - ILLEGAL USE IS FORBIDDEN     |\n"
    "|  You must have EXPLICIT WRITTEN PERMISSION to test any       |\n"
    "|  system with this tool.                                       |\n"
    "+===============================================================+\n"
)

ETHICAL_DISCLAIMER = """
+==============================================================+
|                  ETHICAL & LEGAL NOTICE                      |
+==============================================================+
|  PyScan is an EDUCATIONAL tool for AUTHORIZED security       |
|  testing only. By using this tool you confirm that:          |
|                                                              |
|  1. You OWN the target system, OR                            |
|  2. You have EXPLICIT WRITTEN AUTHORIZATION to test it       |
|                                                              |
|  Unauthorized use is a criminal offence in most countries    |
|  including the Computer Fraud and Abuse Act (USA),           |
|  Computer Misuse Act (UK), and equivalent legislation.       |
|                                                              |
|  The authors accept NO liability for unauthorized use.       |
+==============================================================+
"""

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def build_parser():
    """Build and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="pyscan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""
            pyscan - Educational Web Penetration Testing CLI
            ================================================
            A non-destructive, proof-based vulnerability scanner for
            authorized security assessments.

            LEGAL WARNING: You MUST have explicit written permission to
            test the target system. Unauthorized use is illegal.
        """),
        epilog=textwrap.dedent("""
            Examples:
              pyscan https://example.com --i-have-permission
              pyscan https://example.com --i-have-permission --learning-mode
              pyscan https://example.com --i-have-permission --output html
              pyscan https://example.com --i-have-permission --severity high

            ETHICAL NOTICE: This tool is for authorized testing only.
            Always obtain written permission before scanning any system.
        """),
    )

    parser.add_argument(
        "url",
        help="Target URL (must be a system you own or have permission to test)",
    )

    parser.add_argument(
        "--i-have-permission",
        action="store_true",
        default=False,
        help=(
            "REQUIRED: Confirms you have explicit written authorization to test "
            "this target. The tool WILL NOT run without this flag."
        ),
    )

    parser.add_argument(
        "--learning-mode",
        action="store_true",
        default=False,
        help=(
            "Enable learning mode: explains why each vulnerability matters, "
            "how the payload works, and how to remediate it."
        ),
    )

    parser.add_argument(
        "--output",
        choices=["json", "html", "both"],
        default="json",
        help="Output report format (default: json)",
    )

    parser.add_argument(
        "--severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Minimum severity level to include in output (default: low = all)",
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        metavar="SECONDS",
        help="Delay between requests in seconds (default: 0.5)",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SECONDS",
        help="HTTP request timeout in seconds (default: 10)",
    )

    parser.add_argument(
        "--output-dir",
        default="pyscan_results",
        metavar="DIR",
        help="Directory to save reports and evidence (default: pyscan_results)",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"pyscan {__version__}",
    )

    return parser


def validate_url(url):
    """Validate and normalise the target URL."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        print(f"[!] Invalid URL: {url}", file=sys.stderr)
        sys.exit(1)
    return url


def print_finding_summary(findings, min_severity):
    """Print a summary of findings to stdout."""
    min_level = SEVERITY_ORDER[min_severity]
    filtered = [f for f in findings if SEVERITY_ORDER.get(f.get("severity", "low"), 0) >= min_level]

    if not filtered:
        print("\n[OK] No findings at or above the specified severity threshold.")
        return

    print("\n" + "=" * 70)
    print(f"  FINDINGS SUMMARY  ({len(filtered)} finding(s) at '{min_severity}' or above)")
    print("=" * 70)

    for i, finding in enumerate(filtered, 1):
        sev = finding.get("severity", "low").upper()
        print(f"\n  [{i}] [{sev}] {finding.get('title', 'Finding')}")
        print(f"       URL      : {finding.get('url', '-')}")
        print(f"       Parameter: {finding.get('parameter', '-')}")
        print(f"       OWASP    : {finding.get('owasp', '-')}")
        print(f"       Confidence: {finding.get('confidence', '-')}")

        if finding.get("learning_note"):
            print(f"\n       [LEARNING MODE]")
            for line in textwrap.wrap(finding["learning_note"], width=60):
                print(f"          {line}")

    print("\n" + "=" * 70 + "\n")


def run_scanners(url, http_client, throttler, evidence_store, learning_mode):
    """Instantiate and run all scanner modules, returning a flat list of findings."""
    scanners = [
        HeaderScanner(http_client, throttler, evidence_store, learning_mode),
        XSSScanner(http_client, throttler, evidence_store, learning_mode),
        SQLiScanner(http_client, throttler, evidence_store, learning_mode),
        DirectoryScanner(http_client, throttler, evidence_store, learning_mode),
        SensitiveFileScanner(http_client, throttler, evidence_store, learning_mode),
        TLSScanner(http_client, throttler, evidence_store, learning_mode),
    ]

    all_findings = []
    for scanner in scanners:
        print(f"\n[->] Running: {scanner.name}")
        try:
            findings = scanner.scan(url)
            all_findings.extend(findings)
            if findings:
                print(f"    [!] {len(findings)} finding(s) detected.")
            else:
                print(f"    [OK] No issues found.")
        except Exception as exc:
            print(f"    [ERROR] Scanner error: {exc}")

    return all_findings


def main():
    """Main entry point for the pyscan CLI."""
    parser = build_parser()
    args = parser.parse_args()

    print(BANNER)
    print(ETHICAL_DISCLAIMER)

    if not args.i_have_permission:
        print(
            "[ABORTED] You must pass --i-have-permission to confirm you have\n"
            "    explicit written authorization to test the target.\n",
            file=sys.stderr,
        )
        sys.exit(1)

    url = validate_url(args.url)
    print(f"[*] Target  : {url}")
    print(f"[*] Started : {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"[*] Mode    : {'Learning' if args.learning_mode else 'Standard'}")
    print(f"[*] Output  : {args.output_dir}/")

    http_client = HTTPClient(timeout=args.timeout)
    throttler = Throttler(delay=args.delay)
    evidence_store = EvidenceStore(output_dir=args.output_dir)

    findings = run_scanners(url, http_client, throttler, evidence_store, args.learning_mode)

    print_finding_summary(findings, min_severity=args.severity)

    min_level = SEVERITY_ORDER[args.severity]
    filtered_findings = [
        f for f in findings
        if SEVERITY_ORDER.get(f.get("severity", "low"), 0) >= min_level
    ]

    scan_meta = {
        "target": url,
        "started_at": datetime.utcnow().isoformat() + "Z",
        "pyscan_version": __version__,
        "learning_mode": args.learning_mode,
        "severity_filter": args.severity,
        "total_findings": len(findings),
        "filtered_findings": len(filtered_findings),
    }

    if args.output in ("json", "both"):
        reporter = JSONReporter(output_dir=args.output_dir)
        path = reporter.write(scan_meta, filtered_findings)
        print(f"[OK] JSON report saved: {path}")

    if args.output in ("html", "both"):
        reporter = HTMLReporter(output_dir=args.output_dir)
        path = reporter.write(scan_meta, filtered_findings)
        print(f"[OK] HTML report saved: {path}")

    print(f"\n[*] Scan complete. {len(findings)} total finding(s).\n")

    high_count = sum(
        1 for f in findings
        if SEVERITY_ORDER.get(f.get("severity", "low"), 0) >= SEVERITY_ORDER["high"]
    )
    if high_count:
        sys.exit(2)


if __name__ == "__main__":
    main()
