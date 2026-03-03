"""
Base scanner class for PyScan.

All scanner modules inherit from BaseScanner. It provides shared infrastructure
for constructing standardised finding dictionaries, persisting evidence to disk,
and optionally attaching learning-mode educational notes.
"""

from datetime import datetime, timezone
from typing import Optional


class BaseScanner:
    """
    Abstract base class for all pyscan vulnerability scanner modules.

    Subclasses must:
      - Set the class attribute ``name`` to a human-readable scanner name.
      - Set the class attribute ``owasp`` to the primary OWASP Top 10 category.
      - Implement the ``scan(url: str) -> list`` method.

    The shared ``_make_finding()`` helper constructs a fully-structured finding
    dictionary, saves it to the evidence store, and returns it so the scanner
    can append it to its results list.
    """

    #: Human-readable name shown in CLI progress output.
    name: str = "BaseScanner"

    #: Primary OWASP Top 10 (2021) category for this scanner's findings.
    owasp: str = "A00:Uncategorized"

    def __init__(
        self,
        http_client,
        throttler,
        evidence_store,
        learning_mode: bool = False,
    ):
        """
        Initialise shared scanner infrastructure.

        Args:
            http_client: Shared HTTPClient instance.
            throttler: Shared Throttler instance.
            evidence_store: Shared EvidenceStore instance.
            learning_mode: When True, _make_finding attaches the
                learning_note to the finding dictionary.
        """
        self.http = http_client
        self.throttler = throttler
        self.evidence = evidence_store
        self.learning_mode = learning_mode

    def scan(self, url: str) -> list:
        """
        Execute the vulnerability scan against the target URL.

        Subclasses must override this method. It should return a (possibly
        empty) list of finding dictionaries produced by _make_finding().

        Args:
            url: The fully-qualified target URL (e.g. https://example.com).

        Returns:
            A list of finding dictionaries. Returns an empty list if no
            vulnerabilities are detected.

        Raises:
            NotImplementedError: If the subclass has not implemented this method.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement scan(url: str) -> list"
        )

    def _make_finding(
        self,
        title: str,
        url: str,
        parameter: str,
        payload: str,
        method: str,
        response_snippet: str,
        severity: str,
        confidence: str,
        owasp: str,
        learning_note: Optional[str] = None,
    ) -> dict:
        """
        Construct a standardised finding dictionary, save it to the evidence
        store, and return it.

        The finding schema is consistent across all scanner modules and is used
        directly by both report generators (JSON and HTML).

        Args:
            title: Short descriptive name for the finding,
                   e.g. "Reflected XSS in Parameter: q".
            url: The exact URL that produced the finding, including any
                 injected query parameters.
            parameter: The vulnerable parameter name, header name, or path
                 that triggered the finding.
            payload: The exact probe string injected or checked. Use a
                 descriptive note such as "(passive header check)" for checks
                 that do not inject data.
            method: HTTP method used: "GET", "POST", or "N/A" for non-HTTP
                 checks such as TLS analysis.
            response_snippet: A short excerpt from the HTTP response body or
                 headers that constitutes proof of the finding. Must not
                 contain raw secret values. Truncated to 500 characters.
            severity: One of "low", "medium", "high", or "critical".
            confidence: One of "low", "medium", or "high".
            owasp: OWASP Top 10 (2021) category string,
                   e.g. "A03:2021 - Injection".
            learning_note: Optional educational note covering why the
                 vulnerability is dangerous, how pyscan detected it, and how
                 to remediate it. Only included in the finding when
                 self.learning_mode is True.

        Returns:
            A finding dictionary containing all provided fields plus a UTC
            ISO-8601 timestamp. The dictionary is also written to the evidence
            store before being returned.
        """
        finding = {
            "title": title,
            "url": url,
            "parameter": parameter,
            "payload": payload,
            "method": method,
            # Cap the snippet to avoid bloated evidence files
            "response_snippet": (response_snippet or "")[:500],
            "severity": severity,
            "confidence": confidence,
            "owasp": owasp,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Attach the learning note only when learning mode is active and a
        # note was provided. This keeps JSON output clean in standard mode.
        if self.learning_mode and learning_note:
            finding["learning_note"] = learning_note

        # Persist evidence to disk immediately after detection.
        # The evidence store handles sensitive value masking before writing.
        self.evidence.save(finding)

        return finding
