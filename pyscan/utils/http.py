"""
HTTP client utility for PyScan.

Provides a configured requests Session with retry logic, a scanner User-Agent,
and safe error handling. All request errors return None so scanners can treat
unreachable endpoints as non-findings without crashing.
"""

from dataclasses import dataclass
from typing import Optional

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Suppress InsecureRequestWarning — pyscan handles TLS separately
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class HTTPResponse:
    """Lightweight, serialisable wrapper around a requests.Response."""

    url: str
    status_code: int
    headers: dict
    text: str
    elapsed_ms: float


def _build_session() -> requests.Session:
    """Create a requests Session with conservative retry and safe headers."""
    session = requests.Session()

    retry = Retry(
        total=2,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    session.headers.update(
        {
            "User-Agent": (
                "pyscan/1.0 (Educational Security Scanner; "
                "https://github.com/example/pyscan; authorized use only)"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }
    )
    return session


class HTTPClient:
    """
    Shared HTTP client used by all pyscan scanner modules.

    Design principles:
    - Returns None on network failure rather than raising, so individual
      scanners can cleanly treat unreachable paths as non-findings.
    - SSL certificate verification is disabled here; the TLS scanner
      performs its own explicit certificate analysis.
    - Response bodies are capped at 50 KB to avoid excessive memory use.
    """

    # Maximum response body to capture (bytes)
    MAX_BODY = 50_000

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self._session = _build_session()

    def get(
        self,
        url: str,
        params: Optional[dict] = None,
        allow_redirects: bool = True,
    ) -> Optional[HTTPResponse]:
        """
        Perform an HTTP GET request.

        Args:
            url: Target URL.
            params: Optional query-string parameters.
            allow_redirects: Whether to follow HTTP redirects.

        Returns:
            HTTPResponse on success, None on any network error.

        Raises:
            requests.exceptions.SSLError: Re-raised so TLSScanner can catch it.
        """
        try:
            resp = self._session.get(
                url,
                params=params,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                verify=False,  # TLS scanner handles explicit cert checks
            )
            return HTTPResponse(
                url=resp.url,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                text=resp.text[: self.MAX_BODY],
                elapsed_ms=resp.elapsed.total_seconds() * 1000,
            )
        except requests.exceptions.SSLError:
            # Re-raise so TLSScanner can capture the SSL error details
            raise
        except requests.exceptions.RequestException:
            # All other network errors (connection refused, timeout, etc.)
            return None

    def close(self) -> None:
        """Release the underlying connection pool."""
        self._session.close()
