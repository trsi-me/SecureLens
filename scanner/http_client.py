"""طبقة موحّدة لإجراء طلبات HTTP آمنة أثناء الفحص."""

import time

import requests
from requests.exceptions import RequestException


class FetchResult:
    def __init__(self, ok, response=None, error=None, elapsed_ms=0, final_url=None):
        self.ok = ok
        self.response = response
        self.error = error
        self.elapsed_ms = elapsed_ms
        self.final_url = final_url


def normalize_url(raw_url: str) -> str:
    raw_url = (raw_url or "").strip()
    if not raw_url:
        return raw_url
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url
    return raw_url.rstrip("/")


def safe_get(url, timeout=10, max_redirects=5, user_agent="SecureLens/1.0", extra_headers=None):
    headers = {"User-Agent": user_agent, "Accept": "*/*"}
    if extra_headers:
        headers.update(extra_headers)

    session = requests.Session()
    session.max_redirects = max_redirects

    start = time.monotonic()
    try:
        resp = session.get(
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
            verify=True,
        )
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return FetchResult(True, response=resp, elapsed_ms=elapsed_ms, final_url=resp.url)
    except requests.exceptions.SSLError as exc:
        # Retry once without verification just to report findings about a bad cert,
        # but never treat the result as a "secure" success.
        try:
            resp = session.get(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=True,
                verify=False,
            )
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return FetchResult(
                True,
                response=resp,
                elapsed_ms=elapsed_ms,
                final_url=resp.url,
                error=f"ssl_error:{exc}",
            )
        except RequestException as exc2:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return FetchResult(False, error=str(exc2), elapsed_ms=elapsed_ms)
    except RequestException as exc:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return FetchResult(False, error=str(exc), elapsed_ms=elapsed_ms)
