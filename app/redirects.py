from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from app.config import MAX_REDIRECTS, REDIRECT_TIMEOUT, USER_AGENT
from app.security import is_safe_url


REQUEST_TIMEOUT = REDIRECT_TIMEOUT
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def trace_redirects(url: str, original_domain: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "source": "Redirect Trace",
        "status": "unavailable",
        "detail": "Redirect trace not completed.",
        "final_url": url,
        "final_domain": original_domain,
        "chain": [],
        "redirect_count": 0,
        "cross_domain": False,
    }

    if not url.lower().startswith(("http://", "https://")):
        result.update({"status": "not_applicable", "detail": "Only HTTP and HTTPS URLs can be traced."})
        return result

    if not is_safe_url(url):
        result.update({"status": "blocked", "detail": "The URL resolves to a private or internal address."})
        return result

    session = requests.Session()
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Range": "bytes=0-0",
    }

    # Follow redirects manually so every hop can be validated against SSRF
    # before we connect to it. `requests` would otherwise follow the whole
    # chain internally, including any hop that points at an internal host.
    chain: list[dict[str, Any]] = []
    current_url = url
    try:
        for _ in range(MAX_REDIRECTS + 1):
            response = session.get(
                current_url,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
                stream=True,
            )
            response.close()

            location = response.headers.get("Location") or ""
            if response.status_code not in _REDIRECT_STATUSES or not location:
                break

            next_url = urljoin(current_url, location)
            chain.append(
                {
                    "status_code": response.status_code,
                    "url": current_url,
                    "location": next_url,
                    "domain": (urlparse(current_url).hostname or "").lower(),
                }
            )

            if not is_safe_url(next_url):
                result.update(
                    {
                        "status": "blocked",
                        "detail": "Redirect chain points to a private or internal address.",
                        "final_url": current_url,
                        "final_domain": (urlparse(current_url).hostname or "").lower(),
                        "chain": chain,
                        "redirect_count": len(chain),
                    }
                )
                return result

            current_url = next_url
        else:
            result.update(
                {
                    "status": "suspicious",
                    "detail": "Redirect limit exceeded.",
                    "chain": chain,
                    "redirect_count": len(chain),
                }
            )
            return result
    except requests.TooManyRedirects:
        result.update({"status": "suspicious", "detail": "Redirect limit exceeded.", "redirect_count": MAX_REDIRECTS})
        return result
    except requests.RequestException as exc:
        result["detail"] = f"Redirect trace unavailable: {exc.__class__.__name__}."
        return result

    final_url = response.url
    final_domain = (urlparse(final_url).hostname or "").lower()
    original = (original_domain or "").lower()
    cross_domain = bool(original and final_domain and final_domain != original)
    status = "suspicious" if cross_domain or len(chain) >= 3 else "ok"

    result.update(
        {
            "status": status,
            "detail": "Redirect chain completed." if chain else "No redirects observed.",
            "final_url": final_url,
            "final_domain": final_domain,
            "chain": chain,
            "redirect_count": len(chain),
            "cross_domain": cross_domain,
            "final_status_code": response.status_code,
        }
    )
    return result
