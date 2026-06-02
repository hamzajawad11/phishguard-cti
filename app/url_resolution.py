import re
from typing import Any

import requests

from app.config import PROBE_TIMEOUT, USER_AGENT
from app.security import is_safe_url


REQUEST_TIMEOUT = PROBE_TIMEOUT


def resolve_live_url(raw: str) -> dict[str, Any]:
    value = _target_token(raw)
    if re.match(r"(?i)^https?://", value):
        return {
            "source": "Live URL Resolution",
            "status": "provided",
            "detail": "Input already included a URL scheme.",
            "url": value,
            "attempts": [],
        }

    candidates = [f"https://{value}", f"http://{value}"]
    attempts = []
    for candidate in candidates:
        attempt = _probe(candidate)
        attempts.append(attempt)
        if attempt["reachable"]:
            return {
                "source": "Live URL Resolution",
                "status": "resolved",
                "detail": f"Resolved missing scheme using live probe: {candidate}",
                "url": candidate,
                "attempts": attempts,
            }

    return {
        "source": "Live URL Resolution",
        "status": "fallback",
        "detail": "No scheme was provided and live probing did not find a reachable endpoint; using HTTPS as the safer default.",
        "url": candidates[0],
        "attempts": attempts,
    }


def _target_token(raw: str) -> str:
    value = raw.strip().strip("<>").strip()
    token = value.split()[0] if value.split() else value
    if token.startswith("www."):
        return token
    return token


def _probe(url: str) -> dict[str, Any]:
    if not is_safe_url(url):
        return {
            "url": url,
            "reachable": False,
            "status_code": None,
            "error": "blocked_internal_address",
        }

    try:
        response = requests.head(url, allow_redirects=False, timeout=REQUEST_TIMEOUT)
        if response.status_code in {405, 403}:
            response = requests.get(
                url,
                allow_redirects=False,
                timeout=REQUEST_TIMEOUT,
                headers={"Range": "bytes=0-0", "User-Agent": USER_AGENT},
                stream=True,
            )
            response.close()
        return {
            "url": url,
            "reachable": response.status_code < 500,
            "status_code": response.status_code,
            "error": None,
        }
    except requests.RequestException as exc:
        return {
            "url": url,
            "reachable": False,
            "status_code": None,
            "error": exc.__class__.__name__,
        }
