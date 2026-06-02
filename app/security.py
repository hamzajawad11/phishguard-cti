"""SSRF protection for outbound requests.

PhishGuard fetches user-supplied URLs (live probing and redirect tracing).
Without guardrails an attacker could point the scanner at internal services
(cloud metadata endpoints, localhost admin panels, private subnets). These
helpers resolve a host and reject any address in a private, loopback,
link-local, reserved, multicast, or unspecified range.

Note: this resolve-and-check approach mitigates the common case but does not
fully defeat DNS-rebinding (the address is re-resolved when the request is
actually made). For this passive-CTI tool that trade-off is acceptable.
"""

import ipaddress
import socket
from urllib.parse import urlparse

_ALLOWED_SCHEMES = {"http", "https"}


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def is_safe_host(host: str) -> bool:
    """Return True only if every address ``host`` resolves to is public."""
    if not host:
        return False

    # Literal IP address: check directly, no DNS needed.
    try:
        return not _is_blocked_ip(ipaddress.ip_address(host))
    except ValueError:
        pass

    # Hostname: resolve and reject if any address is internal. If the name
    # does not resolve at all there is nothing to connect to, so it is not an
    # SSRF risk — allow it through and let the request layer fail naturally.
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return True

    for info in infos:
        address = info[4][0]
        # IPv6 results can carry a scope id ("fe80::1%eth0"); strip it.
        address = address.split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        if _is_blocked_ip(ip):
            return False
    return True


def is_safe_url(url: str) -> bool:
    """Return True if ``url`` uses http(s) and targets a public host."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        return False
    return is_safe_host(parsed.hostname or "")
