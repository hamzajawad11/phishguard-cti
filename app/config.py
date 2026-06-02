"""Centralized application configuration.

Keeping timeouts, limits, and shared constants in one place makes the
intelligence sources easy to tune and keeps magic numbers out of the
individual lookup modules.
"""

# Shared HTTP identity for every outbound request PhishGuard makes.
USER_AGENT = "PhishGuard-CTI/1.0"

# Per-source HTTP timeouts (seconds).
PROBE_TIMEOUT = 3          # Live scheme probing in url_resolution.
RDAP_TIMEOUT = 5           # RDAP domain-age lookups.
REDIRECT_TIMEOUT = 5       # Per-hop redirect tracing.
FEED_TIMEOUT = 4           # URLHaus, PhishStats, CISA KEV feeds.
OPTIONAL_API_TIMEOUT = 6   # VirusTotal, AbuseIPDB, OTX, urlscan.io.

# DNS resolver tuning (seconds).
DNS_LIFETIME = 4
DNS_TIMEOUT = 2

# Safety limits.
MAX_REDIRECTS = 6          # Maximum redirect hops to follow.
MAX_SCAN_TARGETS = 50      # Maximum targets processed per submission.
