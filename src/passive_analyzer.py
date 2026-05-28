"""Passive Response Analysis.

Analyzes existing SERVICE_DETECTED and URL_DISCOVERED events to find
security issues without making any additional network requests.

Emits VULNERABILITY_FOUND events with severity low/info.
"""

from __future__ import annotations

import re
import uuid
from typing import Optional

# Patterns that indicate sensitive/exposed files in URLs
_EXPOSED_FILE_PATTERNS = [
    r"\.env$",
    r"\.env\.local$",
    r"\.env\.production$",
    r"config\.json$",
    r"config\.yaml$",
    r"config\.yml$",
    r"docker-compose\.ya?ml$",
    r"backup\.zip$",
    r"backup\.tar\.gz$",
    r"\.git/config$",
    r"\.git/HEAD$",
    r"\.svn/entries$",
    r"\.htaccess$",
    r"\.htpasswd$",
    r"id_rsa$",
    r"id_dsa$",
    r"\.pem$",
    r"\.key$",
    r"\.p12$",
    r"\.pfx$",
    r"phpinfo\.php$",
    r"\.sql$",
    r"\.sqlite$",
    r"\.sqlite3$",
    r"\.db$",
    r"\.DS_Store$",
    r"\.idea/$",
    r"\.vscode/$",
    r"wp-config\.php$",
    r"adminer\.php$",
    r"phpmyadmin",
]

_EXPOSED_FILE_REGEX = re.compile(
    "(" + "|".join(_EXPOSED_FILE_PATTERNS) + ")", re.IGNORECASE
)

# Version pattern in Server header (e.g., nginx/1.18.0, Apache/2.4.41)
_VERSION_REGEX = re.compile(r"[a-z]+[/\s]v?\d+\.\d+", re.IGNORECASE)

# Security headers that should be present
_EXPECTED_SECURITY_HEADERS = {
    "x-frame-options",
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
}


def _base_event(asset: str, name: str, severity: str, matched_at: str = "") -> dict:
    """Build a minimal VULNERABILITY_FOUND event."""
    return {
        "event_id": str(uuid.uuid4()),
        "event_type": "VULNERABILITY_FOUND",
        "asset": asset,
        "source_tool": "passive_analyzer",
        "scan_id": "",  # populated by caller
        "scan_timestamp": "",  # populated by caller
        "metadata": {},  # populated by caller
        "data": {
            "template_id": "passive/" + name.lower().replace(" ", "-"),
            "name": name,
            "severity": severity,
            "matched_at": matched_at or asset,
            "tags": ["passive", "configuration"],
            "matcher_name": "",
            "type": "http",
            "curl_command": "",
        },
    }


class PassiveAnalyzer:
    """Inspect canonical events for security misconfigurations."""

    def analyze(self, event: dict) -> list[dict]:
        """Return list of VULNERABILITY_FOUND events derived from the input event."""
        event_type = event.get("event_type")
        if event_type == "SERVICE_DETECTED":
            return self._analyze_service(event)
        if event_type == "URL_DISCOVERED":
            return self._analyze_url(event)
        return []

    def _analyze_service(self, event: dict) -> list[dict]:
        """Analyze a SERVICE_DETECTED event."""
        findings: list[dict] = []
        data = event.get("data", {})
        asset = event.get("asset", "")
        url = data.get("url", "")
        headers: dict[str, str] = {
            k.lower(): v for k, v in (data.get("headers") or {}).items()
        }
        title = data.get("title", "")

        # 1. CORS misconfiguration
        cors = headers.get("access-control-allow-origin", "")
        if cors == "*":
            findings.append(
                _base_event(
                    asset=asset,
                    name="CORS Wildcard Origin",
                    severity="low",
                    matched_at=url,
                )
            )

        # 2. Missing security headers
        missing = _EXPECTED_SECURITY_HEADERS - set(headers.keys())
        if missing:
            findings.append(
                _base_event(
                    asset=asset,
                    name=f"Missing Security Headers ({', '.join(sorted(missing))})",
                    severity="info",
                    matched_at=url,
                )
            )

        # 3. Version disclosure in Server header
        server = headers.get("server", "")
        if _VERSION_REGEX.search(server):
            findings.append(
                _base_event(
                    asset=asset,
                    name=f"Version Disclosure ({server})",
                    severity="info",
                    matched_at=url,
                )
            )

        # 4. X-Powered-By header
        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            findings.append(
                _base_event(
                    asset=asset,
                    name=f"X-Powered-By Header Exposed ({powered_by})",
                    severity="info",
                    matched_at=url,
                )
            )

        # 5. Directory listing
        if "index of" in title.lower():
            findings.append(
                _base_event(
                    asset=asset,
                    name="Directory Listing Enabled",
                    severity="low",
                    matched_at=url,
                )
            )

        return findings

    def _analyze_url(self, event: dict) -> list[dict]:
        """Analyze a URL_DISCOVERED event for exposed files."""
        findings: list[dict] = []
        data = event.get("data", {})
        url = data.get("url", "")

        if not url:
            return findings

        if _EXPOSED_FILE_REGEX.search(url):
            findings.append(
                _base_event(
                    asset=url,
                    name="Potentially Exposed Sensitive File",
                    severity="low",
                    matched_at=url,
                )
            )

        return findings
