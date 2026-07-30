"""
CNAME-based subdomain-takeover heuristic.

For each resolved subdomain we fetch its CNAME record (see `resolver.py`).
If that CNAME points at a known "vulnerable service" pattern -- a hosting
provider that lets anyone claim an unclaimed name (GitHub Pages, Heroku, S3,
etc.) -- and independent evidence suggests the target is *not* actually
claimed (the CNAME target itself doesn't resolve, or the service's own
"not found" page is served), we flag it as a possible subdomain takeover.

The matching and decision logic here is pure (no network I/O) so it can be
fully unit tested against synthetic fixtures.
"""

from __future__ import annotations

from typing import Optional

from .models import TakeoverFinding

# Known CNAME suffixes for services that are commonly vulnerable to
# subdomain takeover when the referenced resource has been deleted/unclaimed.
VULNERABLE_CNAME_SUFFIXES: list[str] = [
    "github.io",
    "herokuapp.com",
    "s3.amazonaws.com",
    "azurewebsites.net",
    "readme.io",
    "wordpress.com",
    "surge.sh",
    "bitbucket.io",
    "fastly.net",
]

# Fingerprint strings that appear in each service's "nothing is here" /
# "unclaimed resource" response body, used as corroborating evidence when the
# CNAME target itself still resolves (so DNS failure alone can't prove it).
NOT_CLAIMED_MARKERS: dict[str, list[str]] = {
    "github.io": ["there isn't a github pages site here"],
    "herokuapp.com": ["no such app"],
    "s3.amazonaws.com": ["nosuchbucket", "the specified bucket does not exist"],
    "azurewebsites.net": ["404 web site not found", "web app - unavailable"],
    "readme.io": ["project doesnt exist", "project doesn't exist"],
    "wordpress.com": ["do you want to register"],
    "surge.sh": ["project not found"],
    "bitbucket.io": ["repository not found"],
    "fastly.net": ["fastly error: unknown domain"],
}


def matches_vulnerable_service(cname: Optional[str]) -> Optional[str]:
    """Return the matched vulnerable-service suffix if `cname` points at one
    of the known takeover-prone providers, else None."""
    if not cname:
        return None
    cname = cname.strip().lower().rstrip(".")
    for suffix in VULNERABLE_CNAME_SUFFIXES:
        if cname == suffix or cname.endswith(f".{suffix}"):
            return suffix
    return None


def evaluate_takeover(
    subdomain: str,
    cname: Optional[str],
    cname_resolves: bool,
    http_body: str = "",
) -> Optional[TakeoverFinding]:
    """Pure decision function combining CNAME-pattern matching with
    corroborating evidence to decide whether a subdomain is a possible
    takeover candidate.

    - `cname_resolves`: whether the CNAME target itself resolves via DNS.
    - `http_body`: optional response body fetched from the subdomain, used
      to check for service-specific "not claimed" fingerprints when the
      CNAME target does still resolve (shared hosting IPs are common, so
      DNS resolution alone doesn't prove the resource is claimed).
    """
    service = matches_vulnerable_service(cname)
    if service is None:
        return None

    if not cname_resolves:
        return TakeoverFinding(
            service=service,
            cname_target=cname or "",
            evidence=f"CNAME target '{cname}' does not resolve (NXDOMAIN) while "
            f"'{subdomain}' still has a dangling CNAME to it.",
        )

    body_lower = (http_body or "").lower()
    markers = NOT_CLAIMED_MARKERS.get(service, [])
    for marker in markers:
        if marker in body_lower:
            return TakeoverFinding(
                service=service,
                cname_target=cname or "",
                evidence=f"Response body matched unclaimed-resource fingerprint '{marker}' for {service}.",
            )

    return None
