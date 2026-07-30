"""
Passive intelligence sources for subdomain discovery.

Each source is split into two layers:

1. A pure ``parse_*`` function that takes already-decoded JSON (or text) and
   returns a set of subdomains. These are fully unit-testable offline with
   small fixture blobs -- no network required.
2. An async ``fetch_*`` function that performs the actual HTTP call via
   ``aiohttp`` and hands the decoded body to the matching ``parse_*``
   function.

All network calls are defensive: timeouts, connection errors, and malformed
responses are caught and logged, degrading gracefully to an empty result
rather than crashing the whole run.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional
from urllib.parse import urlparse

try:
    import aiohttp
except ImportError:  # pragma: no cover - handled at runtime
    aiohttp = None  # type: ignore[assignment]

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
WAYBACK_URL = (
    "http://web.archive.org/cdx/search/cdx"
    "?url=*.{domain}&output=json&collapse=urlkey&fl=original"
)

_HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$")


def _normalize_and_filter(name: str, domain: str) -> Optional[str]:
    """Lowercase, strip wildcard markers, and keep only names that are the
    apex domain or a genuine subdomain of it."""
    name = name.strip().lower().rstrip(".")
    if not name:
        return None
    if name.startswith("*."):
        name = name[2:]
    if name == domain or name.endswith(f".{domain}"):
        if _HOSTNAME_RE.match(name):
            return name
    return None


def parse_crtsh_json(data: Any, domain: str) -> set[str]:
    """Parse crt.sh's JSON array of certificate entries into a set of
    subdomains. Each entry looks like ``{"name_value": "a.example.com\\nb.example.com", ...}``.
    """
    subdomains: set[str] = set()
    if not isinstance(data, list):
        return subdomains

    for entry in data:
        if not isinstance(entry, dict):
            continue
        name_value = entry.get("name_value", "") or ""
        for raw_name in name_value.split("\n"):
            normalized = _normalize_and_filter(raw_name, domain)
            if normalized:
                subdomains.add(normalized)
    return subdomains


def parse_otx_json(data: Any, domain: str) -> set[str]:
    """Parse AlienVault OTX's passive DNS response into a set of subdomains.

    Expected shape::

        {"passive_dns": [{"hostname": "a.example.com", "address": "1.2.3.4", ...}, ...]}
    """
    subdomains: set[str] = set()
    if not isinstance(data, dict):
        return subdomains

    entries = data.get("passive_dns", [])
    if not isinstance(entries, list):
        return subdomains

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        hostname = entry.get("hostname", "") or ""
        normalized = _normalize_and_filter(hostname, domain)
        if normalized:
            subdomains.add(normalized)
    return subdomains


def parse_wayback_json(data: Any, domain: str) -> set[str]:
    """Parse the Wayback Machine CDX API's JSON response into a set of
    subdomains extracted from archived URLs.

    Expected shape (first row is a header)::

        [["original"], ["http://dev.example.com/path"], ["https://api.example.com/"]]
    """
    subdomains: set[str] = set()
    if not isinstance(data, list) or len(data) < 2:
        return subdomains

    rows = data[1:]  # skip header row
    for row in rows:
        if not isinstance(row, list) or not row:
            continue
        url = row[0]
        if not isinstance(url, str):
            continue
        try:
            host = urlparse(url).netloc
        except ValueError:
            continue
        host = host.split(":")[0]  # strip port if present
        normalized = _normalize_and_filter(host, domain)
        if normalized:
            subdomains.add(normalized)
    return subdomains


async def _fetch_json(
    session: "aiohttp.ClientSession",
    url: str,
    timeout: int,
    logger: logging.Logger,
    source_name: str,
) -> Optional[Any]:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            if resp.status != 200:
                logger.warning(
                    "%s returned HTTP %d; continuing without this source.", source_name, resp.status
                )
                return None
            text = await resp.text()
    except Exception as exc:  # noqa: BLE001 - network layer: any failure degrades gracefully
        logger.warning("%s request failed (%s); continuing without this source.", source_name, exc)
        return None

    try:
        return json.loads(text)
    except (ValueError, json.JSONDecodeError):
        logger.warning(
            "%s returned malformed JSON (possibly rate-limited); continuing without this source.",
            source_name,
        )
        return None


async def fetch_crtsh(
    session: "aiohttp.ClientSession", domain: str, timeout: int, logger: logging.Logger
) -> set[str]:
    url = CRTSH_URL.format(domain=domain)
    data = await _fetch_json(session, url, timeout, logger, "crt.sh")
    if data is None:
        return set()
    found = parse_crtsh_json(data, domain)
    logger.info("Passive crt.sh lookup found %d unique subdomain candidate(s).", len(found))
    return found


async def fetch_otx(
    session: "aiohttp.ClientSession", domain: str, timeout: int, logger: logging.Logger
) -> set[str]:
    url = OTX_URL.format(domain=domain)
    data = await _fetch_json(session, url, timeout, logger, "AlienVault OTX")
    if data is None:
        return set()
    found = parse_otx_json(data, domain)
    logger.info("Passive OTX lookup found %d unique subdomain candidate(s).", len(found))
    return found


async def fetch_wayback(
    session: "aiohttp.ClientSession", domain: str, timeout: int, logger: logging.Logger
) -> set[str]:
    url = WAYBACK_URL.format(domain=domain)
    data = await _fetch_json(session, url, timeout, logger, "Wayback Machine CDX")
    if data is None:
        return set()
    found = parse_wayback_json(data, domain)
    logger.info("Passive Wayback Machine lookup found %d unique subdomain candidate(s).", len(found))
    return found
