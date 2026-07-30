"""
DNS resolution layer.

Concurrency model
------------------
HTTP-based passive sources (``sources.py``) use genuine async I/O via
``aiohttp``, since a single event loop can juggle hundreds of in-flight HTTP
requests cheaply.

Raw DNS resolution is different: Python's standard library only exposes
*blocking* DNS calls (``socket.gethostbyname_ex``), and there is no
guaranteed-available, pure-Python, cross-platform async DNS resolver in the
standard library. The natural async alternative, ``aiodns`` (a wrapper
around ``pycares``), ships a C-extension whose prebuilt wheels are not
reliably available on every platform/Python-version combination (notably
recent Windows + newer CPython releases), which would make the tool fail to
install in exactly the environments where users run it from a plain
``pip install``.

Rather than take on that fragile dependency, DNS resolution keeps using a
``ThreadPoolExecutor`` -- but *driven from asyncio* via
``loop.run_in_executor``. This gives the same practical concurrency as a
native async resolver (many outstanding lookups at once, bounded by
``max_workers``) while integrating cleanly with the asyncio-based pipeline
used for the HTTP sources, and keeps the dependency footprint to pure
standard library plus ``dnspython`` (a pure-Python, extremely portable
package) for CNAME lookups, which the stdlib cannot perform at all.
"""

from __future__ import annotations

import asyncio
import logging
import random
import socket
import string
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from typing import Optional

try:
    import dns.exception
    import dns.resolver
except ImportError:  # pragma: no cover - handled at runtime
    dns = None  # type: ignore[assignment]


class RateLimiter:
    """Simple thread-safe rate limiter: caps calls to N per second (0 = unlimited)."""

    def __init__(self, rate: float) -> None:
        self.rate = rate
        self._lock = Lock()
        self._last_call = 0.0

    def wait(self) -> None:
        if self.rate <= 0:
            return
        min_interval = 1.0 / self.rate
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_call
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
            self._last_call = time.monotonic()


def resolve_hostname_sync(hostname: str, rate_limiter: Optional[RateLimiter] = None) -> list[str]:
    """Resolve a hostname to a list of IPv4 addresses. Returns an empty list
    on any resolution failure. Safe to run in a worker thread."""
    if rate_limiter is not None:
        rate_limiter.wait()
    try:
        _, _, ip_list = socket.gethostbyname_ex(hostname)
        return sorted(set(ip_list))
    except socket.gaierror:
        return []
    except socket.herror:
        return []
    except OSError:
        return []


def resolve_cname_sync(hostname: str) -> Optional[str]:
    """Return the CNAME target for ``hostname`` if one exists, else None.
    Requires dnspython; returns None (rather than raising) if it is
    unavailable or the lookup fails for any reason."""
    if dns is None:
        return None
    try:
        answer = dns.resolver.resolve(hostname, "CNAME", lifetime=5.0)
        target = str(answer[0].target).rstrip(".")
        return target.lower()
    except Exception:  # noqa: BLE001 - any DNS failure just means "no CNAME"
        return None


async def resolve_many(
    hostnames: list[str],
    threads: int,
    rate: float,
    logger: Optional[logging.Logger] = None,
) -> dict[str, list[str]]:
    """Resolve every hostname concurrently via a thread pool driven by
    asyncio, returning a mapping of hostname -> list of resolved IPs
    (empty list if unresolved)."""
    if not hostnames:
        return {}

    rate_limiter = RateLimiter(rate)
    loop = asyncio.get_event_loop()
    results: dict[str, list[str]] = {}

    with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
        tasks = {
            loop.run_in_executor(executor, resolve_hostname_sync, host, rate_limiter): host
            for host in hostnames
        }
        for future, host in tasks.items():
            try:
                results[host] = await future
            except Exception as exc:  # noqa: BLE001 - defensive: worker failure
                if logger:
                    logger.debug("Unexpected error resolving %s: %s", host, exc)
                results[host] = []

    return results


async def resolve_cnames(
    hostnames: list[str],
    threads: int,
) -> dict[str, Optional[str]]:
    """Resolve the CNAME record (if any) for each hostname concurrently."""
    if not hostnames:
        return {}

    loop = asyncio.get_event_loop()
    results: dict[str, Optional[str]] = {}

    with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
        tasks = {
            loop.run_in_executor(executor, resolve_cname_sync, host): host for host in hostnames
        }
        for future, host in tasks.items():
            try:
                results[host] = await future
            except Exception:  # noqa: BLE001
                results[host] = None

    return results


def random_nonexistent_labels(domain: str, count: int = 3) -> list[str]:
    """Generate `count` random, extremely-unlikely-to-exist subdomain labels
    under `domain`, used as wildcard-DNS canaries."""
    labels = []
    for _ in range(count):
        token = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        labels.append(f"wc-canary-{token}.{domain}")
    return labels


def detect_wildcard_ip(canary_resolutions: dict[str, list[str]]) -> Optional[str]:
    """Pure decision function: given a mapping of canary-hostname -> resolved
    IP list, decide whether wildcard DNS is in effect.

    Wildcard DNS is flagged when *all* canaries resolved, and they all
    resolved to the exact same single IP (or same IP set). Returns the
    shared IP if wildcard DNS is detected, else None.
    """
    if not canary_resolutions:
        return None

    ip_sets = [frozenset(ips) for ips in canary_resolutions.values()]
    if any(len(s) == 0 for s in ip_sets):
        # At least one canary failed to resolve -> no wildcard.
        return None

    first = ip_sets[0]
    if all(s == first for s in ip_sets):
        # Return a single representative IP (sorted for determinism).
        return sorted(first)[0]
    return None


async def detect_wildcard(domain: str, threads: int, canary_count: int = 3) -> Optional[str]:
    """End-to-end wildcard-DNS detection: resolves `canary_count` random
    nonsense subdomains and applies `detect_wildcard_ip` to the results."""
    canaries = random_nonexistent_labels(domain, canary_count)
    resolved = await resolve_many(canaries, threads, rate=0)
    return detect_wildcard_ip(resolved)


def is_wildcard_false_positive(ips: list[str], wildcard_ip: Optional[str]) -> bool:
    """Return True if `ips` should be filtered out as a wildcard-DNS false
    positive (i.e. it resolves to nothing but the detected wildcard IP)."""
    if wildcard_ip is None or not ips:
        return False
    return set(ips) == {wildcard_ip}
