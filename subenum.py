#!/usr/bin/env python3
"""
HackDev-SubEnum
================
Subdomain enumeration tool combining passive crt.sh certificate-transparency
lookups with active DNS brute-forcing.

Part of the HackDev cybersecurity toolkit.

Legal: For authorized security testing only. Only run this tool against
domains you own or have explicit written permission to test.
"""

from __future__ import annotations

import argparse
import json
import logging
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from threading import Lock
from typing import Optional

try:
    import requests
except ImportError:  # pragma: no cover - handled at runtime
    requests = None  # type: ignore[assignment]

__version__ = "1.0.0"

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"

# Built-in wordlist of ~150 common subdomain prefixes, used when the user
# does not supply a --wordlist file.
DEFAULT_WORDLIST: list[str] = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "webdisk", "ns", "cpanel", "whm", "autodiscover", "autoconfig",
    "m", "imap", "test", "ns5", "ns6", "dev", "staging", "stage", "api", "admin",
    "vpn", "portal", "app", "apps", "beta", "shop", "store", "blog", "forum",
    "support", "help", "docs", "wiki", "git", "gitlab", "github", "jenkins",
    "ci", "cd", "build", "static", "cdn", "assets", "img", "images", "media",
    "video", "download", "downloads", "files", "upload", "uploads", "backup",
    "backups", "old", "new", "beta2", "demo", "sandbox", "preview", "qa", "uat",
    "prod", "production", "internal", "intranet", "extranet", "remote",
    "secure", "ssl", "vpn2", "gateway", "gw", "firewall", "proxy", "cache",
    "db", "database", "sql", "mysql", "postgres", "mongo", "redis", "elastic",
    "kibana", "grafana", "prometheus", "monitor", "monitoring", "status",
    "health", "metrics", "logs", "logging", "syslog", "ldap", "ad", "sso",
    "auth", "login", "signin", "signup", "register", "account", "accounts",
    "user", "users", "profile", "dashboard", "panel", "cp", "console", "cms",
    "wp", "wordpress", "joomla", "drupal", "magento", "shopify", "payment",
    "payments", "pay", "billing", "invoice", "checkout", "cart", "orders",
    "search", "chat", "im", "voip", "sip", "pbx", "call", "conference", "meet",
    "meeting", "zoom", "webinar", "stream", "streaming", "live", "tv", "radio",
    "news", "press", "careers", "jobs", "about", "contact", "info", "legal",
    "privacy", "terms", "faq", "kb", "knowledgebase", "docs2", "developer",
    "developers", "dev2", "sandbox2", "mobile", "m2", "wap", "web", "web2",
    "origin", "edge", "cluster", "node", "node1", "node2", "master", "slave",
    "primary", "secondary", "backup2", "dr", "test2", "test1", "demo2",
]


@dataclass
class SubdomainResult:
    subdomain: str
    ips: list[str] = field(default_factory=list)
    resolved: bool = False
    source: str = "active"  # "passive" or "active"

    def to_dict(self) -> dict:
        return {
            "subdomain": self.subdomain,
            "ips": self.ips,
            "resolved": self.resolved,
            "source": self.source,
        }


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


def setup_logging(verbose: bool) -> logging.Logger:
    logger = logging.getLogger("subenum")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()
    handler = logging.StreamHandler(sys.stderr)
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    handler.setFormatter(logging.Formatter(fmt, datefmt="%H:%M:%S"))
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def passive_crtsh_lookup(domain: str, timeout: int, logger: logging.Logger) -> set[str]:
    """Query crt.sh's JSON API for certificate transparency records and
    return a deduplicated set of subdomains (wildcards stripped)."""
    if requests is None:
        logger.warning(
            "The 'requests' library is not installed; skipping passive crt.sh lookup."
        )
        return set()

    url = CRTSH_URL.format(domain=domain)
    subdomains: set[str] = set()

    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
    except requests.exceptions.Timeout:
        logger.warning("crt.sh request timed out after %ss; continuing with active-only results.", timeout)
        return subdomains
    except requests.exceptions.ConnectionError:
        logger.warning("Could not connect to crt.sh (unreachable); continuing with active-only results.")
        return subdomains
    except requests.exceptions.HTTPError as exc:
        logger.warning("crt.sh returned an HTTP error (%s); continuing with active-only results.", exc)
        return subdomains
    except requests.exceptions.RequestException as exc:
        logger.warning("crt.sh request failed (%s); continuing with active-only results.", exc)
        return subdomains

    try:
        data = response.json()
    except (ValueError, json.JSONDecodeError):
        logger.warning("crt.sh returned malformed JSON (possibly rate-limited); continuing with active-only results.")
        return subdomains

    if not isinstance(data, list):
        logger.warning("Unexpected crt.sh response format; continuing with active-only results.")
        return subdomains

    for entry in data:
        name_value = entry.get("name_value", "") if isinstance(entry, dict) else ""
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if not name:
                continue
            if name.startswith("*."):
                name = name[2:]
            if name.endswith(f".{domain}") or name == domain:
                subdomains.add(name)

    logger.info("Passive crt.sh lookup found %d unique subdomain candidate(s).", len(subdomains))
    return subdomains


def load_wordlist(path: Optional[str], logger: logging.Logger) -> list[str]:
    if not path:
        logger.debug("Using built-in wordlist with %d entries.", len(DEFAULT_WORDLIST))
        return list(DEFAULT_WORDLIST)

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            words = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
        logger.info("Loaded %d entries from wordlist file '%s'.", len(words), path)
        return words
    except FileNotFoundError:
        logger.warning("Wordlist file '%s' not found; falling back to built-in wordlist.", path)
        return list(DEFAULT_WORDLIST)
    except OSError as exc:
        logger.warning("Could not read wordlist file '%s' (%s); falling back to built-in wordlist.", path, exc)
        return list(DEFAULT_WORDLIST)


def resolve_hostname(hostname: str, rate_limiter: RateLimiter) -> list[str]:
    """Resolve a hostname to a list of IPv4 addresses using socket.gethostbyname_ex.
    Returns an empty list if resolution fails."""
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


def active_brute_force(
    domain: str,
    wordlist: list[str],
    threads: int,
    rate: float,
    logger: logging.Logger,
) -> set[str]:
    """Return the set of candidate subdomains from the wordlist that
    successfully resolve via DNS A-record lookup."""
    candidates = [f"{word}.{domain}" for word in wordlist]
    rate_limiter = RateLimiter(rate)
    found: set[str] = set()

    logger.info("Starting active DNS brute-force with %d candidates using %d thread(s).", len(candidates), threads)

    with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
        future_to_host = {
            executor.submit(resolve_hostname, host, rate_limiter): host for host in candidates
        }
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            try:
                ips = future.result()
            except Exception as exc:  # noqa: BLE001 - defensive: thread pool worker failure
                logger.debug("Unexpected error resolving %s: %s", host, exc)
                continue
            if ips:
                found.add(host)
                logger.debug("Resolved %s -> %s", host, ips)

    logger.info("Active brute-force found %d resolvable subdomain(s).", len(found))
    return found


def resolve_all(
    subdomains: dict[str, str],
    threads: int,
    rate: float,
    logger: logging.Logger,
) -> list[SubdomainResult]:
    """Resolve every discovered subdomain to its IP(s), tagging source and
    resolved status. `subdomains` maps subdomain -> source label."""
    rate_limiter = RateLimiter(rate)
    results: list[SubdomainResult] = []

    with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
        future_to_host = {
            executor.submit(resolve_hostname, host, rate_limiter): host for host in subdomains
        }
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            source = subdomains[host]
            try:
                ips = future.result()
            except Exception as exc:  # noqa: BLE001 - defensive: thread pool worker failure
                logger.debug("Unexpected error resolving %s: %s", host, exc)
                ips = []
            results.append(
                SubdomainResult(subdomain=host, ips=ips, resolved=bool(ips), source=source)
            )

    results.sort(key=lambda r: r.subdomain)
    return results


def print_text_output(results: list[SubdomainResult]) -> None:
    if not results:
        print("No subdomains found.")
        return

    name_width = max(len(r.subdomain) for r in results) + 2
    name_width = max(name_width, len("SUBDOMAIN") + 2)

    print(f"{'SUBDOMAIN':<{name_width}}{'SOURCE':<10}{'STATUS/IP(S)'}")
    print("-" * (name_width + 10 + 30))
    for r in results:
        status = ", ".join(r.ips) if r.resolved else "UNRESOLVED"
        print(f"{r.subdomain:<{name_width}}{r.source:<10}{status}")

    resolved_count = sum(1 for r in results if r.resolved)
    print()
    print(f"Total: {len(results)} subdomain(s), {resolved_count} resolved, {len(results) - resolved_count} unresolved.")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="subenum",
        description=(
            "HackDev-SubEnum: subdomain enumeration combining passive crt.sh "
            "certificate-transparency lookups with active DNS brute-forcing."
        ),
    )
    parser.add_argument("domain", help="Target domain to enumerate (e.g. example.com)")
    parser.add_argument(
        "-o", "--output", metavar="FILE", help="Write results to FILE instead of stdout"
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose (debug) logging"
    )
    parser.add_argument(
        "--threads", type=int, default=20, help="Number of concurrent threads for DNS resolution (default: 20)"
    )
    parser.add_argument(
        "--timeout", type=int, default=10, help="Timeout in seconds for the crt.sh HTTP request (default: 10)"
    )
    parser.add_argument(
        "--rate", type=float, default=0, help="Max DNS resolutions per second, 0 = unlimited (default: 0)"
    )
    parser.add_argument(
        "--wordlist", metavar="PATH", help="Path to a custom subdomain wordlist file (one prefix per line)"
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--passive-only", action="store_true", help="Only perform passive crt.sh lookup (skip DNS brute-force)"
    )
    mode_group.add_argument(
        "--active-only", action="store_true", help="Only perform active DNS brute-force (skip crt.sh lookup)"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    logger = setup_logging(args.verbose)

    domain = args.domain.strip().lower()
    if not domain:
        logger.error("A target domain is required.")
        return 1

    subdomain_sources: dict[str, str] = {}

    if not args.active_only:
        passive_results = passive_crtsh_lookup(domain, args.timeout, logger)
        for sub in passive_results:
            subdomain_sources[sub] = "passive"
    else:
        logger.info("Skipping passive crt.sh lookup (--active-only specified).")

    if not args.passive_only:
        wordlist = load_wordlist(args.wordlist, logger)
        active_results = active_brute_force(domain, wordlist, args.threads, args.rate, logger)
        for sub in active_results:
            # Active brute-force results are already confirmed resolvable;
            # only overwrite source if not already found passively.
            subdomain_sources.setdefault(sub, "active")
    else:
        logger.info("Skipping active DNS brute-force (--passive-only specified).")

    if not subdomain_sources:
        logger.warning("No subdomains discovered for %s.", domain)

    logger.info("Resolving %d unique discovered subdomain(s)...", len(subdomain_sources))
    results = resolve_all(subdomain_sources, args.threads, args.rate, logger)

    if args.format == "json":
        output_text = json.dumps([r.to_dict() for r in results], indent=2)
    else:
        import io

        buf = io.StringIO()
        real_stdout = sys.stdout
        sys.stdout = buf
        try:
            print_text_output(results)
        finally:
            sys.stdout = real_stdout
        output_text = buf.getvalue()

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(output_text)
                if not output_text.endswith("\n"):
                    fh.write("\n")
            logger.info("Results written to %s", args.output)
        except OSError as exc:
            logger.error("Failed to write output file '%s': %s", args.output, exc)
            print(output_text)
    else:
        print(output_text)

    return 0


if __name__ == "__main__":
    sys.exit(main())
