"""
Command-line interface and orchestration for HackDev-SubEnum.

Pipeline
--------
1. Passive recon: crt.sh + AlienVault OTX + Wayback Machine CDX (parallel
   ``aiohttp`` requests), merged and deduplicated.
2. Active DNS brute-force against a wordlist.
3. Wildcard-DNS detection (canary resolution) so brute-force false
   positives can be filtered.
4. Mutation engine: bounded permutations of discovered words, resolved the
   same way as the brute-force candidates.
5. Resolve every unique candidate, filter wildcard false positives.
6. CNAME lookup + subdomain-takeover heuristic on resolved hosts.
7. Render as text or JSON, optionally to a file.
"""

from __future__ import annotations

import argparse
import asyncio
import io
import json
import logging
import sys
from typing import Optional

from . import __version__
from .models import SubdomainResult
from .mutate import DEFAULT_CAP, generate_mutations
from .resolver import (
    detect_wildcard,
    is_wildcard_false_positive,
    resolve_cnames,
    resolve_many,
)
from .sources import fetch_crtsh, fetch_otx, fetch_wayback
from .takeover import evaluate_takeover

try:
    import aiohttp
except ImportError:  # pragma: no cover
    aiohttp = None  # type: ignore[assignment]

# Built-in wordlist of common subdomain prefixes, used when the user does
# not supply a --wordlist file.
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


async def _run_passive_sources(
    domain: str,
    timeout: int,
    logger: logging.Logger,
    use_crtsh: bool,
    use_otx: bool,
    use_wayback: bool,
) -> dict[str, str]:
    """Run all enabled passive sources concurrently, returning
    subdomain -> source-label, preferring the first source that found it."""
    sources_found: dict[str, str] = {}
    if aiohttp is None:
        logger.warning("aiohttp is not installed; skipping all passive sources.")
        return sources_found

    async with aiohttp.ClientSession() as session:
        jobs = []
        labels = []
        if use_crtsh:
            jobs.append(fetch_crtsh(session, domain, timeout, logger))
            labels.append("passive-crtsh")
        if use_otx:
            jobs.append(fetch_otx(session, domain, timeout, logger))
            labels.append("passive-otx")
        if use_wayback:
            jobs.append(fetch_wayback(session, domain, timeout, logger))
            labels.append("passive-wayback")

        if not jobs:
            return sources_found

        results = await asyncio.gather(*jobs, return_exceptions=True)

    for label, result in zip(labels, results):
        if isinstance(result, Exception):
            logger.warning("%s source raised an unexpected error: %s", label, result)
            continue
        for sub in result:
            sources_found.setdefault(sub, label)

    return sources_found


async def _fetch_body(url: str, timeout: int, logger: logging.Logger) -> str:
    if aiohttp is None:
        return ""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=timeout), allow_redirects=True
            ) as resp:
                return await resp.text(errors="ignore")
    except Exception as exc:  # noqa: BLE001 - best-effort corroborating evidence only
        logger.debug("Could not fetch body for takeover check on %s: %s", url, exc)
        return ""


async def run_pipeline(args: argparse.Namespace, logger: logging.Logger) -> list[SubdomainResult]:
    domain = args.domain

    subdomain_sources: dict[str, str] = {}

    if not args.active_only:
        subdomain_sources.update(
            await _run_passive_sources(
                domain,
                args.timeout,
                logger,
                use_crtsh=not args.no_crtsh,
                use_otx=not args.no_otx,
                use_wayback=not args.no_wayback,
            )
        )
    else:
        logger.info("Skipping passive sources (--active-only specified).")

    active_candidates: list[str] = []
    if not args.passive_only:
        wordlist = load_wordlist(args.wordlist, logger)
        active_candidates = [f"{word}.{domain}" for word in wordlist]
        logger.info(
            "Prepared %d active brute-force candidate(s) using %d thread(s).",
            len(active_candidates),
            args.threads,
        )
    else:
        logger.info("Skipping active DNS brute-force (--passive-only specified).")

    # Wildcard DNS detection, run before we trust any brute-force / mutation hit.
    wildcard_ip = None
    if args.wildcard_check and not args.passive_only:
        wildcard_ip = await detect_wildcard(domain, args.threads)
        if wildcard_ip:
            logger.warning(
                "Wildcard DNS detected: random canary subdomains all resolve to %s. "
                "Brute-force/mutation hits matching this IP will be filtered.",
                wildcard_ip,
            )

    # Resolve passive + active candidates together first, since mutation needs
    # the passive/active word list as its seed.
    first_pass_hosts = sorted(set(subdomain_sources) | set(active_candidates))
    first_pass_resolutions = await resolve_many(first_pass_hosts, args.threads, args.rate, logger)

    for host in active_candidates:
        if first_pass_resolutions.get(host):
            subdomain_sources.setdefault(host, "active")

    mutation_candidates: list[str] = []
    if args.mutate:
        seed_words = sorted(set(subdomain_sources) | {h for h, ips in first_pass_resolutions.items() if ips})
        mutation_candidates = generate_mutations(seed_words, domain, cap=args.mutate_cap)
        logger.info(
            "Generated %d bounded mutation candidate(s) (cap=%d).",
            len(mutation_candidates),
            args.mutate_cap,
        )

    all_hosts = sorted(set(first_pass_resolutions) | set(mutation_candidates))
    remaining = [h for h in mutation_candidates if h not in first_pass_resolutions]
    if remaining:
        mutation_resolutions = await resolve_many(remaining, args.threads, args.rate, logger)
    else:
        mutation_resolutions = {}

    final_resolutions: dict[str, list[str]] = {**first_pass_resolutions, **mutation_resolutions}
    for host in mutation_candidates:
        if final_resolutions.get(host):
            subdomain_sources.setdefault(host, "mutation")

    results: list[SubdomainResult] = []
    resolved_hosts_for_cname: list[str] = []

    for host in all_hosts:
        ips = final_resolutions.get(host, [])
        source = subdomain_sources.get(host, "active" if host in active_candidates else "mutation")
        filtered = args.wildcard_check and is_wildcard_false_positive(ips, wildcard_ip)
        resolved = bool(ips) and not filtered
        result = SubdomainResult(
            subdomain=host,
            ips=[] if filtered else ips,
            resolved=resolved,
            source=source,
            wildcard_filtered=filtered,
        )
        results.append(result)
        if resolved:
            resolved_hosts_for_cname.append(host)

    if args.takeover_check and resolved_hosts_for_cname:
        logger.info("Checking %d resolved subdomain(s) for CNAME-based takeover risk...", len(resolved_hosts_for_cname))
        cnames = await resolve_cnames(resolved_hosts_for_cname, args.threads)

        by_host = {r.subdomain: r for r in results}
        for host, cname in cnames.items():
            if not cname:
                continue
            by_host[host].cname = cname

            from .takeover import matches_vulnerable_service

            if matches_vulnerable_service(cname) is None:
                continue

            target_resolution = await resolve_many([cname], args.threads, args.rate, logger)
            cname_resolves = bool(target_resolution.get(cname))
            body = ""
            if cname_resolves:
                body = await _fetch_body(f"http://{host}/", args.timeout, logger)

            finding = evaluate_takeover(host, cname, cname_resolves, body)
            if finding:
                by_host[host].takeover = finding
                logger.warning(
                    "Possible subdomain takeover: %s -> CNAME %s (%s)",
                    host,
                    finding.cname_target,
                    finding.evidence,
                )

    results.sort(key=lambda r: r.subdomain)
    return results


def print_text_output(results: list[SubdomainResult]) -> str:
    buf = io.StringIO()
    if not results:
        buf.write("No subdomains found.\n")
        return buf.getvalue()

    name_width = max(len(r.subdomain) for r in results) + 2
    name_width = max(name_width, len("SUBDOMAIN") + 2)

    buf.write(f"{'SUBDOMAIN':<{name_width}}{'SOURCE':<16}{'STATUS/IP(S)'}\n")
    buf.write("-" * (name_width + 16 + 40) + "\n")
    for r in results:
        if r.wildcard_filtered:
            status = "FILTERED (wildcard DNS)"
        elif r.resolved:
            status = ", ".join(r.ips)
        else:
            status = "UNRESOLVED"
        buf.write(f"{r.subdomain:<{name_width}}{r.source:<16}{status}\n")
        if r.takeover:
            buf.write(
                f"{'':<{name_width}}{'':<16}!! POSSIBLE TAKEOVER via {r.takeover.service} "
                f"(CNAME -> {r.takeover.cname_target})\n"
            )

    resolved_count = sum(1 for r in results if r.resolved)
    filtered_count = sum(1 for r in results if r.wildcard_filtered)
    takeover_count = sum(1 for r in results if r.takeover)
    buf.write("\n")
    buf.write(
        f"Total: {len(results)} subdomain(s), {resolved_count} resolved, "
        f"{len(results) - resolved_count - filtered_count} unresolved, "
        f"{filtered_count} filtered (wildcard), {takeover_count} possible takeover(s).\n"
    )
    return buf.getvalue()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="subenum",
        description=(
            "HackDev-SubEnum: advanced subdomain enumeration combining multiple "
            "passive sources (crt.sh, AlienVault OTX, Wayback Machine), active DNS "
            "brute-forcing, wildcard-DNS detection, a bounded mutation engine, and "
            "CNAME-based subdomain-takeover heuristics."
        ),
    )
    parser.add_argument("domain", help="Target domain to enumerate (e.g. example.com)")
    parser.add_argument("-o", "--output", metavar="FILE", help="Write results to FILE instead of stdout")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format (default: text)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose (debug) logging")
    parser.add_argument(
        "--threads", type=int, default=20, help="Concurrency level for DNS resolution (default: 20)"
    )
    parser.add_argument(
        "--timeout", type=int, default=10, help="Timeout in seconds for HTTP requests (default: 10)"
    )
    parser.add_argument(
        "--rate", type=float, default=0, help="Max DNS resolutions per second, 0 = unlimited (default: 0)"
    )
    parser.add_argument("--wordlist", metavar="PATH", help="Path to a custom subdomain wordlist file")

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--passive-only", action="store_true", help="Only perform passive lookups (skip DNS brute-force/mutation)"
    )
    mode_group.add_argument(
        "--active-only", action="store_true", help="Only perform active DNS brute-force (skip passive sources)"
    )

    parser.add_argument("--no-crtsh", action="store_true", help="Disable the crt.sh passive source")
    parser.add_argument("--no-otx", action="store_true", help="Disable the AlienVault OTX passive source")
    parser.add_argument("--no-wayback", action="store_true", help="Disable the Wayback Machine CDX passive source")

    parser.add_argument(
        "--mutate", dest="mutate", action="store_true", default=True, help="Enable the mutation/permutation engine (default: on)"
    )
    parser.add_argument(
        "--no-mutate", dest="mutate", action="store_false", help="Disable the mutation/permutation engine"
    )
    parser.add_argument(
        "--mutate-cap",
        type=int,
        default=DEFAULT_CAP,
        help=f"Maximum number of mutation candidates to generate/resolve (default: {DEFAULT_CAP})",
    )

    parser.add_argument(
        "--wildcard-check",
        dest="wildcard_check",
        action="store_true",
        default=True,
        help="Enable wildcard-DNS detection and false-positive filtering (default: on)",
    )
    parser.add_argument(
        "--no-wildcard-check", dest="wildcard_check", action="store_false", help="Disable wildcard-DNS detection"
    )

    parser.add_argument(
        "--takeover-check",
        dest="takeover_check",
        action="store_true",
        default=True,
        help="Enable CNAME-based subdomain-takeover heuristic checks (default: on)",
    )
    parser.add_argument(
        "--no-takeover-check", dest="takeover_check", action="store_false", help="Disable takeover checks"
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
    args.domain = domain

    try:
        results = asyncio.run(run_pipeline(args, logger))
    except KeyboardInterrupt:
        logger.warning("Interrupted by user.")
        return 130

    if not results:
        logger.warning("No subdomains discovered for %s.", domain)

    if args.format == "json":
        output_text = json.dumps([r.to_dict() for r in results], indent=2)
    else:
        output_text = print_text_output(results)

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
