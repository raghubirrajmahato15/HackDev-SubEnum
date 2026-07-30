"""
Subdomain permutation / mutation engine.

Given a set of already-discovered subdomains, generate plausible variants by
combining the discovered "words" (the leftmost label of each subdomain) with
common prefixes and suffixes seen in real-world naming conventions
(dev-, -staging, -v2, -old, etc.). The output is deterministic (sorted) and
hard-capped so it can never explode into an unbounded resolution workload.
"""

from __future__ import annotations

DEFAULT_CAP = 500

PREFIXES: list[str] = [
    "dev-",
    "staging-",
    "stage-",
    "test-",
    "qa-",
    "uat-",
    "old-",
    "new-",
    "beta-",
    "alpha-",
    "internal-",
    "int-",
    "preprod-",
    "sandbox-",
    "demo-",
]

SUFFIXES: list[str] = [
    "-dev",
    "-staging",
    "-stage",
    "-test",
    "-qa",
    "-uat",
    "-old",
    "-new",
    "-beta",
    "-v1",
    "-v2",
    "-v3",
    "-01",
    "-02",
    "-backup",
    "-internal",
]


def _extract_word(subdomain: str, domain: str) -> str:
    """Return the leftmost label of a subdomain relative to `domain`.

    e.g. _extract_word("api.dev.example.com", "example.com") -> "api.dev"
    which we then further reduce to its first label "api" for mutation
    purposes (mutating the immediate leftmost label is what mirrors typical
    naming schemes like dev-api / api-old, etc.).
    """
    suffix = f".{domain}"
    if subdomain == domain:
        return ""
    if subdomain.endswith(suffix):
        remainder = subdomain[: -len(suffix)]
    else:
        remainder = subdomain
    if not remainder:
        return ""
    return remainder.split(".")[0]


def generate_mutations(
    subdomains: list[str],
    domain: str,
    cap: int = DEFAULT_CAP,
    prefixes: list[str] | None = None,
    suffixes: list[str] | None = None,
) -> list[str]:
    """Generate bounded, deduplicated permutations of the discovered
    subdomains' base words, combined with common prefixes/suffixes.

    The result never contains an entry already present in `subdomains`, is
    sorted for determinism, and is truncated to at most `cap` entries.
    """
    if cap <= 0:
        return []

    prefixes = prefixes if prefixes is not None else PREFIXES
    suffixes = suffixes if suffixes is not None else SUFFIXES

    existing = {s.strip().lower() for s in subdomains}
    words: set[str] = set()
    for sub in subdomains:
        word = _extract_word(sub.strip().lower(), domain)
        if word:
            words.add(word)

    candidates: set[str] = set()
    for word in sorted(words):
        for prefix in prefixes:
            candidates.add(f"{prefix}{word}.{domain}")
        for suffix in suffixes:
            candidates.add(f"{word}{suffix}.{domain}")

    candidates -= existing
    ordered = sorted(candidates)
    return ordered[:cap]
