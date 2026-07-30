# HackDev-SubEnum

[![Test](https://github.com/raghubirrajmahato15/HackDev-SubEnum/actions/workflows/test.yml/badge.svg)](https://github.com/raghubirrajmahato15/HackDev-SubEnum/actions/workflows/test.yml)

Advanced subdomain enumeration combining multiple passive intelligence sources, active DNS
brute-forcing, wildcard-DNS detection, a bounded permutation/mutation engine, and CNAME-based
subdomain-takeover heuristics. Part of the **HackDev** open-source cybersecurity toolkit.

## Features

- **Three passive sources, run concurrently**: [crt.sh](https://crt.sh) certificate-transparency
  logs, [AlienVault OTX](https://otx.alienvault.com) passive DNS, and the Wayback Machine CDX API —
  merged and deduplicated
- **Active DNS brute-forcing** with a built-in wordlist of ~190 common subdomain prefixes, or your
  own custom wordlist file
- **Wildcard-DNS detection**: resolves random canary subdomains first; if they all resolve to the
  same IP, brute-force/mutation hits matching that IP are filtered out as false positives instead
  of being reported as real subdomains
- **Bounded mutation/permutation engine**: generates plausible variants of discovered subdomains
  (`dev-api`, `api-staging`, `api-v2`, etc.) and resolves those too, capped at a configurable limit
  so it can never explode into an unbounded workload
- **CNAME-based subdomain-takeover heuristic**: flags subdomains whose CNAME points at a
  known takeover-prone provider (GitHub Pages, Heroku, S3, Azure Web Apps, etc.) when the target
  either doesn't resolve or serves that provider's "unclaimed resource" page
- **Concurrent DNS resolution** driven from asyncio via a thread pool, sized by `--threads`
- **Text and JSON output formats**, suitable for both humans and pipelines
- **Rate limiting** (`--rate`) and **mode control** (`--passive-only` / `--active-only`,
  per-source `--no-crtsh` / `--no-otx` / `--no-wayback`, `--no-mutate`, `--no-wildcard-check`,
  `--no-takeover-check`)
- **Graceful degradation** — any single passive source being unreachable, rate-limited, or
  returning malformed data is logged as a warning; the run continues with everything else

## Installation

```bash
git clone https://github.com/raghubirrajmahato15/HackDev-SubEnum.git
cd HackDev-SubEnum
pip install -r requirements.txt
```

Requires Python 3.10+, `aiohttp` (passive HTTP sources), and `dnspython` (CNAME lookups for the
takeover check). Active DNS brute-force resolution itself uses only the standard library.

## Usage

Full pipeline (all passive sources + active brute-force + mutation + wildcard/takeover checks):

```bash
python subenum.py example.com
```

Passive-only, JSON output written to a file:

```bash
python subenum.py example.com --passive-only --format json -o results.json
```

Active-only brute-force with a custom wordlist, 50 threads, verbose logging:

```bash
python subenum.py example.com --active-only --wordlist my_wordlist.txt --threads 50 -v
```

Disable the mutation engine and takeover checks, cap DNS resolution rate:

```bash
python subenum.py example.com --no-mutate --no-takeover-check --rate 20
```

Example JSON finding, including a flagged takeover:

```json
{
  "subdomain": "old-app.example.com",
  "ips": [],
  "resolved": false,
  "source": "passive-crtsh",
  "cname": "deleted-app.herokuapp.com",
  "wildcard_filtered": false,
  "takeover": {
    "service": "herokuapp.com",
    "cname_target": "deleted-app.herokuapp.com",
    "evidence": "CNAME target 'deleted-app.herokuapp.com' does not resolve (NXDOMAIN) while 'old-app.example.com' still has a dangling CNAME to it."
  }
}
```

## CLI flag reference

| Flag | Description | Default |
|---|---|---|
| `domain` | Target domain to enumerate (positional, required) | - |
| `-o`, `--output FILE` | Write results to `FILE` instead of stdout | stdout |
| `--format {text,json}` | Output format | `text` |
| `-v`, `--verbose` | Enable verbose (debug) logging | off |
| `--threads N` | Concurrency level for DNS resolution | `20` |
| `--timeout N` | Timeout in seconds for HTTP requests | `10` |
| `--rate N` | Max DNS resolutions per second, `0` = unlimited | `0` |
| `--wordlist PATH` | Path to a custom subdomain wordlist file | built-in list |
| `--passive-only` / `--active-only` | Restrict to one mode (mutually exclusive) | off |
| `--no-crtsh` / `--no-otx` / `--no-wayback` | Disable an individual passive source | all enabled |
| `--mutate` / `--no-mutate` | Toggle the mutation/permutation engine | on |
| `--mutate-cap N` | Max mutation candidates generated/resolved | `500` |
| `--wildcard-check` / `--no-wildcard-check` | Toggle wildcard-DNS detection | on |
| `--takeover-check` / `--no-takeover-check` | Toggle CNAME-takeover heuristic checks | on |
| `--version` | Show the program's version and exit | - |

## Project layout

```
subenum.py               Thin CLI entrypoint
hackdev_subenum/
  models.py               SubdomainResult / TakeoverFinding data models
  sources.py               Passive source fetch + pure JSON-parsing functions (crt.sh/OTX/Wayback)
  resolver.py               DNS resolution, wildcard detection, rate limiting
  mutate.py                 Bounded subdomain permutation/mutation engine
  takeover.py               CNAME-based subdomain-takeover heuristic
  cli.py                     argparse wiring, pipeline orchestration, output formatting
tests/                     pytest suite (see below)
```

## Testing

```bash
pip install -r requirements-dev.txt
pytest -q
```

Every passive source's JSON parser is unit-tested against realistic fixture blobs (no live network
calls needed for these). The mutation engine, wildcard-detection decision logic, and
takeover-matching heuristic are all pure functions and fully covered with crafted examples. The
resolver tests include real (non-mocked) DNS resolutions of `localhost` to prove the resolution
layer genuinely works end-to-end, not just against mocks.

## Legal

This tool is intended for **authorized security testing only** — against systems you own, or
systems for which you have obtained explicit written permission to test. Running subdomain
enumeration or DNS brute-forcing against domains you do not own or have not been authorized to test
may violate computer misuse laws, terms of service, or other regulations in your jurisdiction. The
authors and contributors of HackDev-SubEnum accept no liability for misuse of this tool.
