# HackDev-SubEnum

Subdomain enumeration tool combining passive crt.sh certificate-transparency lookups with active DNS brute-forcing. Part of the **HackDev** open-source cybersecurity toolkit.

HackDev-SubEnum discovers subdomains for a target domain in two complementary ways: it queries [crt.sh](https://crt.sh)'s certificate transparency log JSON API for any subdomain that has ever appeared on a TLS certificate (passive mode), and it brute-forces a wordlist of common subdomain prefixes against the domain's DNS, resolving each candidate with an A-record lookup (active mode). Results from both modes are merged, deduplicated, resolved to their current IP addresses using a multi-threaded resolver, and presented as a clean table or structured JSON.

## Features

- **Passive enumeration** via crt.sh certificate transparency logs — no active traffic sent to the target
- **Active DNS brute-forcing** with a built-in wordlist of ~190 common subdomain prefixes, or your own custom wordlist file
- **Concurrent DNS resolution** using a `ThreadPoolExecutor`, sized by `--threads`
- **IP resolution for every discovered subdomain**, with unresolvable hosts clearly marked
- **Deduplication and alphabetical sorting** of combined results
- **Text and JSON output formats**, suitable for both humans and pipelines
- **Rate limiting** (`--rate`) to control the speed of DNS lookups
- **Graceful degradation** — if crt.sh is unreachable, rate-limited, or returns malformed data, the tool logs a warning and continues with active-only results instead of failing
- **Mode control** via `--passive-only` and `--active-only` flags

## Installation

```bash
git clone https://github.com/raghubirrajmahato15/HackDev-SubEnum.git
cd HackDev-SubEnum
pip install -r requirements.txt
```

Requires Python 3.10+. If `requests` is not installed, active DNS brute-forcing still works — only the passive crt.sh lookup is skipped (with a logged warning).

## Usage

Run both passive and active enumeration (default):

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

Full scan with a capped DNS resolution rate and a request timeout:

```bash
python subenum.py example.com --rate 20 --timeout 15 --format json
```

Example JSON finding:

```json
{
  "subdomain": "api.example.com",
  "ips": ["93.184.216.34"],
  "resolved": true,
  "source": "passive"
}
```

## CLI flag reference

| Flag | Description | Default |
|---|---|---|
| `domain` | Target domain to enumerate (positional, required) | - |
| `-o`, `--output FILE` | Write results to `FILE` instead of stdout | stdout |
| `--format {text,json}` | Output format | `text` |
| `-v`, `--verbose` | Enable verbose (debug) logging | off |
| `--threads N` | Number of concurrent threads for DNS resolution | `20` |
| `--timeout N` | Timeout in seconds for the crt.sh HTTP request | `10` |
| `--rate N` | Max DNS resolutions per second, `0` = unlimited | `0` |
| `--wordlist PATH` | Path to a custom subdomain wordlist file (one prefix per line) | built-in list |
| `--passive-only` | Only perform passive crt.sh lookup | off |
| `--active-only` | Only perform active DNS brute-force | off |
| `--version` | Show the program's version and exit | - |
| `-h`, `--help` | Show help and exit | - |

## Legal

This tool is intended for **authorized security testing only** — against systems you own, or systems for which you have obtained explicit written permission to test. Running subdomain enumeration or DNS brute-forcing against domains you do not own or have not been authorized to test may violate computer misuse laws, terms of service, or other regulations in your jurisdiction. The authors and contributors of HackDev-SubEnum accept no liability for misuse of this tool.
