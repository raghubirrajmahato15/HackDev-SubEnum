#!/usr/bin/env python3
"""
HackDev-SubEnum
================
Advanced subdomain enumeration combining multiple passive intelligence sources
(crt.sh, AlienVault OTX, Wayback Machine), active DNS brute-forcing, wildcard-DNS
detection, a bounded permutation/mutation engine, and CNAME-based subdomain-takeover
heuristics.

Thin CLI entrypoint - the actual implementation lives in the hackdev_subenum/
package (sources.py, resolver.py, mutate.py, takeover.py, models.py, cli.py).

Legal: For authorized security testing only. Only run this tool against
domains you own or have explicit written permission to test.
"""
import sys

from hackdev_subenum.cli import main

if __name__ == "__main__":
    sys.exit(main())
