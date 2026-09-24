#!/usr/bin/env python3
"""
dns_gen.py - Async DNS traffic generator for FortiGate labs.

Fires large volumes of DNS queries to exercise FortiGate **DNS filtering** and
**Botnet C&C / DGA detection**:

  * DGA (Domain Generation Algorithm) domains - high-entropy and dictionary-style,
    the way real botnet families (Conficker, CryptoLocker, matsnu, ...) beacon.
    Most resolve to NXDOMAIN, which is exactly the signal DGA detection watches for.
  * Suspicious / category domains from config (DNS-filter test).
  * Benign domains for baseline.

Detects blocking two ways:
  * NXDOMAIN vs. resolved.
  * Responses pointing at a FortiGuard block/sinkhole IP (configurable) -> "blocked".

Uses aiodns (c-ares) for true async resolution at scale. Queries go to whatever
DNS server the OS is configured to use - i.e. through the FortiGate.

Standalone:
    python dns_gen.py --dga-count 500 --concurrency 300 -v
Or imported by web_gen.py for an integrated DNS phase.
"""

import argparse
import asyncio
import hashlib
import json
import random
import string
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

try:
    import aiodns
except ImportError:
    aiodns = None

# aiodns/pycares needs a selector loop on Windows; aiohttp is fine on it too.
# (Silence the 3.16 deprecation of the policy API - the selector loop itself stays.)
if sys.platform == "win32":
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


# FortiGuard DNS filter redirects blocked lookups to these portal IPs by default.
DEFAULT_BLOCK_IPS = ["208.91.112.55", "208.91.112.52", "208.91.112.53"]

DGA_TLDS = [".com", ".net", ".org", ".info", ".biz", ".ru", ".cn", ".xyz",
            ".top", ".club", ".online", ".site", ".su", ".cc", ".ws"]

# Small word pool for dictionary-style DGAs (matsnu / suppobox family look).
DGA_WORDS = [
    "time", "market", "power", "green", "north", "storm", "iron", "silver",
    "quick", "silent", "hidden", "broken", "frozen", "golden", "crimson",
    "shadow", "signal", "vector", "matrix", "cipher", "packet", "kernel",
    "orbit", "nova", "delta", "echo", "flux", "grid", "haze", "jolt",
    "loop", "mesh", "node", "pulse", "rift", "surge", "tide", "vault",
]


@dataclass
class DnsStats:
    total: int = 0
    resolved: int = 0
    nxdomain: int = 0
    blocked: int = 0
    errors: int = 0
    per_source: dict = field(default_factory=lambda: defaultdict(lambda: defaultdict(int)))


# --------------------------------------------------------------------------- #
# DGA generators
# --------------------------------------------------------------------------- #

def gen_random_dga(count, min_len=12, max_len=22, tlds=None, rng=None):
    """High-entropy random-looking domains (conficker/necurs style)."""
    rng = rng or random
    tlds = tlds or DGA_TLDS
    out = []
    for _ in range(count):
        length = rng.randint(min_len, max_len)
        label = "".join(rng.choice(string.ascii_lowercase + string.digits)
                         for _ in range(length))
        out.append(label + rng.choice(tlds))
    return out


def gen_date_seeded_dga(count, seed_date=None, tlds=None):
    """
    Deterministic, date-seeded domains - the way many real DGAs derive the day's
    rendezvous list from the current date. Same date -> same domains, so repeat
    runs hit the same names (and the same NXDOMAIN pattern) the way a botnet would.
    """
    tlds = tlds or DGA_TLDS
    seed_date = seed_date or date.today()
    base = f"{seed_date.year}-{seed_date.month}-{seed_date.day}"
    out = []
    for i in range(count):
        h = hashlib.md5(f"{base}-{i}".encode()).hexdigest()
        # Map hex to a-z to look like a letter-only DGA label.
        label = "".join(chr(ord("a") + (int(c, 16) % 26)) for c in h[:16])
        tld = tlds[int(h[16:18], 16) % len(tlds)]
        out.append(label + tld)
    return out


def gen_dictionary_dga(count, tlds=None, rng=None):
    """Lower-entropy dictionary-word domains (matsnu/suppobox style)."""
    rng = rng or random
    tlds = tlds or DGA_TLDS
    out = []
    for _ in range(count):
        n = rng.randint(2, 3)
        label = "".join(rng.choice(DGA_WORDS) for _ in range(n))
        if rng.random() < 0.3:
            label += str(rng.randint(1, 999))
        out.append(label + rng.choice(tlds))
    return out


def build_dga_domains(dga_cfg, rng=None):
    """Build the full DGA list from a config dict."""
    if not dga_cfg.get("enabled", True):
        return []
    count = dga_cfg.get("count", 200)
    tlds = dga_cfg.get("tlds") or DGA_TLDS
    min_len = dga_cfg.get("min_len", 12)
    max_len = dga_cfg.get("max_len", 22)
    # Split the requested count across the three styles.
    n_rand = count // 2
    n_date = count // 4
    n_dict = count - n_rand - n_date
    domains = []
    domains += gen_random_dga(n_rand, min_len, max_len, tlds, rng)
    domains += gen_date_seeded_dga(n_date, tlds=tlds)
    domains += gen_dictionary_dga(n_dict, tlds, rng)
    return domains


# --------------------------------------------------------------------------- #
# Resolution
# --------------------------------------------------------------------------- #

async def resolve_one(resolver, sem, source, domain, record_types, block_ips,
                      stats, verbose):
    async with sem:
        stats.total += 1
        got_answer = False
        blocked = False
        errored = False
        for rtype in record_types:
            try:
                result = await resolver.query(domain, rtype)
                got_answer = True
                # A/AAAA results have .host; check for FortiGuard block IPs.
                for rec in (result if isinstance(result, list) else [result]):
                    host = getattr(rec, "host", None)
                    if host and host in block_ips:
                        blocked = True
            except aiodns.error.DNSError as exc:
                code = exc.args[0] if exc.args else None
                # 4 == ARES_ENOTFOUND (NXDOMAIN); 1 == ENODATA. Others = real error.
                if code in (1, 4):
                    pass  # no record of this type; not an error per se
                else:
                    errored = True
            except Exception:  # noqa: BLE001
                errored = True

        if blocked:
            stats.blocked += 1
            stats.per_source[source]["blocked"] += 1
            tag = "BLOCK"
        elif got_answer:
            stats.resolved += 1
            stats.per_source[source]["resolved"] += 1
            tag = "resolv"
        elif errored:
            stats.errors += 1
            stats.per_source[source]["error"] += 1
            tag = "err"
        else:
            stats.nxdomain += 1
            stats.per_source[source]["nxdomain"] += 1
            tag = "NXDOM"
        if verbose:
            print(f"[{tag:6}] {source:20} {domain}")


def build_domain_list(dns_cfg, dga_count=None, rng=None):
    """Return list of (source, domain) from the dns config section."""
    domains = []
    dga_cfg = dict(dns_cfg.get("dga", {}))
    if dga_count is not None:
        dga_cfg["count"] = dga_count
        dga_cfg["enabled"] = True
    for d in build_dga_domains(dga_cfg, rng):
        domains.append(("dga", d))
    for d in dns_cfg.get("suspicious_domains", []):
        domains.append(("suspicious", d))
    for d in dns_cfg.get("benign_domains", []):
        domains.append(("benign", d))
    return domains


def _make_resolvers(timeout, servers, source_ips):
    """One resolver per source IP (bound via pycares local_ip); [None] = default."""
    ips = source_ips or [None]
    resolvers = []
    for ip in ips:
        kwargs = {"timeout": timeout, "tries": 1}
        if ip:
            kwargs["local_ip"] = ip  # pycares binds queries to this source address
        r = aiodns.DNSResolver(**kwargs)
        if servers:
            r.nameservers = servers
        resolvers.append(r)
    return resolvers


async def run_dns_phase(dns_cfg, concurrency=200, timeout=5.0, dga_count=None,
                        verbose=False, stats=None, rng=None, servers=None,
                        source_ips=None, extra_domains=None):
    """Resolve the whole domain list once. Returns DnsStats."""
    if aiodns is None:
        print("aiodns not installed - skipping DNS phase. pip install aiodns")
        return stats or DnsStats()

    stats = stats or DnsStats()
    domains = build_domain_list(dns_cfg, dga_count=dga_count, rng=rng)
    if extra_domains:
        domains = domains + list(extra_domains)  # e.g. threat-feed domains
    if not domains:
        return stats

    record_types = dns_cfg.get("record_types", ["A"])
    block_ips = set(dns_cfg.get("block_ips", DEFAULT_BLOCK_IPS))

    resolvers = _make_resolvers(timeout, servers, source_ips)
    sem = asyncio.Semaphore(concurrency)
    tasks = [
        asyncio.create_task(
            resolve_one(resolvers[i % len(resolvers)], sem, src, dom,
                        record_types, block_ips, stats, verbose)
        )
        for i, (src, dom) in enumerate(domains)
    ]
    await asyncio.gather(*tasks)
    return stats


def print_dns_report(stats: DnsStats):
    print("\n" + "=" * 70)
    print("DNS RESULTS")
    print("=" * 70)
    print(f"  total queries : {stats.total}")
    print(f"  resolved      : {stats.resolved}")
    print(f"  NXDOMAIN      : {stats.nxdomain}   <- expected high for DGA")
    print(f"  blocked (fg)  : {stats.blocked}")
    print(f"  errors        : {stats.errors}")
    print("\n  by source:")
    print(f"    {'source':20} {'resolv':>7} {'nxdom':>7} {'block':>7} {'err':>6}")
    for src in sorted(stats.per_source):
        d = stats.per_source[src]
        print(f"    {src:20} {d.get('resolved', 0):7} {d.get('nxdomain', 0):7} "
              f"{d.get('blocked', 0):7} {d.get('error', 0):6}")
    print("=" * 70)


# --------------------------------------------------------------------------- #
# Standalone CLI
# --------------------------------------------------------------------------- #

def parse_args():
    p = argparse.ArgumentParser(description="Async DNS / DGA traffic generator for FortiGate labs.")
    p.add_argument("--config", default="config.json")
    p.add_argument("--concurrency", type=int, default=200)
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--dga-count", type=int, default=None,
                   help="Override the number of DGA domains generated.")
    p.add_argument("--iterations", type=int, default=1)
    p.add_argument("--servers", nargs="*", help="Override DNS server(s) instead of the OS default.")
    p.add_argument("--source-ips", nargs="*", metavar="IP", default=None,
                   help="Bind queries to these local source IPs (round-robin). "
                        "Overrides 'source_ips' in config.json.")
    p.add_argument("--sample", action="store_true", help="Print a sample of generated DGA domains and exit.")
    p.add_argument("--verbose", "-v", action="store_true")
    return p.parse_args()


async def _main_async(args, dns_cfg, source_ips):
    stats = DnsStats()
    for _ in range(args.iterations):
        await run_dns_phase(dns_cfg, concurrency=args.concurrency, timeout=args.timeout,
                            dga_count=args.dga_count, verbose=args.verbose, stats=stats,
                            servers=args.servers, source_ips=source_ips)
    print_dns_report(stats)


def main():
    args = parse_args()
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = Path(__file__).parent / config_path
    with config_path.open(encoding="utf-8") as fh:
        full_cfg = json.load(fh)
    dns_cfg = full_cfg.get("dns", {})
    source_ips = args.source_ips if args.source_ips is not None else full_cfg.get("source_ips", [])
    source_ips = [ip for ip in source_ips if ip] or [None]

    if args.sample:
        rng = random.Random()
        for src, dom in build_domain_list(dns_cfg, dga_count=args.dga_count, rng=rng)[:40]:
            print(f"{src:12} {dom}")
        return

    if aiodns is None:
        sys.exit("aiodns is required. Activate your venv and run: pip install -r requirements.txt")
    asyncio.run(_main_async(args, dns_cfg, source_ips))


if __name__ == "__main__":
    main()
