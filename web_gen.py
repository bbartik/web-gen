#!/usr/bin/env python3
"""
web_gen.py - Comprehensive async web traffic generator for FortiGate labs.

Fires large volumes of concurrent HTTP(S) requests at categorized target lists
(malware/EICAR, phishing, gambling, hacking, proxy-avoidance, etc.) so you can
watch FortiGate web filtering, antivirus, and app control light up.

Runs on a lab VM behind the FortiGate. All targets are either harmless industry
test files (EICAR/AMTSO/WICAR/testmyids) or public sites that fall into a
FortiGuard category. Nothing here attacks anything - it only requests pages.

Usage examples:
    python web_gen.py                          # one pass over every enabled category
    python web_gen.py --loop --duration 300    # hammer for 5 minutes
    python web_gen.py --concurrency 200 --iterations 5
    python web_gen.py --categories gambling hacking av_malware_eicar
    python web_gen.py --list                    # show categories and exit
"""

import argparse
import asyncio
import json
import random
import ssl
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

try:
    import aiohttp
except ImportError:
    sys.exit("aiohttp is required. Activate your venv and run: pip install -r requirements.txt")

import dns_gen  # noqa: E402  (also sets the Windows selector loop policy aiodns needs)
import threat_feeds  # noqa: E402


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

# Substrings that appear in a FortiGate web-filter / AV block page.
FORTI_BLOCK_MARKERS = (
    "web page blocked",
    "fortiguard",
    "url blocked",
    "web filter",
    "the page you have requested has been blocked",
    "file blocked",
    "virus/malware detected",
    "high security alert",
    "content has been blocked",
)


@dataclass
class Stats:
    total: int = 0
    ok: int = 0
    blocked: int = 0
    errors: int = 0
    bytes_down: int = 0
    status_counts: dict = field(default_factory=lambda: defaultdict(int))
    per_category: dict = field(default_factory=lambda: defaultdict(lambda: defaultdict(int)))
    per_source_ip: dict = field(default_factory=lambda: defaultdict(int))


def load_targets(config_path: Path, only: list[str] | None):
    with config_path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    cats = data.get("categories", {})
    targets = []  # list of (category, url, expect, weight)
    selected = {}
    for name, cfg in cats.items():
        if only and name not in only:
            continue
        if not only and not cfg.get("enabled", True):
            continue
        urls = cfg.get("urls", [])
        if not urls:
            continue
        expect = cfg.get("expect", "unknown")
        weight = max(1, int(cfg.get("weight", 1)))
        selected[name] = (len(urls), weight)
        for url in urls:
            targets.append((name, url, expect, weight))
    return targets, selected


def bust_cache(url: str) -> str:
    """Append a random query param so caches/proxies see a unique request."""
    token = f"cb={random.randint(100000, 999999)}"
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{token}"


def classify(status: int, body_snippet: str) -> str:
    low = body_snippet.lower()
    if any(marker in low for marker in FORTI_BLOCK_MARKERS):
        return "blocked"
    if status in (403, 451, 503) and "forti" in low:
        return "blocked"
    if 200 <= status < 400:
        return "ok"
    return "error"


async def fetch(session, sem, category, url, expect, stats, args, src_ip=None):
    # Threat-feed targets are real malicious indicators: keep the URL exact (no
    # cache-bust so URL-feed matching stays exact) and never download the body.
    is_threat = category == "threat_feed"
    request_url = url if is_threat else (bust_cache(url) if args.cache_bust else url)
    full_dl = args.full_download and not is_threat
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    async with sem:
        stats.total += 1
        if src_ip:
            stats.per_source_ip[src_ip] += 1
        try:
            async with session.get(
                request_url,
                headers=headers,
                allow_redirects=not args.no_redirects,
                ssl=False,  # lab: don't fail on the FortiGate's cert / self-signed block page
            ) as resp:
                # Read a small slice - enough to sniff a block page without huge downloads,
                # unless --full-download is set (useful to actually pull the EICAR file).
                if full_dl:
                    chunk = await resp.read()
                else:
                    chunk = await resp.content.read(4096)
                stats.bytes_down += len(chunk)
                snippet = chunk.decode("utf-8", errors="ignore")
                result = classify(resp.status, snippet)
                stats.status_counts[resp.status] += 1
                stats.per_category[category][result] += 1
                if result == "blocked":
                    stats.blocked += 1
                    tag = "BLOCK"
                elif result == "ok":
                    stats.ok += 1
                    tag = "ok"
                else:
                    stats.errors += 1
                    tag = "err"
                if args.verbose:
                    print(f"[{tag:5}] {resp.status} {category:24} {url}")
        except asyncio.TimeoutError:
            stats.errors += 1
            stats.per_category[category]["timeout"] += 1
            if args.verbose:
                print(f"[TMOUT] ----- {category:24} {url}")
        except aiohttp.ClientError as exc:
            stats.errors += 1
            stats.per_category[category]["conn_error"] += 1
            if args.verbose:
                print(f"[CERR ] ----- {category:24} {url}  ({type(exc).__name__})")
        except Exception as exc:  # noqa: BLE001 - lab tool, keep firing
            stats.errors += 1
            stats.per_category[category]["error"] += 1
            if args.verbose:
                print(f"[EXC  ] ----- {category:24} {url}  ({type(exc).__name__})")


async def run(args):
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = Path(__file__).parent / config_path

    with config_path.open(encoding="utf-8") as fh:
        full_cfg = json.load(fh)
    dns_cfg = full_cfg.get("dns", {})
    do_dns = args.dns or args.dns_only

    # Source IPs to bind outgoing traffic to (CLI overrides config). Each becomes a
    # distinct client on the FortiGate. [None] = OS default source selection.
    source_ips = args.source_ips if args.source_ips is not None else full_cfg.get("source_ips", [])
    source_ips = [ip for ip in source_ips if ip] or [None]

    # Threat-feed mixing (CLI overrides config).
    tf_cfg = dict(full_cfg.get("threat_feeds", {}))
    if args.threat_rate is not None:
        tf_cfg["mix_rate"] = args.threat_rate
    do_threat = tf_cfg.get("enabled", False) and not args.no_threat_feeds
    tf = threat_feeds.ThreatFeeds(tf_cfg) if do_threat else None

    targets, selected = ([], {})
    if not args.dns_only:
        targets, selected = load_targets(config_path, args.categories)
        if not targets:
            sys.exit("No HTTP targets selected. Check --categories or enable some in config.json.")

    print("=" * 70)
    print("FortiGate lab web traffic generator")
    print("=" * 70)
    # Weighted pool: each target repeated 'weight' times so higher-weight
    # (normal) categories are hit proportionally more often.
    weighted_pool = []
    for cat, url, expect, weight in targets:
        weighted_pool.extend([(cat, url, expect)] * weight)

    if not args.dns_only:
        for name, (count, weight) in selected.items():
            print(f"  {name:26} {count:3} url(s)  x{weight}")
        if args.requests:
            print(f"\n  http requests/pass : {args.requests} (weighted-random sample)")
        else:
            print(f"\n  http requests/pass : {len(weighted_pool)} "
                  f"(weighted full pass; {len(targets)} unique urls)")
    if do_dns:
        n_dns = len(dns_gen.build_domain_list(dns_cfg, dga_count=args.dga_count))
        print(f"  dns queries/pass  : {n_dns} "
              f"(dga + suspicious + benign)")
    if do_threat:
        print(f"  threat feeds : on (~{tf.mix_rate*100:.1f}% of connections, "
              f"poll {int(tf.poll_interval)}s)")
    print(f"  concurrency  : {args.concurrency}")
    if source_ips != [None]:
        print(f"  source ips   : {', '.join(source_ips)}")
    mode = f"loop for {args.duration}s" if args.loop else f"{args.iterations} iteration(s)"
    print(f"  mode         : {mode}")
    if not args.dns_only:
        print(f"  cache-bust   : {args.cache_bust}   full-download: {args.full_download}")
    print("=" * 70)

    stats = Stats()
    dns_stats = dns_gen.DnsStats()
    sem = asyncio.Semaphore(args.concurrency)
    timeout = aiohttp.ClientTimeout(total=args.timeout)

    # One ClientSession per source IP - aiohttp binds a connector to a single
    # local_addr, so we pool them and round-robin requests across the pool.
    sessions = []  # list of (src_ip, session)
    for ip in source_ips:
        conn = aiohttp.TCPConnector(
            limit=args.concurrency, ssl=False, force_close=True,
            local_addr=(ip, 0) if ip else None,
        )
        sessions.append((ip, aiohttp.ClientSession(timeout=timeout, connector=conn)))

    # Separate session (default source) for fetching the threat feeds from GitHub.
    feed_session = None
    if do_threat:
        feed_session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=tf.timeout),
            connector=aiohttp.TCPConnector(ssl=False, force_close=True),
        )

    start = time.monotonic()
    passes = 0
    try:
        while True:
            passes += 1
            if do_threat:
                await tf.maybe_refresh(feed_session)

            if not args.dns_only:
                if args.requests:
                    # Weighted-random sample (with replacement) for sustained load.
                    batch = random.choices(weighted_pool, k=args.requests)
                else:
                    batch = list(weighted_pool)
                    if args.shuffle:
                        random.shuffle(batch)
                # Mix in a small assortment of threat-feed targets.
                if do_threat:
                    batch = batch + tf.sample_http(tf.inject_count(len(batch)))
                    if args.shuffle:
                        random.shuffle(batch)
                tasks = []
                for i, (cat, url, expect) in enumerate(batch):
                    src_ip, session = sessions[i % len(sessions)]  # round-robin across IPs
                    tasks.append(asyncio.create_task(
                        fetch(session, sem, cat, url, expect, stats, args, src_ip)))
                await asyncio.gather(*tasks)

            if do_dns:
                extra = tf.sample_dns(tf.inject_count(300)) if do_threat else None
                await dns_gen.run_dns_phase(
                    dns_cfg, concurrency=args.concurrency, timeout=args.timeout,
                    dga_count=args.dga_count, verbose=args.verbose, stats=dns_stats,
                    source_ips=source_ips, extra_domains=extra,
                )

            if args.delay:
                await asyncio.sleep(args.delay)

            elapsed = time.monotonic() - start
            if args.loop:
                if elapsed >= args.duration:
                    break
            else:
                if passes >= args.iterations:
                    break
    finally:
        for _, session in sessions:
            await session.close()
        if feed_session is not None:
            await feed_session.close()

    elapsed = time.monotonic() - start
    if not args.dns_only:
        print_report(stats, elapsed, passes)
    if do_dns:
        dns_gen.print_dns_report(dns_stats)


def print_report(stats: Stats, elapsed: float, passes: int):
    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)
    print(f"  passes           : {passes}")
    print(f"  duration         : {elapsed:.1f}s")
    print(f"  total requests   : {stats.total}")
    rate = stats.total / elapsed if elapsed else 0
    print(f"  request rate     : {rate:.1f} req/s")
    print(f"  allowed (ok)     : {stats.ok}")
    print(f"  blocked          : {stats.blocked}")
    print(f"  errors/timeouts  : {stats.errors}")
    print(f"  data downloaded  : {stats.bytes_down / 1024:.1f} KiB")

    print("\n  by category:")
    print(f"    {'category':26} {'ok':>5} {'block':>6} {'err':>5} {'other':>6}")
    for cat in sorted(stats.per_category):
        d = stats.per_category[cat]
        other = sum(v for k, v in d.items() if k not in ("ok", "blocked", "error"))
        print(f"    {cat:26} {d.get('ok', 0):5} {d.get('blocked', 0):6} "
              f"{d.get('error', 0):5} {other:6}")

    print("\n  by HTTP status:")
    for status in sorted(stats.status_counts):
        print(f"    {status} : {stats.status_counts[status]}")

    if stats.per_source_ip:
        print("\n  by source IP:")
        for ip in sorted(stats.per_source_ip):
            print(f"    {ip:16} {stats.per_source_ip[ip]}")
    print("=" * 70)


def list_categories(config_path: Path):
    with config_path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    print(f"{'category':28} {'enabled':8} {'expect':7} {'weight':>6} urls")
    print("-" * 66)
    for name, cfg in data.get("categories", {}).items():
        print(f"{name:28} {str(cfg.get('enabled', True)):8} "
              f"{cfg.get('expect', '?'):7} {cfg.get('weight', 1):>6} {len(cfg.get('urls', []))}")


def parse_args():
    p = argparse.ArgumentParser(
        description="Comprehensive async web traffic generator for FortiGate labs.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--config", default="config.json", help="Path to target config.")
    p.add_argument("--categories", nargs="*", metavar="CAT",
                   help="Only hit these categories (overrides 'enabled' flags).")
    p.add_argument("--concurrency", type=int, default=100,
                   help="Max simultaneous in-flight requests.")
    p.add_argument("--iterations", type=int, default=1,
                   help="Number of passes over the target list (ignored with --loop).")
    p.add_argument("--loop", action="store_true",
                   help="Keep looping until --duration seconds elapse.")
    p.add_argument("--duration", type=int, default=60,
                   help="Seconds to run when --loop is set.")
    p.add_argument("--delay", type=float, default=0.0,
                   help="Seconds to sleep between passes.")
    p.add_argument("--timeout", type=float, default=15.0,
                   help="Per-request total timeout (seconds).")
    p.add_argument("--full-download", action="store_true",
                   help="Download full response bodies (e.g. actually pull EICAR files).")
    p.add_argument("--cache-bust", action="store_true", default=True,
                   help="Append a random query param to each URL.")
    p.add_argument("--no-cache-bust", dest="cache_bust", action="store_false",
                   help="Do not modify URLs.")
    p.add_argument("--no-redirects", action="store_true",
                   help="Do not follow HTTP redirects.")
    p.add_argument("--shuffle", action="store_true",
                   help="Shuffle target order each pass (weighted full-pass mode).")
    p.add_argument("--requests", type=int, default=None, metavar="N",
                   help="Instead of a full pass, fire N weighted-random requests/pass "
                        "(with replacement) - realistic, rate-controllable mix.")
    p.add_argument("--dns", action="store_true",
                   help="Also run a DNS/DGA query phase each pass (DNS filtering + Botnet C&C test).")
    p.add_argument("--dns-only", action="store_true",
                   help="Run only the DNS/DGA phase; skip HTTP entirely.")
    p.add_argument("--dga-count", type=int, default=None,
                   help="Override number of DGA domains generated per pass.")
    p.add_argument("--no-threat-feeds", action="store_true",
                   help="Disable mixing in external threat-feed targets (URLhaus/OpenPhish/etc).")
    p.add_argument("--threat-rate", type=float, default=None, metavar="R",
                   help="Fraction of connections that are threat-feed targets (e.g. 0.03). "
                        "Overrides 'mix_rate' in config.json.")
    p.add_argument("--source-ips", nargs="*", metavar="IP", default=None,
                   help="Bind outgoing traffic to these local source IPs (round-robin), "
                        "so each shows up as a separate client on the FortiGate. "
                        "Overrides 'source_ips' in config.json. Must already be assigned "
                        "to a NIC on this machine.")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Print every request result.")
    p.add_argument("--list", action="store_true",
                   help="List categories in the config and exit.")
    return p.parse_args()


def main():
    args = parse_args()
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = Path(__file__).parent / config_path

    if args.list:
        list_categories(config_path)
        return

    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\nInterrupted.")


if __name__ == "__main__":
    main()
