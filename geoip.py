#!/usr/bin/env python3
"""
geoip.py - Generate traffic to IPs allocated to embargoed / sanctioned countries so
FortiGate GeoIP (destination-country) firewall policies match and block it.

Pulls per-country IPv4 CIDR lists (default: ipdeny.com aggregated zones), picks
random hosts in each country, and makes an HTTP connection to them. Optionally also
hits known in-country domains for a cleaner client-side signal.

Client-side block detection is best-effort: a GeoIP block is usually a silent drop or
reset, and random in-country IPs may not answer anyway - so the FortiGate policy log
(showing the destination country + block action) is the authoritative proof. This
tool's job is to GENERATE the connections.

SAFETY: connects to ordinary IP allocations by country, reads at most a few KB, saves
nothing. Use only against your own lab FortiGate. Some destinations are simply
addresses in a country's range and may not host anything.

Imported by web_gen.py (--geo / --geo-only) or run standalone.
"""

import asyncio
import ipaddress
import json
import random
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

try:
    import aiohttp
except ImportError:
    aiohttp = None

# Sanctioned / embargoed countries (ISO 3166-1 alpha-2 + name). Mirrors the common
# EAR / ITAR / OFAC lists. Trim or extend in config.json.
DEFAULT_COUNTRIES = [
    {"code": "cu", "name": "Cuba"}, {"code": "ir", "name": "Iran"},
    {"code": "sy", "name": "Syria"}, {"code": "kp", "name": "North Korea"},
    {"code": "ru", "name": "Russia"}, {"code": "by", "name": "Belarus"},
    {"code": "ve", "name": "Venezuela"}, {"code": "cn", "name": "China"},
    {"code": "mm", "name": "Myanmar"}, {"code": "af", "name": "Afghanistan"},
    {"code": "iq", "name": "Iraq"}, {"code": "ly", "name": "Libya"},
    {"code": "sd", "name": "Sudan"}, {"code": "ss", "name": "South Sudan"},
    {"code": "so", "name": "Somalia"}, {"code": "ye", "name": "Yemen"},
    {"code": "cd", "name": "DR Congo"}, {"code": "cf", "name": "Central African Rep"},
    {"code": "er", "name": "Eritrea"}, {"code": "lb", "name": "Lebanon"},
    {"code": "ml", "name": "Mali"}, {"code": "ni", "name": "Nicaragua"},
    {"code": "zw", "name": "Zimbabwe"}, {"code": "et", "name": "Ethiopia"},
]

BLOCK_MARKERS = ("web page blocked", "fortiguard", "blocked by", "geo", "blocked",
                 "high security alert")


@dataclass
class GeoStats:
    total: int = 0
    blocked: int = 0
    reached: int = 0
    no_response: int = 0
    errors: int = 0
    per_country: dict = field(default_factory=lambda: defaultdict(lambda: defaultdict(int)))


class GeoFeeds:
    def __init__(self, cfg):
        self.cfg = cfg or {}
        self.url_template = self.cfg.get(
            "cidr_url_template",
            "https://www.ipdeny.com/ipblocks/data/aggregated/{cc}-aggregated.zone")
        self.countries = self.cfg.get("countries", DEFAULT_COUNTRIES)
        self.ips_per_country = int(self.cfg.get("ips_per_country", 2))
        self.poll_interval = float(self.cfg.get("poll_interval_sec", 3600))
        self.domains = self.cfg.get("domains", [])  # [{code,name,domain}]
        self.cidrs = {}  # cc -> list of CIDR strings
        self.names = {c["code"]: c["name"] for c in self.countries}
        self.last_fetch = 0.0

    async def _fetch_cc(self, session, cc):
        url = self.url_template.format(cc=cc)
        async with session.get(url, ssl=False) as resp:
            resp.raise_for_status()
            text = await resp.text()
        return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]

    async def refresh(self, session):
        loaded = 0
        for c in self.countries:
            cc = c["code"]
            try:
                self.cidrs[cc] = await self._fetch_cc(session, cc)
                loaded += len(self.cidrs[cc])
            except Exception as exc:  # noqa: BLE001
                print(f"[geoip] {cc}: fetch failed ({type(exc).__name__})")
        self.last_fetch = time.monotonic()
        print(f"[geoip] loaded {loaded} CIDRs across {len(self.cidrs)} countries")

    async def maybe_refresh(self, session):
        if not self.last_fetch or (time.monotonic() - self.last_fetch) >= self.poll_interval:
            await self.refresh(session)

    @property
    def loaded(self):
        return any(self.cidrs.values())

    @staticmethod
    def _random_host(cidr, rng):
        net = ipaddress.ip_network(cidr, strict=False)
        if net.num_addresses <= 2:
            return str(net.network_address)
        return str(net.network_address + rng.randint(1, net.num_addresses - 2))

    def sample(self, rng=None):
        """Return list of (cc, name, target) - IPs (http://ip/) and known domains."""
        rng = rng or random
        out = []
        for cc, cidrs in self.cidrs.items():
            if not cidrs:
                continue
            name = self.names.get(cc, cc)
            for _ in range(self.ips_per_country):
                ip = self._random_host(rng.choice(cidrs), rng)
                out.append((cc, name, f"http://{ip}/"))
        for d in self.domains:
            out.append((d.get("code", "?"), d.get("name", d["domain"]),
                        f"https://{d['domain']}/"))
        return out


async def geo_one(session, sem, cc, name, url, stats, verbose, src_ip):
    async with sem:
        stats.total += 1
        result = "no_response"
        try:
            async with session.get(url, ssl=False) as resp:
                chunk = await resp.content.read(4096)
                low = chunk.decode("utf-8", "ignore").lower()
                if "forti" in low and any(m in low for m in BLOCK_MARKERS):
                    result = "blocked"
                else:
                    result = "reached"
        except (aiohttp.ServerDisconnectedError, aiohttp.ClientConnectionError,
                ConnectionResetError):
            result = "blocked"          # RST - often the FortiGate GeoIP drop
        except asyncio.TimeoutError:
            result = "no_response"       # dead IP or silent drop - check FortiGate log
        except aiohttp.ClientError:
            result = "no_response"
        except Exception:  # noqa: BLE001
            result = "error"

        stats.per_country[name][result] += 1
        if result == "blocked":
            stats.blocked += 1
            tag = "BLOCK"
        elif result == "reached":
            stats.reached += 1
            tag = "reach"
        elif result == "no_response":
            stats.no_response += 1
            tag = "noresp"
        else:
            stats.errors += 1
            tag = "err"
        if verbose:
            ip = f" [{src_ip}]" if src_ip else ""
            print(f"[{tag:6}] {name:20} {url}{ip}")


async def run_geo_phase(feeds, sessions, sem, stats=None, verbose=False, rng=None):
    stats = stats or GeoStats()
    targets = feeds.sample(rng)
    tasks = []
    for i, (cc, name, url) in enumerate(targets):
        src_ip, session = sessions[i % len(sessions)]
        tasks.append(asyncio.create_task(
            geo_one(session, sem, cc, name, url, stats, verbose, src_ip)))
    await asyncio.gather(*tasks)
    return stats


def print_geo_report(stats: GeoStats):
    print("\n" + "=" * 70)
    print("GEOIP RESULTS  (best-effort; FortiGate GeoIP policy log is authoritative)")
    print("=" * 70)
    print(f"  connections : {stats.total}")
    print(f"  blocked/RST : {stats.blocked}")
    print(f"  reached     : {stats.reached}   (got an HTTP response - not GeoIP-blocked)")
    print(f"  no response : {stats.no_response}   (dead IP or silent drop)")
    print(f"  errors      : {stats.errors}")
    print("\n  by country:")
    print(f"    {'country':22} {'blk/rst':>8} {'reach':>6} {'noresp':>7} {'err':>5}")
    for name in sorted(stats.per_country):
        d = stats.per_country[name]
        print(f"    {name:22} {d.get('blocked', 0):8} {d.get('reached', 0):6} "
              f"{d.get('no_response', 0):7} {d.get('error', 0):5}")
    print("\n  -> confirm blocks by destination country in the FortiGate policy log.")
    print("=" * 70)


async def _standalone(cfg, concurrency):
    timeout = aiohttp.ClientTimeout(total=8)
    conn = aiohttp.TCPConnector(ssl=False, force_close=True, limit=concurrency)
    feeds = GeoFeeds(cfg)
    async with aiohttp.ClientSession(timeout=timeout, connector=conn) as s:
        await feeds.refresh(s)
        stats = await run_geo_phase(feeds, [(None, s)], asyncio.Semaphore(concurrency),
                                    verbose=True)
    print_geo_report(stats)


def main():
    import argparse
    p = argparse.ArgumentParser(description="FortiGate GeoIP (sanctioned-country) traffic generator.")
    p.add_argument("--config", default="config.json")
    p.add_argument("--concurrency", type=int, default=30)
    args = p.parse_args()
    if aiohttp is None:
        sys.exit("aiohttp required. Activate venv and pip install -r requirements.txt")
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = Path(__file__).parent / config_path
    cfg = json.loads(config_path.read_text(encoding="utf-8")).get("geoip", {})
    asyncio.run(_standalone(cfg, args.concurrency))


if __name__ == "__main__":
    main()
