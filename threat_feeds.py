#!/usr/bin/env python3
"""
threat_feeds.py - Pull external threat-feed lists and mix a small, random
assortment of them into the generated traffic, to demonstrate that firewall
external threat feeds (URL / Domain / IP block lists) are matching.

Feeds are the same lists you point the firewall at (URLhaus, OpenPhish, Spamhaus,
Feodo, ...). Entries:
  * urls    - scheme-less URLs (host[:port]/path)  -> HTTP GET  http://<entry>
  * ips     - IPs or CIDRs                          -> HTTP GET  http://<host>/
  * domains - hostnames                             -> HTTPS GET https://<domain>/ + DNS

SAFETY: these are real malicious indicators. This module never downloads full
bodies from feed targets and never saves them - it only makes the connection so
the firewall can match/block it. Only run behind a firewall that is actually
enforcing these feeds.
"""

import ipaddress
import random
import time


def _parse_lines(text):
    """Strip comments (#...) and blank lines."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


class ThreatFeeds:
    def __init__(self, cfg):
        self.cfg = cfg or {}
        self.feeds = self.cfg.get("feeds", {})
        self.mix_rate = float(self.cfg.get("mix_rate", 0.025))
        self.poll_interval = float(self.cfg.get("poll_interval_sec", 600))
        self.max_per_pass = int(self.cfg.get("max_per_pass", 40))
        self.timeout = float(self.cfg.get("fetch_timeout_sec", 20))
        self.urls = []
        self.ips = []
        self.domains = []
        self.last_fetch = 0.0
        self.last_error = None

    # -- fetching -------------------------------------------------------------

    async def _fetch_one(self, session, url):
        async with session.get(url, ssl=False) as resp:
            resp.raise_for_status()
            return _parse_lines(await resp.text())

    async def refresh(self, session):
        """Fetch all configured feeds. Keeps old data on failure."""
        try:
            if self.feeds.get("urls"):
                self.urls = await self._fetch_one(session, self.feeds["urls"])
            if self.feeds.get("ips"):
                self.ips = await self._fetch_one(session, self.feeds["ips"])
            if self.feeds.get("domains"):
                self.domains = await self._fetch_one(session, self.feeds["domains"])
            self.last_fetch = time.monotonic()
            self.last_error = None
            print(f"[threat-feeds] loaded: {len(self.urls)} urls, "
                  f"{len(self.ips)} ips, {len(self.domains)} domains")
        except Exception as exc:  # noqa: BLE001
            self.last_error = f"{type(exc).__name__}: {exc}"
            print(f"[threat-feeds] fetch failed ({self.last_error}); "
                  f"using {len(self.urls)+len(self.ips)+len(self.domains)} cached entries")

    async def maybe_refresh(self, session):
        if not self.last_fetch or (time.monotonic() - self.last_fetch) >= self.poll_interval:
            await self.refresh(session)

    @property
    def loaded(self):
        return bool(self.urls or self.ips or self.domains)

    # -- sampling -------------------------------------------------------------

    @staticmethod
    def _host_from_ip_entry(entry, rng):
        """Return a usable host IP from an IP or CIDR entry."""
        try:
            net = ipaddress.ip_network(entry, strict=False)
            if net.num_addresses <= 2:
                return str(net.network_address)
            offset = rng.randint(1, net.num_addresses - 2)  # skip network/broadcast
            return str(net.network_address + offset)
        except ValueError:
            return entry.split("/")[0]

    def sample_http(self, n, rng=None):
        """Return up to n (category, url, expect) drawn from a random mix of feeds."""
        rng = rng or random
        pools = []
        if self.urls:
            pools.append("url")
        if self.ips:
            pools.append("ip")
        if self.domains:
            pools.append("domain")
        out = []
        for _ in range(max(0, n)):
            if not pools:
                break
            kind = rng.choice(pools)
            if kind == "url":
                e = rng.choice(self.urls)
                url = e if e.startswith(("http://", "https://")) else "http://" + e
            elif kind == "ip":
                url = "http://" + self._host_from_ip_entry(rng.choice(self.ips), rng) + "/"
            else:
                url = "https://" + rng.choice(self.domains) + "/"
            out.append(("threat_feed", url, "block"))
        return out

    def sample_dns(self, n, rng=None):
        """Return up to n (source, domain) for the DNS phase."""
        rng = rng or random
        if not self.domains:
            return []
        return [("threat_feed", rng.choice(self.domains)) for _ in range(max(0, n))]

    def inject_count(self, batch_len):
        """How many feed targets to add for a batch of the given size."""
        if not self.loaded or batch_len <= 0:
            return 0
        n = round(self.mix_rate * batch_len)
        if n == 0:
            n = 1  # always show at least one so the demo is visible
        return min(self.max_per_pass, n)
