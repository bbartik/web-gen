#!/usr/bin/env python3
"""
ips.py - Fire an assortment of well-known IPS signature patterns to validate
firewall Intrusion Prevention.

IPS inspects the pattern *in transit*, so a vulnerable target is NOT required -
the patterns are simply carried in a request to a neutral sink and the firewall
matches/blocks them on the wire. When IPS blocks, it typically resets the session
(seen here as a connection reset) or returns a firewall IPS block page.

SAFETY: patterns are public, well-known signatures; payload internals are inert
(JNDI points at loopback; shell/SQL payloads hit an echo service with no shell or
DB). This only *carries* the pattern for signature matching - it does not exploit
anything and does not target a victim application. Use only against your own lab
firewall.

Imported by web_gen.py (--ips / --ips-only) or run standalone.
"""

import asyncio
import json
import random
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

try:
    import aiohttp
except ImportError:
    aiohttp = None

import blockpages

BLOCK_MARKERS = (
    "web page blocked", "fortiguard", "intrusion", "ips", "attack",
    "high security alert", "blocked", "content has been blocked",
)

# Each trigger: name, category, where to inject, and the payload.
#   where: query | ua | header | body | path | response
# 'response' means the *server's response* carries the signature (testmyids).
TRIGGERS = [
    {"name": "gpl-id-check", "cat": "ids-test", "where": "response",
     "url": "http://www.testmyids.com/"},
    {"name": "shellshock", "cat": "cve-2014-6271", "where": "ua",
     "value": "() { :;}; echo; /bin/cat /etc/passwd"},
    {"name": "log4shell", "cat": "cve-2021-44228", "where": "header",
     "header": "X-Api-Version", "value": "${jndi:ldap://127.0.0.1:1/a}"},
    {"name": "log4shell-ua", "cat": "cve-2021-44228", "where": "ua",
     "value": "${jndi:ldap://127.0.0.1:1/a}"},
    {"name": "sqli-or-1", "cat": "sql-injection", "where": "query",
     "param": "id", "value": "1' OR '1'='1' -- "},
    {"name": "sqli-union", "cat": "sql-injection", "where": "query",
     "param": "id", "value": "1 UNION SELECT username,password FROM users-- "},
    {"name": "xss-script", "cat": "xss", "where": "query",
     "param": "q", "value": "<script>alert(1)</script>"},
    {"name": "xss-img-onerror", "cat": "xss", "where": "query",
     "param": "q", "value": "<img src=x onerror=alert(1)>"},
    {"name": "path-traversal", "cat": "traversal", "where": "query",
     "param": "file", "value": "../../../../../../etc/passwd"},
    {"name": "cmd-injection", "cat": "command-injection", "where": "query",
     "param": "host", "value": "127.0.0.1;cat /etc/passwd"},
    {"name": "struts-ognl", "cat": "cve-2017-5638", "where": "header",
     "header": "Content-Type",
     "value": "%{(#_='multipart/form-data').(#cmd='id').(#p=new java.lang.ProcessBuilder(#cmd))}"},
    {"name": "scanner-nikto", "cat": "scanner-ua", "where": "ua",
     "value": "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:map_codes)"},
    {"name": "scanner-sqlmap", "cat": "scanner-ua", "where": "ua",
     "value": "sqlmap/1.7.2#stable (https://sqlmap.org)"},
    {"name": "scanner-nmap", "cat": "scanner-ua", "where": "ua",
     "value": "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"},
    {"name": "scanner-zmeu", "cat": "scanner-ua", "where": "ua",
     "value": "ZmEu"},
    {"name": "scanner-masscan", "cat": "scanner-ua", "where": "ua",
     "value": "masscan/1.3"},
]

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


@dataclass
class IpsStats:
    total: int = 0
    blocked: int = 0
    passed: int = 0
    errors: int = 0
    per_trigger: dict = field(default_factory=lambda: defaultdict(lambda: defaultdict(int)))


def _build_request(trig, target_get, target_post):
    """Return (method, url, headers, data) for a trigger."""
    headers = {"User-Agent": DEFAULT_UA}
    method, url, data = "GET", target_get, None
    where = trig["where"]
    if where == "response":
        url = trig["url"]
    elif where == "ua":
        headers["User-Agent"] = trig["value"]
    elif where == "header":
        headers[trig["header"]] = trig["value"]
    elif where == "query":
        sep = "&" if "?" in target_get else "?"
        url = f"{target_get}{sep}{trig['param']}={trig['value']}"
    elif where == "body":
        method, url, data = "POST", target_post, trig["value"]
    return method, url, headers, data


async def fire_one(session, sem, trig, target_get, target_post, stats, verbose, src_ip):
    method, url, headers, data = _build_request(trig, target_get, target_post)
    async with sem:
        stats.total += 1
        result = "passed"
        try:
            async with session.request(method, url, headers=headers, data=data,
                                       ssl=False, allow_redirects=False) as resp:
                chunk = await resp.content.read(4096)
                low = chunk.decode("utf-8", "ignore").lower()
                # An IPS block is a reset or a firewall IPS block page. Getting ANY
                # HTTP response back (even a 403 from the origin) means IPS did not
                # act - the origin's own status is not our signal.
                if blockpages.looks_blocked(low, BLOCK_MARKERS):
                    result = "blocked"
                else:
                    result = "passed"
        except (aiohttp.ServerDisconnectedError, aiohttp.ClientConnectionError,
                ConnectionResetError):
            result = "blocked"   # IPS commonly resets the session
        except asyncio.TimeoutError:
            result = "error"
        except aiohttp.ClientError:
            result = "error"
        except Exception:  # noqa: BLE001
            result = "error"

        stats.per_trigger[trig["name"]][result] += 1
        if result == "blocked":
            stats.blocked += 1
            tag = "BLOCK"
        elif result == "passed":
            stats.passed += 1
            tag = "pass"
        else:
            stats.errors += 1
            tag = "err"
        if verbose:
            ip = f" [{src_ip}]" if src_ip else ""
            print(f"[{tag:5}] {trig['cat']:20} {trig['name']}{ip}")


async def run_ips_phase(cfg, sessions, sem, stats=None, verbose=False, rng=None):
    """One pass over all triggers. `sessions` is a list of (src_ip, session)."""
    stats = stats or IpsStats()
    target_get = cfg.get("target_url", "http://example.com/")
    target_post = cfg.get("target_post_url", "http://example.com/")
    triggers = cfg.get("triggers") or TRIGGERS
    tasks = []
    for i, trig in enumerate(triggers):
        src_ip, session = sessions[i % len(sessions)]
        tasks.append(asyncio.create_task(
            fire_one(session, sem, trig, target_get, target_post, stats, verbose, src_ip)))
    await asyncio.gather(*tasks)
    return stats


def print_ips_report(stats: IpsStats):
    print("\n" + "=" * 70)
    print("IPS RESULTS  (blocked = IPS caught it / reset session)")
    print("=" * 70)
    print(f"  triggers sent : {stats.total}")
    print(f"  blocked       : {stats.blocked}")
    print(f"  passed        : {stats.passed}   <- IPS did NOT catch these")
    print(f"  errors        : {stats.errors}")
    print("\n  by trigger:")
    print(f"    {'trigger':22} {'blocked':>8} {'passed':>7} {'err':>5}")
    for name in sorted(stats.per_trigger):
        d = stats.per_trigger[name]
        print(f"    {name:22} {d.get('blocked', 0):8} {d.get('passed', 0):7} "
              f"{d.get('error', 0):5}")
    print("=" * 70)


async def _standalone(cfg, concurrency):
    timeout = aiohttp.ClientTimeout(total=15)
    conn = aiohttp.TCPConnector(ssl=False, force_close=True)
    async with aiohttp.ClientSession(timeout=timeout, connector=conn) as s:
        stats = await run_ips_phase(cfg, [(None, s)], asyncio.Semaphore(concurrency),
                                    verbose=True)
    print_ips_report(stats)


def main():
    import argparse
    p = argparse.ArgumentParser(description="firewall IPS signature tester.")
    p.add_argument("--config", default="config.json")
    p.add_argument("--concurrency", type=int, default=10)
    args = p.parse_args()
    if aiohttp is None:
        sys.exit("aiohttp required. Activate venv and pip install -r requirements.txt")
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = Path(__file__).parent / config_path
    cfg = json.loads(config_path.read_text(encoding="utf-8")).get("ips", {})
    asyncio.run(_standalone(cfg, args.concurrency))


if __name__ == "__main__":
    main()
