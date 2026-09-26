#!/usr/bin/env python3
"""
app_control.py - Generate real application-protocol traffic to exercise firewall
Application Control (App Control uses DPI on protocol behavior, not URLs).

Covers:
  * BitTorrent - HTTP tracker announce (info_hash/peer_id/port + BT user-agent)
                 and DHT ping (UDP bencode) to real DHT bootstrap nodes.
  * Proxy      - HTTP CONNECT and absolute-URI requests (proxy semantics).
  * Tor        - a REAL Tor circuit via torpy (pure-Python Tor client), which
                 puts genuine Tor TLS on the wire for the firewall to detect.

Client-side block detection is best-effort: an App Control block is a mid-session
reset, which is hard to tell from an ordinary reset. The authoritative proof is the
firewall App Control / App-ID log - this tool's job is to GENERATE the traffic.

Imported by web_gen.py (--apps / --apps-only) or run standalone.
"""

import asyncio
import logging
import os
import random
import socket
import sys
import threading
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

try:
    import aiohttp
except ImportError:
    aiohttp = None

import blockpages

import ssl as _ssl
# torpy (unmaintained) calls ssl.wrap_socket, removed in Python 3.12+. Shim it with a
# modern SSLContext. Tor relays use self-signed certs, so no verification (matches the
# old default) - fine here; the Tor protocol does its own relay authentication.
if not hasattr(_ssl, "wrap_socket"):
    def _wrap_socket(sock, keyfile=None, certfile=None, server_side=False,
                     cert_reqs=_ssl.CERT_NONE, ssl_version=None, ca_certs=None,
                     do_handshake_on_connect=True, suppress_ragged_eofs=True,
                     ciphers=None, **_):
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER if server_side else _ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        if certfile:
            ctx.load_cert_chain(certfile, keyfile)
        if ca_certs:
            ctx.load_verify_locations(ca_certs)
        if ciphers:
            ctx.set_ciphers(ciphers)
        return ctx.wrap_socket(sock, server_side=server_side,
                               do_handshake_on_connect=do_handshake_on_connect,
                               suppress_ragged_eofs=suppress_ragged_eofs)
    _ssl.wrap_socket = _wrap_socket

try:
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # torpy pulls in a deprecated crypto primitive
        from torpy import TorClient  # real Tor client (optional)
except ImportError:
    TorClient = None

BT_USER_AGENT = "uTorrent/3550(44348)"

# Real DHT bootstrap nodes (UDP 6881).
DHT_NODES = [
    ("router.bittorrent.com", 6881),
    ("dht.transmissionbt.com", 6881),
    ("router.utorrent.com", 6881),
]

BLOCK_MARKERS = ("web page blocked", "fortiguard", "application", "blocked",
                 "high security alert")


@dataclass
class AppStats:
    total: int = 0
    blocked: int = 0
    passed: int = 0
    errors: int = 0
    per_app: dict = field(default_factory=lambda: defaultdict(lambda: defaultdict(int)))


def _record(stats, app, result, verbose, detail, src_ip):
    stats.total += 1
    stats.per_app[app][result] += 1
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
        print(f"[{tag:5}] {app:18} {detail}{ip}")


# --------------------------------------------------------------------------- #
# BitTorrent
# --------------------------------------------------------------------------- #

def _announce_query():
    info_hash = os.urandom(20)
    peer_id = b"-UT3550-" + os.urandom(12)
    q = {
        "info_hash": info_hash, "peer_id": peer_id, "port": 6881,
        "uploaded": 0, "downloaded": 0, "left": 0, "compact": 1, "event": "started",
    }
    return urllib.parse.urlencode(q)


async def bt_announce(session, sem, tracker, stats, verbose, src_ip):
    sep = "&" if "?" in tracker else "?"
    url = f"{tracker}{sep}{_announce_query()}"
    headers = {"User-Agent": BT_USER_AGENT}
    async with sem:
        try:
            async with session.get(url, headers=headers, ssl=False) as resp:
                chunk = await resp.content.read(4096)
                low = chunk.decode("utf-8", "ignore").lower()
                result = "blocked" if blockpages.looks_blocked(low, BLOCK_MARKERS) else "passed"
                _record(stats, "bittorrent-announce", result, verbose, tracker, src_ip)
        except (aiohttp.ServerDisconnectedError, aiohttp.ClientConnectionError,
                ConnectionResetError):
            _record(stats, "bittorrent-announce", "blocked", verbose, f"{tracker} (reset)", src_ip)
        except Exception as exc:  # noqa: BLE001
            _record(stats, "bittorrent-announce", "error", verbose,
                    f"{tracker} ({type(exc).__name__})", src_ip)


def _dht_ping():
    tid = os.urandom(2)
    node_id = os.urandom(20)
    # bencoded: d1:ad2:id20:<id>e1:q4:ping1:t2:<tid>1:y1:qe
    return (b"d1:ad2:id20:" + node_id + b"e1:q4:ping1:t2:" + tid + b"1:y1:qe")


async def dht_ping(sem, host, port, stats, verbose, src_ip):
    loop = asyncio.get_running_loop()
    sock = None
    async with sem:
        try:
            addr = await loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
            family, _, _, _, sockaddr = addr[0]
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.setblocking(False)
            if src_ip:
                try:
                    sock.bind((src_ip, 0))
                except OSError:
                    pass
            sock.connect(sockaddr)  # UDP "connect" fixes the peer for send/recv
            await loop.sock_sendall(sock, _dht_ping())
            try:
                data = await asyncio.wait_for(loop.sock_recv(sock, 1024), timeout=4)
                result = "passed" if data else "error"
            except asyncio.TimeoutError:
                result = "error"  # no reply != blocked (UDP is lossy)
            _record(stats, "bittorrent-dht", result, verbose, f"{host}:{port}", src_ip)
        except Exception as exc:  # noqa: BLE001
            _record(stats, "bittorrent-dht", "error", verbose,
                    f"{host}:{port} ({type(exc).__name__})", src_ip)
        finally:
            if sock is not None:
                sock.close()


# --------------------------------------------------------------------------- #
# Proxy
# --------------------------------------------------------------------------- #

async def _raw_send(sem, host, port, payload, app, detail, stats, verbose, src_ip):
    async with sem:
        writer = None
        try:
            local = (src_ip, 0) if src_ip else None
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, local_addr=local), timeout=8)
            writer.write(payload)
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=6)
                result = "passed" if data else "blocked"  # clean close w/o data ~ reset
            except asyncio.TimeoutError:
                result = "passed"  # connection held open, no reset
            _record(stats, app, result, verbose, detail, src_ip)
        except (ConnectionResetError, asyncio.IncompleteReadError):
            _record(stats, app, "blocked", verbose, f"{detail} (reset)", src_ip)
        except Exception as exc:  # noqa: BLE001
            _record(stats, app, "error", verbose, f"{detail} ({type(exc).__name__})", src_ip)
        finally:
            if writer is not None:
                writer.close()


async def proxy_connect(sem, host, port, target, stats, verbose, src_ip):
    payload = (f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
               f"User-Agent: proxytest\r\nProxy-Connection: keep-alive\r\n\r\n").encode()
    await _raw_send(sem, host, port, payload, "proxy-connect", f"{host}:{port} CONNECT {target}",
                    stats, verbose, src_ip)


async def proxy_absolute_uri(sem, host, port, uri, stats, verbose, src_ip):
    parsed = urllib.parse.urlparse(uri)
    payload = (f"GET {uri} HTTP/1.1\r\nHost: {parsed.hostname}\r\n"
               f"User-Agent: proxytest\r\nProxy-Connection: keep-alive\r\n\r\n").encode()
    await _raw_send(sem, host, port, payload, "proxy-http", f"{host}:{port} GET {uri}",
                    stats, verbose, src_ip)


# --------------------------------------------------------------------------- #
# Tor (real circuit via torpy)
# --------------------------------------------------------------------------- #

def _tor_probe_blocking(target_host, target_port):
    """Build a real Tor circuit and fetch a few bytes. Returns (ok, detail)."""
    with TorClient() as tor:
        with tor.create_circuit(3) as circuit:
            with circuit.create_stream((target_host, target_port)) as stream:
                stream.send(b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % target_host.encode())
                data = stream.recv(1024)
                return bool(data), f"circuit ok, {len(data)}B via Tor"


def _run_in_daemon_thread(fn, *args):
    """Like asyncio.to_thread, but in a daemon thread. torpy blocks on sockets and
    retries guards for minutes; a daemon thread lets Ctrl+C / timeout exit promptly
    instead of the interpreter waiting on the executor at shutdown."""
    loop = asyncio.get_running_loop()
    fut = loop.create_future()

    def _settle(setter, value):
        if not fut.done():
            setter(value)

    def worker():
        try:
            outcome = (fut.set_result, fn(*args))
        except BaseException as exc:  # noqa: BLE001
            outcome = (fut.set_exception, exc)
        try:
            loop.call_soon_threadsafe(_settle, *outcome)
        except RuntimeError:  # loop already closed (timed out / Ctrl+C)
            pass

    threading.Thread(target=worker, name="tor-probe", daemon=True).start()
    return fut


class _GuardLogHandler(logging.Handler):
    """Surface torpy's (INFO-level) guard-connect lines so you know which relay
    IP:port to look for in the firewall logs."""

    def emit(self, record):
        msg = record.getMessage()
        if msg.startswith("Connecting to guard node"):
            print(f"[app-control] tor: {msg}")


async def tor_probe(stats, verbose, target_host="example.com", target_port=80, timeout=90):
    if TorClient is None:
        print("[app-control] torpy not installed - skipping Tor (pip install torpy)")
        return
    if verbose:
        print("[app-control] building real Tor circuit (may take 10-40s)...")
        print("[app-control] tor: torpy uses the OS default source IP (not source_ips); "
              "filter firewall logs on the guard IPs below")
        guard_log = logging.getLogger("torpy.guard")
        if not any(isinstance(h, _GuardLogHandler) for h in guard_log.handlers):
            guard_log.addHandler(_GuardLogHandler())
        guard_log.setLevel(logging.INFO)
    # Either way, torpy makes real TLS connections to Tor guard relays - that is the
    # traffic App Control detects. Whether the circuit *completes* depends on the
    # network (and whether the firewall blocks Tor), so a failure is not, by itself,
    # proof of a block - confirm in the firewall App Control / App-ID log.
    try:
        ok, detail = await asyncio.wait_for(
            _run_in_daemon_thread(_tor_probe_blocking, target_host, target_port), timeout=timeout)
        _record(stats, "tor", "passed" if ok else "error", verbose, detail, None)
    except asyncio.TimeoutError:
        _record(stats, "tor", "error", verbose,
                "circuit not established in time (Tor traffic still sent - check firewall log)", None)
    except Exception as exc:  # noqa: BLE001
        _record(stats, "tor", "error", verbose,
                f"circuit not established ({type(exc).__name__}: {exc}) - Tor traffic still sent, check firewall log", None)


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

async def run_app_phase(cfg, sessions, sem, stats=None, verbose=False,
                        source_ips=None, do_tor=True):
    stats = stats or AppStats()
    source_ips = source_ips or [None]
    bt = cfg.get("bittorrent", {})
    px = cfg.get("proxy", {})
    tor_cfg = cfg.get("tor", {})

    trackers = bt.get("trackers", ["http://example.com/announce"])
    dht_nodes = [tuple(n) for n in bt.get("dht_nodes", DHT_NODES)]
    connect_host, connect_port = (px.get("host", "example.com"), px.get("port", 80))
    connect_targets = px.get("connect_targets", ["www.google.com:443"])
    abs_uris = px.get("absolute_uris", ["http://www.google.com/"])

    tasks = []
    i = 0

    def next_ip():
        nonlocal i
        ip = source_ips[i % len(source_ips)]
        i += 1
        return ip

    for tr in trackers:
        src_ip, session = sessions[i % len(sessions)]
        tasks.append(asyncio.create_task(bt_announce(session, sem, tr, stats, verbose, src_ip)))
        i += 1
    for host, port in dht_nodes:
        tasks.append(asyncio.create_task(dht_ping(sem, host, port, stats, verbose, next_ip())))
    for tgt in connect_targets:
        tasks.append(asyncio.create_task(
            proxy_connect(sem, connect_host, connect_port, tgt, stats, verbose, next_ip())))
    for uri in abs_uris:
        tasks.append(asyncio.create_task(
            proxy_absolute_uri(sem, connect_host, connect_port, uri, stats, verbose, next_ip())))

    await asyncio.gather(*tasks)

    # Tor last (slow, blocking circuit build).
    if do_tor and tor_cfg.get("enabled", True):
        th = tor_cfg.get("target_host", "example.com")
        tp = int(tor_cfg.get("target_port", 80))
        await tor_probe(stats, verbose, th, tp, timeout=int(tor_cfg.get("timeout", 90)))

    return stats


def print_app_report(stats: AppStats):
    print("\n" + "=" * 70)
    print("APP CONTROL RESULTS  (best-effort; firewall App Control / App-ID log is authoritative)")
    print("=" * 70)
    print(f"  sessions  : {stats.total}")
    print(f"  blocked?  : {stats.blocked}   (reset mid-session - may be App Control)")
    print(f"  passed    : {stats.passed}")
    print(f"  errors    : {stats.errors}")
    print("\n  by app:")
    print(f"    {'app':22} {'blocked?':>9} {'passed':>7} {'err':>5}")
    for app in sorted(stats.per_app):
        d = stats.per_app[app]
        print(f"    {app:22} {d.get('blocked', 0):9} {d.get('passed', 0):7} {d.get('error', 0):5}")
    print("\n  -> confirm actual detections in the firewall App Control / App-ID log.")
    print("=" * 70)


async def _standalone(cfg, concurrency, do_tor):
    timeout = aiohttp.ClientTimeout(total=15)
    conn = aiohttp.TCPConnector(ssl=False, force_close=True)
    async with aiohttp.ClientSession(timeout=timeout, connector=conn) as s:
        stats = await run_app_phase(cfg, [(None, s)], asyncio.Semaphore(concurrency),
                                    verbose=True, do_tor=do_tor)
    print_app_report(stats)


def main():
    import argparse
    p = argparse.ArgumentParser(description="Application Control / App-ID traffic generator.")
    p.add_argument("--config", default="config.json")
    p.add_argument("--concurrency", type=int, default=10)
    p.add_argument("--no-tor", action="store_true", help="Skip the Tor circuit.")
    args = p.parse_args()
    if aiohttp is None:
        sys.exit("aiohttp required. Activate venv and pip install -r requirements.txt")
    import json
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = Path(__file__).parent / config_path
    cfg = json.loads(config_path.read_text(encoding="utf-8")).get("app_control", {})
    asyncio.run(_standalone(cfg, args.concurrency, not args.no_tor))


if __name__ == "__main__":
    main()
