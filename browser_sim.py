#!/usr/bin/env python3
"""
browser_sim.py - Drive real (headless) browsers to generate genuine user traffic:
video streaming, news browsing with link-following, web search, social/SaaS apps,
GenAI chat, URL-filter category sites, and file downloads.

A real browser puts real browser traffic on the wire (TLS fingerprints, HTTP/2,
media segment fetches, redirects, cookies) - which is what App-ID / App Control,
URL filtering and file inspection are built to recognize.

  * GenAI     - 'chat' types benign / prompt-injection / synthetic-DLP prompts into
                ChatGPT, Gemini and Duck.ai (all usable logged-out) - see ai_sim.py.
  * Personas  - named action lists in config.json ("browser" -> "personas").
  * Sessions  - each persona run launches a fresh browser, so state never leaks.
  * Source IP - browsers can't bind a source IP, so each configured source IP gets
                a tiny local HTTP proxy that makes its upstream connections from
                that IP. The firewall still sees direct client->site connections.
  * QUIC      - disabled by default so traffic is TLS/TCP (decryptable/inspectable).
  * Decryption- Edge/Chrome trust the Windows cert store, so an installed
                forward-trust CA just works; ignore_https_errors covers the rest.

Uses Playwright:  pip install playwright   then   playwright install chromium
(or leave "channel": "msedge" to drive the already-installed Edge).

Imported by web_gen.py (--browser / --browser-only) or run standalone.
"""

import asyncio
import base64
import json
import os
import random
import re
import sys
import threading
import time
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import blockpages

try:
    from playwright.async_api import async_playwright, Error as PlaywrightError
    from playwright.async_api import TimeoutError as PlaywrightTimeout
except ImportError:
    async_playwright = None
    PlaywrightError = PlaywrightTimeout = Exception

# Block pages (Palo Alto, firewall, generic SWG) - see blockpages.py.
BLOCK_MARKERS = blockpages.STRONG_PHRASES

# Chromium net errors that usually mean the firewall reset/refused the session.
RESET_ERRORS = (
    "ERR_CONNECTION_RESET", "ERR_CONNECTION_CLOSED", "ERR_EMPTY_RESPONSE",
    "ERR_TUNNEL_CONNECTION_FAILED", "ERR_CONNECTION_REFUSED", "ERR_SSL_PROTOCOL_ERROR",
    "ERR_CONNECTION_ABORTED",
)

SEARCH_ENGINES = {
    "bing": ("https://www.bing.com/search?q={q}", "li.b_algo h2 a"),
    "google": ("https://www.google.com/search?q={q}", "#search a:has(h3)"),
    "duckduckgo": ("https://duckduckgo.com/?q={q}", "a[data-testid=result-title-a]"),
}

# Cookie / consent buttons worth a quick click so pages (and video) actually load.
CONSENT_BUTTONS = (
    "button:has-text('Accept all')", "button:has-text('Reject all')",
    "button:has-text('Accept All')", "button:has-text('I agree')",
    "button:has-text('Accept')", "#onetrust-accept-btn-handler",
)


@dataclass
class BrowserStats:
    total: int = 0
    ok: int = 0
    blocked: int = 0
    reset: int = 0
    errors: int = 0
    video_seconds: float = 0.0
    downloads: int = 0
    download_bytes: int = 0
    per_persona: dict = field(default_factory=lambda: defaultdict(lambda: defaultdict(int)))
    per_action: dict = field(default_factory=lambda: defaultdict(lambda: defaultdict(int)))
    per_source_ip: dict = field(default_factory=lambda: defaultdict(int))


def _record(stats, persona, action, result, verbose, detail, src_ip):
    stats.total += 1
    stats.per_persona[persona][result] += 1
    stats.per_action[action][result] += 1
    if src_ip:
        stats.per_source_ip[src_ip] += 1
    if result == "ok":
        stats.ok += 1
    elif result == "blocked":
        stats.blocked += 1
    elif result == "reset":
        stats.reset += 1
    else:
        stats.errors += 1
    if verbose:
        tag = {"ok": "ok", "blocked": "BLOCK", "reset": "RESET"}.get(result, "err")
        ip = f" [{src_ip}]" if src_ip else ""
        print(f"[{tag:5}] browser {persona:14} {action:9} {detail}{ip}")


# --------------------------------------------------------------------------- #
# Per-source-IP local proxy
# --------------------------------------------------------------------------- #

class SourceIpProxy:
    """Minimal local HTTP proxy (CONNECT + absolute-URI) whose upstream connections
    are bound to one local source IP. Plain-HTTP requests are forced to
    'Connection: close' so one proxy connection never carries two hosts."""

    def __init__(self, src_ip):
        self.src_ip = src_ip
        self.port = None
        self._server = None

    async def start(self):
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def close(self):
        if self._server:
            self._server.close()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    async def _open(self, host, port):
        return await asyncio.wait_for(
            asyncio.open_connection(host, port, local_addr=(self.src_ip, 0)), 20)

    async def _handle(self, reader, writer):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
            lines = head.split(b"\r\n")
            method, target, version = lines[0].split(b" ", 2)
            if method == b"CONNECT":
                host, _, port = target.decode().rpartition(":")
                up_r, up_w = await self._open(host.strip("[]"), int(port or 443))
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                u = urllib.parse.urlsplit(target.decode())
                if not u.hostname:
                    writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                    writer.close()
                    return
                path = (u.path or "/") + (f"?{u.query}" if u.query else "")
                keep = [ln for ln in lines[1:] if ln and not ln.lower().startswith(
                    (b"proxy-connection:", b"connection:", b"keep-alive:"))]
                up_r, up_w = await self._open(u.hostname, u.port or 80)
                up_w.write(b"\r\n".join(
                    [method + b" " + path.encode() + b" " + version, *keep,
                     b"Connection: close", b"", b""]))
        except Exception:  # noqa: BLE001 - upstream failed; browser sees a proxy error
            try:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            except Exception:  # noqa: BLE001
                pass
            writer.close()
            return
        await asyncio.gather(_pipe(reader, up_w), _pipe(up_r, writer))


async def _pipe(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except Exception:  # noqa: BLE001
        pass
    finally:
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass


# --------------------------------------------------------------------------- #
# Page helpers
# --------------------------------------------------------------------------- #

async def _page_text(page):
    try:
        return (await page.evaluate(
            "() => (document.title + ' ' + (document.body ? document.body.innerText : ''))"
            ".slice(0, 8000)")).lower()
    except Exception:  # noqa: BLE001
        return ""


def _classify_error(exc):
    msg = str(exc)
    if isinstance(exc, PlaywrightTimeout) or "Timeout" in msg:
        return "timeout", "timeout"
    for code in RESET_ERRORS:
        if code in msg:
            return "reset", code
    first = msg.splitlines()[0] if msg else type(exc).__name__
    return "error", first[:120]


async def _goto(page, url, timeout_ms, referer=None):
    """Navigate and classify. Returns (result, detail)."""
    try:
        resp = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms,
                               referer=referer)
    except Exception as exc:  # noqa: BLE001
        return _classify_error(exc)
    text = await _page_text(page)
    status = resp.status if resp else "-"
    if any(m in text for m in BLOCK_MARKERS):
        return "blocked", f"{status} block page"
    if resp and resp.status >= 400:
        return "error", f"HTTP {status}"
    return "ok", f"{status}"


async def _dismiss_consent(page):
    for sel in CONSENT_BUTTONS:
        try:
            btn = page.locator(sel).first
            if await btn.is_visible(timeout=300):
                await btn.click(timeout=2000)
                return
        except Exception:  # noqa: BLE001
            continue


async def _scroll(page, dwell):
    """Read-like behaviour: scroll in steps across the dwell time."""
    end = time.monotonic() + dwell
    while time.monotonic() < end:
        try:
            await page.mouse.wheel(0, random.randint(300, 900))
        except Exception:  # noqa: BLE001
            return
        await asyncio.sleep(random.uniform(1.0, 3.0))


async def _same_site_links(page):
    try:
        return await page.evaluate(
            "() => [...new Set(Array.from(document.querySelectorAll('a[href]'))"
            ".map(a => a.href.split('#')[0])"
            ".filter(h => h.startsWith(location.origin) && h !== location.href))]")
    except Exception:  # noqa: BLE001
        return []


def _unwrap_result(href):
    """Bing wraps results in bing.com/ck/a?...&u=a1<base64url(real url)>."""
    try:
        u = urllib.parse.urlsplit(href)
        if u.netloc.endswith("bing.com") and u.path.startswith("/ck/"):
            enc = urllib.parse.parse_qs(u.query).get("u", [""])[0]
            if enc.startswith("a1"):
                enc = enc[2:]
                return base64.urlsafe_b64decode(enc + "=" * (-len(enc) % 4)).decode()
    except Exception:  # noqa: BLE001
        pass
    return href


async def _find_video_frame(page, timeout):
    """Return the frame holding a <video> (players like Vimeo sit in an iframe)."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        for frame in page.frames:
            try:
                if await frame.evaluate("() => !!document.querySelector('video')"):
                    return frame
            except Exception:  # noqa: BLE001 - frame detached/navigating
                continue
        await asyncio.sleep(1)
    return None


def _dwell(action, cfg):
    lo, hi = action.get("dwell", cfg.get("dwell", [4, 10]))
    return random.uniform(lo, hi)


# --------------------------------------------------------------------------- #
# Actions
# --------------------------------------------------------------------------- #

async def act_browse(ctx, action, rec):
    """Visit a URL, read/scroll, then follow a few same-site links."""
    page, cfg = ctx["page"], ctx["cfg"]
    url = action["url"]
    result, detail = await _goto(page, url, ctx["timeout_ms"])
    rec("browse", result, f"{url}  ({detail})")
    if result != "ok":
        return
    await _dismiss_consent(page)
    await _scroll(page, _dwell(action, cfg))
    for _ in range(int(action.get("follow_links", cfg.get("follow_links", 2)))):
        links = await _same_site_links(page)
        if not links:
            break
        nxt = random.choice(links[:40])
        result, detail = await _goto(page, nxt, ctx["timeout_ms"], referer=page.url)
        rec("link", result, f"{nxt}  ({detail})")
        if result != "ok":
            break
        await _scroll(page, _dwell(action, cfg))


async def act_visit(ctx, action, rec):
    """Load an app/site and linger (SaaS / social login pages are enough for App-ID)."""
    page, cfg = ctx["page"], ctx["cfg"]
    url = action["url"]
    result, detail = await _goto(page, url, ctx["timeout_ms"])
    rec("visit", result, f"{url}  ({detail})")
    if result == "ok":
        await _dismiss_consent(page)
        await _scroll(page, _dwell(action, cfg))


async def act_search(ctx, action, rec):
    """Search on a real engine, then open one of the top results."""
    page, cfg = ctx["page"], ctx["cfg"]
    engine = action.get("engine", "bing")
    tmpl, result_sel = SEARCH_ENGINES.get(engine, SEARCH_ENGINES["bing"])
    query = random.choice(action["queries"]) if "queries" in action else action["query"]
    url = tmpl.format(q=urllib.parse.quote_plus(query))
    result, detail = await _goto(page, url, ctx["timeout_ms"])
    rec("search", result, f"{engine}: {query!r}  ({detail})")
    if result != "ok" or not action.get("open_result", True):
        return
    await _dismiss_consent(page)
    await asyncio.sleep(random.uniform(1, 3))
    try:
        hrefs = await page.locator(result_sel).evaluate_all(
            "els => els.slice(0, 5).map(e => e.href)")
    except Exception:  # noqa: BLE001
        hrefs = []
    if hrefs:
        pick = _unwrap_result(random.choice(hrefs))
        result, detail = await _goto(page, pick, ctx["timeout_ms"], referer=page.url)
        rec("link", result, f"{page.url[:90]}  ({detail})")
        if result == "ok":
            await _scroll(page, _dwell(action, cfg))


_PLAY_JS = """() => {
    const vs = [...document.querySelectorAll('video')].sort((a, b) => b.readyState - a.readyState);
    const v = vs[0];
    if (!v) return 0;
    v.muted = true;
    if (v.paused) v.play().catch(() => {});
    return v.currentTime;
}"""


async def act_video(ctx, action, rec):
    """Play a video for watch_seconds. Pick the video by one of:
      'url'                        - a specific watch page
      'query' / 'queries'          - YouTube search, play the first result
      'list_url' + 'link_pattern'  - open a listing page (e.g. Vimeo Staff Picks) and
                                     play a random link matching the regex; unlike a
                                     fixed url this never goes stale."""
    page = ctx["page"]
    watch = float(action.get("watch_seconds", ctx["cfg"].get("watch_seconds", 45)))
    if "list_url" in action:
        list_url = action["list_url"]
        result, detail = await _goto(page, list_url, ctx["timeout_ms"])
        if result != "ok":
            rec("video", result, f"{list_url}  ({detail})")
            return
        await _dismiss_consent(page)
        await asyncio.sleep(3)  # listing pages fill in client-side
        pattern = re.compile(action.get("link_pattern", r"."))
        try:
            hrefs = await page.evaluate(
                "() => [...new Set([...document.querySelectorAll('a[href]')].map(a => a.href))]")
        except Exception:  # noqa: BLE001
            hrefs = []
        matches = [h for h in hrefs if pattern.search(h)]
        if not matches:
            rec("video", "error", f"{list_url}  (no links matching {pattern.pattern!r})")
            return
        url = random.choice(matches[:10])
    elif "query" in action or "queries" in action:
        query = random.choice(action["queries"]) if "queries" in action else action["query"]
        url = "https://www.youtube.com/results?search_query=" + urllib.parse.quote_plus(query)
        result, detail = await _goto(page, url, ctx["timeout_ms"])
        if result != "ok":
            rec("video", result, f"youtube search {query!r}  ({detail})")
            return
        await _dismiss_consent(page)
        try:
            await page.wait_for_selector("a[href*='/watch?v=']", timeout=15000)
            href = await page.locator("a[href*='/watch?v=']").first.get_attribute("href")
            url = urllib.parse.urljoin("https://www.youtube.com", href)
        except Exception:  # noqa: BLE001
            rec("video", "error", f"youtube search {query!r}  (no results found)")
            return
    else:
        url = action["url"]
    result, detail = await _goto(page, url, ctx["timeout_ms"])
    if result != "ok":
        rec("video", result, f"{url}  ({detail})")
        return
    await _dismiss_consent(page)
    if await _find_video_frame(page, 20) is None:
        rec("video", "error", f"{url}  (no <video> element - blocked or bot-check page?)")
        return
    # Players often swap their placeholder <video> for the real one after load, so
    # keep re-finding it and nudging play() for the whole watch window.
    played = 0.0
    end = time.monotonic() + watch
    while time.monotonic() < end:
        frame = await _find_video_frame(page, 5)
        if frame is not None:
            try:
                played = max(played, await frame.evaluate(_PLAY_JS))
            except Exception:  # noqa: BLE001 - frame navigated/detached mid-check
                pass
        await asyncio.sleep(3)
    if played and played > 1:
        ctx["stats"].video_seconds += played
        rec("video", "ok", f"{url}  (played {played:.0f}s)")
    else:
        text = await _page_text(page)
        if any(m in text for m in BLOCK_MARKERS):
            rec("video", "blocked", f"{url}  (block page)")
        else:
            rec("video", "error", f"{url}  (video never advanced - stalled or blocked mid-stream)")


async def act_download(ctx, action, rec):
    """Download a file through the browser's own network stack (so file blocking,
    AV and WildFire see a normal browser download)."""
    page = ctx["page"]
    url = action["url"]
    downloads = []

    def on_download(dl):
        downloads.append(dl)

    page.on("download", on_download)
    try:
        resp = await page.goto(url, wait_until="domcontentloaded", timeout=ctx["timeout_ms"])
    except Exception as exc:  # noqa: BLE001
        if "Download is starting" not in str(exc):
            result, detail = _classify_error(exc)
            rec("download", result, f"{url}  ({detail})")
            return
        resp = None

    if resp is not None and not downloads:
        page.remove_listener("download", on_download)
        # Served inline (PDF viewer, text) or replaced by a block page - either way
        # the browser fetched the whole response through the firewall.
        text = await _page_text(page)
        if any(m in text for m in BLOCK_MARKERS):
            rec("download", "blocked", f"{url}  ({resp.status} block page)")
        elif resp.status >= 400:
            rec("download", "error", f"{url}  (HTTP {resp.status})")
        else:
            # The PDF viewer keeps only a stub body, so trust Content-Length if larger.
            size = int(resp.headers.get("content-length", 0) or 0)
            try:
                size = max(size, len(await resp.body()))
            except Exception:  # noqa: BLE001 - body not retained for some viewers
                pass
            ctx["stats"].downloads += 1
            ctx["stats"].download_bytes += size
            shown = f"{size / 1024:.1f} KiB" if size else "size n/a"
            rec("download", "ok", f"{url}  (opened inline, {shown})")
        return

    for _ in range(50):  # the download event can trail the goto error slightly
        if downloads:
            break
        await asyncio.sleep(0.1)
    page.remove_listener("download", on_download)
    if not downloads:
        rec("download", "error", f"{url}  (no download started)")
        return
    try:
        path = await downloads[0].path()  # waits for the transfer to finish
        failure = await downloads[0].failure()
    except Exception as exc:  # noqa: BLE001
        result, detail = _classify_error(exc)
        rec("download", result, f"{url}  ({detail})")
        return
    if failure:
        result = "reset" if any(c.lower() in failure.lower() for c in ("network", "reset", "fail")) else "error"
        rec("download", result, f"{url}  (download failed: {failure})")
        return
    size = os.path.getsize(path) if path and os.path.exists(path) else 0
    ctx["stats"].downloads += 1
    ctx["stats"].download_bytes += size
    rec("download", "ok", f"{url}  ({size / 1024:.0f} KiB)")


async def act_category(ctx, action, rec):
    """Browse N random URLs from a web_gen URL-filter category in config.json."""
    urls = ctx["categories"].get(action["name"], {}).get("urls", [])
    if not urls:
        rec("category", "error", f"{action['name']}  (no such category / no urls)")
        return
    for url in random.sample(urls, min(int(action.get("count", 2)), len(urls))):
        result, detail = await _goto(ctx["page"], url, ctx["timeout_ms"])
        rec("category", result, f"[{action['name']}] {url}  ({detail})")
        if result == "ok":
            await _scroll(ctx["page"], _dwell(action, ctx["cfg"]) / 2)


CHAT_INPUTS = "#prompt-textarea, textarea, div[contenteditable='true'], [role='textbox']"
# Some chat UIs (Duck.ai) only ask for terms acceptance after the first prompt.
POST_SUBMIT_BUTTONS = ("button:has-text('Continue')", "button:has-text('Agree')",
                       "button:has-text('Get Started')", "button:has-text('Accept')")


async def _chat_input(page):
    boxes = page.locator(CHAT_INPUTS)
    for i in range(await boxes.count()):
        box = boxes.nth(i)
        try:
            if await box.is_visible():
                return box
        except Exception:  # noqa: BLE001
            continue
    return None


def _marker(text):
    """A distinctive word from the prompt, to spot it in outgoing request bodies."""
    words = re.findall(r"[A-Za-z0-9]{5,}", text)
    return max(words, key=len).lower().encode() if words else None


async def act_chat(ctx, action, rec):
    """Type prompts into a GenAI chat UI (works logged-out on ChatGPT, Gemini, Duck.ai).
    A prompt counts as sent only if its text is seen leaving in a request body."""
    import ai_sim  # prompt sets + mix picker live with the API-side generator
    page, cfg = ctx["page"], ctx["cfg"]
    url = action["url"]
    site = urllib.parse.urlsplit(url).netloc
    result, detail = await _goto(page, url, ctx["timeout_ms"])
    if result != "ok":
        rec("chat", result, f"{url}  ({detail})")
        return
    await asyncio.sleep(3)
    await _dismiss_consent(page)
    mix = action.get("mix", cfg.get("chat_mix", {"benign": 5, "injection": 3, "dlp": 2}))
    for kind, text in ai_sim.pick_prompts(ctx["prompts"], int(action.get("prompts", 2)),
                                          mix, random):
        box = await _chat_input(page)
        if box is None:
            rec("chat", "error", f"{site}: no chat box (login wall or bot check?)")
            return
        marker, seen = _marker(text), []

        def on_request(req, marker=marker, seen=seen):
            try:
                if marker and marker in (req.post_data_buffer or b"").lower():
                    seen.append(req.url)
            except Exception:  # noqa: BLE001
                pass

        page.on("request", on_request)
        try:
            try:
                await box.click(timeout=5000)
            except Exception:  # noqa: BLE001 - overlay in the way
                await box.focus()
            for n, line in enumerate(text.split("\n")):
                if n:
                    await page.keyboard.press("Shift+Enter")  # newline without sending
                await page.keyboard.type(line, delay=random.randint(8, 25))
            await page.keyboard.press("Enter")
            await asyncio.sleep(2)
            for sel in POST_SUBMIT_BUTTONS:
                try:
                    btn = page.locator(sel).first
                    if await btn.is_visible(timeout=300):
                        await btn.click(timeout=2000)
                        break
                except Exception:  # noqa: BLE001
                    continue
            end = time.monotonic() + float(action.get("wait_seconds", 15))
            while time.monotonic() < end and not seen:
                await asyncio.sleep(0.5)
            if seen:  # let the answer stream for a bit, like a person reading it
                await asyncio.sleep(random.uniform(3, 8))
        finally:
            page.remove_listener("request", on_request)
        label = f"{site} [{kind}] {' '.join(text.split())[:50]}"
        page_text = await _page_text(page)
        if any(m in page_text for m in BLOCK_MARKERS):
            rec("chat", "blocked", f"{label}  (block page)")
        elif seen:
            rec("chat", "ok", f"{label}  (sent)")
        else:
            rec("chat", "error", f"{label}  (typed, but not seen leaving - UI changed?)")


ACTIONS = {
    "chat": act_chat,
    "browse": act_browse,
    "visit": act_visit,
    "search": act_search,
    "video": act_video,
    "download": act_download,
    "category": act_category,
}


# --------------------------------------------------------------------------- #
# Sessions / orchestration
# --------------------------------------------------------------------------- #

def _user_agent(version, channel):
    """Headless Chromium advertises 'HeadlessChrome' - many sites bot-check that."""
    ua = (f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          f"(KHTML, like Gecko) Chrome/{version} Safari/537.36")
    if channel == "msedge":
        ua += f" Edg/{version}"
    return ua


async def _launch(pw, cfg, proxy_url):
    args = ["--autoplay-policy=no-user-gesture-required", "--mute-audio",
            "--disable-blink-features=AutomationControlled"]
    if cfg.get("disable_quic", True):
        args.append("--disable-quic")
    kwargs = {"headless": cfg.get("headless", True), "args": args}
    if proxy_url:
        kwargs["proxy"] = {"server": proxy_url}
    channel = cfg.get("channel", "msedge") or None
    try:
        return await pw.chromium.launch(channel=channel, **kwargs), channel
    except Exception as exc:  # noqa: BLE001 - e.g. Edge not installed
        if channel is None:
            raise
        print(f"[browser] could not launch channel {channel!r} ({str(exc).splitlines()[0]}); "
              "falling back to bundled Chromium")
        return await pw.chromium.launch(**kwargs), None


async def _run_session(pw, persona_name, persona, src_ip, proxy, shared, stats, verbose):
    cfg = shared["cfg"]
    browser, channel = await _launch(pw, cfg, proxy.url if proxy else None)
    try:
        context = await browser.new_context(
            ignore_https_errors=cfg.get("ignore_https_errors", True),
            accept_downloads=True,
            user_agent=_user_agent(browser.version, channel),
            viewport={"width": 1366, "height": 768},
        )
        page = await context.new_page()
        ctx = {"page": page, "cfg": cfg, "stats": stats, "categories": shared["categories"],
               "prompts": shared["prompts"],
               "timeout_ms": int(cfg.get("nav_timeout", 30)) * 1000}

        def rec(action, result, detail):
            _record(stats, persona_name, action, result, verbose, detail, src_ip)

        actions = list(persona.get("actions", []))
        if persona.get("shuffle", True):
            random.shuffle(actions)
        for action in actions:
            fn = ACTIONS.get(action.get("type"))
            if fn is None:
                rec(str(action.get("type")), "error", "unknown action type")
                continue
            try:
                await fn(ctx, action, rec)
            except Exception as exc:  # noqa: BLE001 - keep the session going
                result, detail = _classify_error(exc)
                rec(action.get("type"), result, detail)
        await context.close()
    finally:
        await browser.close()


async def _browser_phase(cfg, categories, source_ips, stats, verbose, prompts=None):
    personas = {n: p for n, p in cfg.get("personas", {}).items() if p.get("enabled", True)}
    if not personas:
        print("[browser] no enabled personas in config - skipping")
        return
    source_ips = [ip for ip in (source_ips or []) if ip] or [None]

    # One local proxy per real source IP ([None] = no proxy, OS default source).
    proxies = {ip: (await SourceIpProxy(ip).start()) if ip else None for ip in source_ips}

    queue = asyncio.Queue()
    for name, persona in personas.items():
        for _ in range(int(persona.get("sessions", 1))):
            queue.put_nowait((name, persona))
    if prompts is None:
        import ai_sim
        prompts = ai_sim.build_prompts()
    shared = {"cfg": cfg, "categories": categories or {}, "prompts": prompts}
    ip_cycle = iter(range(10**9))

    async def worker(pw):
        while True:
            try:
                name, persona = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            ip = source_ips[next(ip_cycle) % len(source_ips)]
            if verbose:
                print(f"[browser] session start: {name}" + (f" from {ip}" if ip else ""))
            try:
                await _run_session(pw, name, persona, ip, proxies[ip], shared, stats, verbose)
            except Exception as exc:  # noqa: BLE001
                _record(stats, name, "session", "error", verbose,
                        f"browser session failed: {str(exc).splitlines()[0][:160]}", ip)

    try:
        async with async_playwright() as pw:
            n_workers = max(1, min(int(cfg.get("workers", 3)), queue.qsize()))
            await asyncio.gather(*(worker(pw) for _ in range(n_workers)))
    finally:
        for p in proxies.values():
            if p:
                await p.close()


def _run_blocking(cfg, categories, source_ips, stats, verbose, prompts=None):
    """Playwright launches the browser as a subprocess, which on Windows needs a
    Proactor loop - but dns_gen installs the Selector policy (aiodns needs it). So
    the browser phase gets its own Proactor loop in its own thread."""
    loop = asyncio.ProactorEventLoop() if sys.platform == "win32" else asyncio.new_event_loop()

    def quiet_resets(lp, context):
        # Proactor logs a traceback for every peer reset on the proxy sockets -
        # routine behind a firewall, so drop those and keep everything else.
        if isinstance(context.get("exception"),
                      (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
            return
        lp.default_exception_handler(context)

    loop.set_exception_handler(quiet_resets)
    try:
        loop.run_until_complete(
            _browser_phase(cfg, categories, source_ips, stats, verbose, prompts))
    finally:
        loop.close()


async def run_browser_phase(cfg, categories=None, source_ips=None, stats=None, verbose=False,
                            prompts=None):
    stats = stats or BrowserStats()
    if async_playwright is None:
        print("[browser] playwright not installed - skipping "
              "(pip install playwright && playwright install chromium)")
        return stats
    loop = asyncio.get_running_loop()
    fut = loop.create_future()

    def _settle(setter, value):
        if not fut.done():
            setter(value)

    def worker():
        try:
            _run_blocking(cfg, categories, source_ips, stats, verbose, prompts)
            outcome = (fut.set_result, stats)
        except BaseException as exc:  # noqa: BLE001
            outcome = (fut.set_exception, exc)
        try:
            loop.call_soon_threadsafe(_settle, *outcome)
        except RuntimeError:  # main loop already closed (Ctrl+C)
            pass

    # Daemon thread: Ctrl+C exits promptly instead of waiting on open browsers.
    threading.Thread(target=worker, name="browser-sim", daemon=True).start()
    return await fut


def print_browser_report(stats: BrowserStats):
    print("\n" + "=" * 70)
    print("BROWSER SIMULATION RESULTS")
    print("=" * 70)
    print(f"  page actions : {stats.total}")
    print(f"  ok           : {stats.ok}")
    print(f"  blocked      : {stats.blocked}   (block page seen)")
    print(f"  reset        : {stats.reset}   (connection reset/refused - likely firewall)")
    print(f"  errors       : {stats.errors}")
    print(f"  video watched: {stats.video_seconds:.0f}s")
    print(f"  downloads    : {stats.downloads} ({stats.download_bytes / 1024:.0f} KiB)")
    for title, table in (("by persona", stats.per_persona), ("by action", stats.per_action)):
        print(f"\n  {title}:")
        print(f"    {'name':18} {'ok':>5} {'block':>6} {'reset':>6} {'other':>6}")
        for name in sorted(table):
            d = table[name]
            other = sum(v for k, v in d.items() if k not in ("ok", "blocked", "reset"))
            print(f"    {name:18} {d.get('ok', 0):5} {d.get('blocked', 0):6} "
                  f"{d.get('reset', 0):6} {other:6}")
    if stats.per_source_ip:
        print("\n  by source IP:")
        for ip in sorted(stats.per_source_ip):
            print(f"    {ip:16} {stats.per_source_ip[ip]}")
    print("=" * 70)


def main():
    import argparse
    p = argparse.ArgumentParser(description="Real-browser user traffic simulator.")
    p.add_argument("--config", default="config.json")
    p.add_argument("--personas", nargs="*", metavar="NAME",
                   help="Only run these personas (overrides 'enabled').")
    p.add_argument("--headed", action="store_true", help="Show the browser windows.")
    p.add_argument("--workers", type=int, default=None, help="Parallel browsers.")
    p.add_argument("--source-ips", nargs="*", metavar="IP", default=None,
                   help="Source IPs (or 'auto'). Overrides 'source_ips' in config.json.")
    args = p.parse_args()
    if async_playwright is None:
        sys.exit("playwright required: pip install playwright && playwright install chromium")

    import dns_gen  # source-IP helpers
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = Path(__file__).parent / config_path
    full_cfg = json.loads(config_path.read_text(encoding="utf-8"))
    cfg = apply_cli(full_cfg.get("browser", {}), args.personas, args.headed, args.workers)
    source_ips = dns_gen.resolve_source_ips(args.source_ips, full_cfg.get("source_ips", []))
    dns_gen.check_source_ips(source_ips)
    stats = BrowserStats()
    try:
        import ai_sim
        _run_blocking(cfg, full_cfg.get("categories", {}), source_ips, stats, True,
                      ai_sim.build_prompts(full_cfg.get("ai", {})))
    except KeyboardInterrupt:
        print("\nInterrupted.")
    print_browser_report(stats)


def apply_cli(cfg, personas=None, headed=False, workers=None):
    """Return a copy of the browser config with CLI overrides applied."""
    cfg = dict(cfg)
    if personas:
        cfg["personas"] = {n: dict(p, enabled=True)
                           for n, p in cfg.get("personas", {}).items() if n in personas}
    if headed:
        cfg["headless"] = False
    if workers:
        cfg["workers"] = workers
    return cfg


if __name__ == "__main__":
    main()
