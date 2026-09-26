#!/usr/bin/env python3
"""
wildfire.py - Get files in front of sandbox analysis (Palo Alto WildFire, or any
"forward unknown files to the cloud" feature).

Two kinds of files:

  * Vendor test files - Palo Alto's official WildFire test files
    (wildfire.paloaltonetworks.com/publicapi/test/{pe,elf,macos,apk}). Harmless,
    but every download is a NEW sample that WildFire rules MALICIOUS - the
    end-to-end proof that forwarding, verdicts, and signature/verdict blocking work.
  * Unique generated files - harmless EXE/DLL/ELF/PDF/Office/script/archive files
    with random content, so their hashes have never been seen and the firewall must
    forward them for analysis (a known hash is just looked up, never re-submitted).
    Each is sent both ways: UPLOADED (POST to an echo endpoint) and DOWNLOADED
    (served back by an endpoint that decodes base64 from the URL). Expect BENIGN.

The report lists the SHA-256 of every generated file so you can search for them
in Monitor > WildFire Submissions. The files are never written to disk.

Imported by web_gen.py (--wildfire / --wildfire-only) or run standalone.
"""

import asyncio
import base64
import hashlib
import io
import json
import os
import struct
import sys
import time
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

try:
    import aiohttp
except ImportError:
    aiohttp = None

import blockpages
import file_filter

DEFAULT_TEST_FILES = [
    "http://wildfire.paloaltonetworks.com/publicapi/test/pe",
    "http://wildfire.paloaltonetworks.com/publicapi/test/elf",
    "http://wildfire.paloaltonetworks.com/publicapi/test/macos",
    "http://wildfire.paloaltonetworks.com/publicapi/test/apk",
]

# Magic bytes that prove a real test file (not a block page) came back.
MAGIC = {
    "pe": (b"MZ",),
    "elf": (b"\x7fELF",),
    "apk": (b"PK",),
    "macos": (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"PK", b"xar!"),
}

DOWNLOAD_URL = "https://httpbingo.org/base64/decode/{b64}"  # echoes decoded bytes
MAX_DOWNLOAD_BYTES = 6000  # the base64 rides in the URL; ~8 KB URLs are the safe limit


# --------------------------------------------------------------------------- #
# Unique, harmless files
# --------------------------------------------------------------------------- #

def _token():
    return f"wf-test-{int(time.time())}-{os.urandom(8).hex()}"


def _pe(token, dll=False):
    # Headers from file_filter + an overlay of random bytes and the token: a valid
    # PE shape with a hash nobody has seen before.
    return file_filter._make_pe(dll=dll) + os.urandom(2048) + token.encode()


def _elf(token):
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8     # 64-bit, LE, SysV
    hdr = struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x400078, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    return ident + hdr + os.urandom(2048) + token.encode()


def _pdf(token, with_js=False):
    js = (b"/OpenAction << /S /JavaScript /JS (app.alert\\('" + token.encode() + b"'\\);) >>"
          if with_js else b"")
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R " + js + b" >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> >>",
    ]
    text = b"BT /F1 12 Tf 72 720 Td (Harmless sandbox test document " + token.encode() + b") Tj ET"
    objs.append(b"<< /Length " + str(len(text)).encode() + b" >>\nstream\n" + text + b"\nendstream")
    out, offsets = io.BytesIO(), []
    out.write(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    for i, body in enumerate(objs, 1):
        offsets.append(out.tell())
        out.write(f"{i} 0 obj\n".encode() + body + b"\nendobj\n")
    xref = out.tell()
    out.write(f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode())
    for off in offsets:
        out.write(f"{off:010d} 00000 n \n".encode())
    out.write(f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return out.getvalue()


def _docx(token):
    parts = {
        "[Content_Types].xml":
            '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/'
            'package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.'
            'openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType='
            '"application/xml"/><Override PartName="/word/document.xml" ContentType="application/'
            'vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
        "_rels/.rels":
            '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.'
            'openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://'
            'schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="word/document.xml"/></Relationships>',
        "word/document.xml":
            '<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.'
            'openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Harmless '
            f'sandbox test document {token}</w:t></w:r></w:p></w:body></w:document>',
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in parts.items():
            z.writestr(name, data)
    return buf.getvalue()


def _zip_with(name, blob):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(name, blob)
    return buf.getvalue()


def generate_files(types=None):
    """(type, filename, bytes) - fresh random content on every call."""
    t = _token()
    makers = {
        "exe": lambda: ("setup_tool.exe", _pe(t)),
        "dll": lambda: ("helper.dll", _pe(t, dll=True)),
        "elf": lambda: ("agent.bin", _elf(t)),
        "pdf": lambda: ("invoice.pdf", _pdf(t)),
        "pdf_js": lambda: ("statement.pdf", _pdf(t, with_js=True)),
        "docx": lambda: ("report.docx", _docx(t)),
        "ps1": lambda: ("update.ps1", f"# {t}\nWrite-Output 'harmless sandbox test'\n"
                                      "Get-Date | Out-Null\n".encode()),
        "js": lambda: ("notice.js", f"// {t}\nWScript.Echo('harmless sandbox test');\n".encode()),
        "vbs": lambda: ("notice.vbs", f"' {t}\nWScript.Echo \"harmless sandbox test\"\n".encode()),
        "bat": lambda: ("run.bat", f"@echo off\nrem {t}\necho harmless sandbox test\n".encode()),
        "zip_exe": lambda: ("bundle.zip", _zip_with("setup_tool.exe", _pe(t))),
    }
    return [(k, *makers[k]()) for k in (types or makers) if k in makers]


# --------------------------------------------------------------------------- #
# Stats
# --------------------------------------------------------------------------- #

@dataclass
class WildfireStats:
    total: int = 0
    transferred: int = 0  # the whole file crossed the firewall - eligible for forwarding
    blocked: int = 0      # block page (e.g. WildFire/AV signature block)
    reset: int = 0        # reset mid-transfer - usually the firewall
    errors: int = 0
    per_item: dict = field(default_factory=lambda: defaultdict(lambda: defaultdict(int)))
    hashes: list = field(default_factory=list)  # (type, filename, sha256)


def _record(stats, item, result, verbose, detail, src_ip):
    stats.total += 1
    stats.per_item[item][result] += 1
    setattr(stats, result, getattr(stats, result) + 1)
    if verbose:
        tag = {"transferred": "xfer", "blocked": "BLOCK", "reset": "RESET"}.get(result, "err")
        ip = f" [{src_ip}]" if src_ip else ""
        print(f"[{tag:5}] wildfire {item:18} {detail}{ip}")


def _exc_result(exc):
    msg = str(exc).lower()
    if isinstance(exc, (aiohttp.ServerDisconnectedError, ConnectionResetError)) or any(
            s in msg for s in ("reset", "10054", "forcibly closed", "connection aborted")):
        return "reset"
    return "errors"


async def _guard(coro, stats, item, verbose, label, src_ip):
    try:
        await coro
    except asyncio.TimeoutError:
        _record(stats, item, "errors", verbose, f"timeout  {label}", src_ip)
    except (aiohttp.ClientError, ConnectionResetError) as exc:
        _record(stats, item, _exc_result(exc), verbose,
                f"{type(exc).__name__}: {exc}  {label}", src_ip)


# --------------------------------------------------------------------------- #
# Transfers
# --------------------------------------------------------------------------- #

async def fetch_test_file(session, sem, url, stats, verbose, src_ip):
    kind = url.rstrip("/").rsplit("/", 1)[-1]
    item = f"testfile:{kind}"

    async def run():
        async with sem, session.get(url, ssl=False) as resp:
            body = await resp.read()  # whole file: forwarding happens once it completes
            low = body[:4096].decode("utf-8", "ignore").lower()
            if blockpages.looks_blocked(low):
                _record(stats, item, "blocked", verbose, f"{resp.status} block page  {url}", src_ip)
            elif resp.status == 200 and body.startswith(MAGIC.get(kind, (b"",))):
                _record(stats, item, "transferred", verbose,
                        f"{len(body) / 1024:.0f} KiB, expect MALICIOUS verdict  {url}", src_ip)
            else:
                _record(stats, item, "errors", verbose,
                        f"HTTP {resp.status}, not a {kind} file  {url}", src_ip)

    await _guard(run(), stats, item, verbose, url, src_ip)


async def upload_file(session, sem, url, ftype, fname, blob, stats, verbose, src_ip):
    item = f"{ftype}:upload"

    async def run():
        form = aiohttp.FormData()
        form.add_field("file", blob, filename=fname, content_type="application/octet-stream")
        async with sem, session.post(url, data=form, ssl=False) as resp:
            low = (await resp.content.read(4096)).decode("utf-8", "ignore").lower()
            if blockpages.looks_blocked(low):
                _record(stats, item, "blocked", verbose, f"{resp.status} block page  {fname}", src_ip)
            elif resp.status < 400:
                _record(stats, item, "transferred", verbose, f"{resp.status}  {fname}", src_ip)
            else:
                _record(stats, item, "errors", verbose, f"HTTP {resp.status}  {fname}", src_ip)

    await _guard(run(), stats, item, verbose, fname, src_ip)


async def download_file(session, sem, ftype, fname, blob, stats, verbose, src_ip):
    item = f"{ftype}:download"
    if len(blob) > MAX_DOWNLOAD_BYTES:
        _record(stats, item, "errors", verbose, f"{fname} too large for URL-served download", src_ip)
        return
    url = DOWNLOAD_URL.format(b64=base64.urlsafe_b64encode(blob).decode())

    async def run():
        async with sem, session.get(url, ssl=False) as resp:
            body = await resp.read()
            if body == blob:
                _record(stats, item, "transferred", verbose, f"{len(body)} B  {fname}", src_ip)
            elif blockpages.looks_blocked(body[:4096].decode("utf-8", "ignore").lower()):
                _record(stats, item, "blocked", verbose, f"{resp.status} block page  {fname}", src_ip)
            else:
                _record(stats, item, "errors", verbose,
                        f"HTTP {resp.status}, content altered/replaced  {fname}", src_ip)

    await _guard(run(), stats, item, verbose, fname, src_ip)


async def run_wildfire_phase(cfg, sessions, sem, stats=None, verbose=False, upload_url=None):
    stats = stats or WildfireStats()
    upload_url = cfg.get("upload_url", upload_url or "https://postman-echo.com/post")
    tasks, i = [], 0

    def next_session():
        nonlocal i
        pair = sessions[i % len(sessions)]
        i += 1
        return pair

    if cfg.get("test_files_enabled", True):
        for url in cfg.get("test_files", DEFAULT_TEST_FILES):
            ip, s = next_session()
            tasks.append(fetch_test_file(s, sem, url, stats, verbose, ip))

    if cfg.get("unique_files_enabled", True):
        for ftype, fname, blob in generate_files(cfg.get("unique_types")):
            stats.hashes.append((ftype, fname, hashlib.sha256(blob).hexdigest()))
            if cfg.get("upload", True):
                ip, s = next_session()
                tasks.append(upload_file(s, sem, upload_url, ftype, fname, blob, stats, verbose, ip))
            if cfg.get("download", True):
                # Download gets its OWN unique copy - once a hash has been forwarded,
                # the second transfer of it would only be a verdict lookup.
                ip, s = next_session()
                _, _, blob2 = generate_files([ftype])[0]
                stats.hashes.append((ftype, fname + " (dl)", hashlib.sha256(blob2).hexdigest()))
                tasks.append(download_file(s, sem, ftype, fname, blob2, stats, verbose, ip))

    await asyncio.gather(*tasks)
    return stats


def print_wildfire_report(stats: WildfireStats):
    print("\n" + "=" * 70)
    print("WILDFIRE / SANDBOX RESULTS  (Monitor > WildFire Submissions is authoritative)")
    print("=" * 70)
    print(f"  transfers    : {stats.total}")
    print(f"  transferred  : {stats.transferred}   (whole file crossed - eligible for forwarding)")
    print(f"  blocked      : {stats.blocked}   (block page)")
    print(f"  reset        : {stats.reset}   (reset mid-transfer - usually the firewall)")
    print(f"  errors       : {stats.errors}")
    print("\n  by file:")
    print(f"    {'file':22} {'xfer':>5} {'block':>6} {'reset':>6} {'err':>5}")
    for item in sorted(stats.per_item):
        d = stats.per_item[item]
        print(f"    {item:22} {d.get('transferred', 0):5} {d.get('blocked', 0):6} "
              f"{d.get('reset', 0):6} {d.get('errors', 0):5}")
    if stats.hashes:
        print("\n  generated files (search these SHA-256s in WildFire Submissions; expect benign):")
        for ftype, fname, digest in stats.hashes:
            print(f"    {fname:26} {digest}")
    print("\n  -> test files should show verdict MALICIOUS within a few minutes; generated")
    print("     files BENIGN. No submissions at all = no WildFire Analysis profile on the")
    print("     rule, or HTTPS not decrypted for the download/upload sites.")
    print("=" * 70)


async def _standalone(cfg, upload_url, concurrency):
    timeout = aiohttp.ClientTimeout(total=60)
    conn = aiohttp.TCPConnector(ssl=False, force_close=True)
    async with aiohttp.ClientSession(timeout=timeout, connector=conn) as s:
        stats = await run_wildfire_phase(cfg, [(None, s)], asyncio.Semaphore(concurrency),
                                         verbose=True, upload_url=upload_url)
    print_wildfire_report(stats)


def main():
    import argparse
    p = argparse.ArgumentParser(description="WildFire / sandbox file-forwarding tester.")
    p.add_argument("--config", default="config.json")
    p.add_argument("--concurrency", type=int, default=10)
    args = p.parse_args()
    if aiohttp is None:
        sys.exit("aiohttp required. Activate venv and pip install -r requirements.txt")
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = Path(__file__).parent / config_path
    full = json.loads(config_path.read_text(encoding="utf-8"))
    asyncio.run(_standalone(full.get("wildfire", {}),
                            full.get("file_filter", {}).get("upload_url"), args.concurrency))


if __name__ == "__main__":
    main()
