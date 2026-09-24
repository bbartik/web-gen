#!/usr/bin/env python3
"""
file_filter.py - Exercise FortiGate File Filter (and AV) by moving an assortment
of file *types* across the firewall in both directions:

  * UPLOAD  - generate small files locally with correct magic bytes (MZ/PE for
              .exe, real .zip, AES-encrypted .zip, 7z/RAR/PDF/CAB signatures,
              script text for .bat/.js/.ps1/...) and POST them to an echo endpoint.
  * DOWNLOAD - GET real, harmless public files of various types.

File Filter matches on file type (magic bytes) and extension, not content, so the
generated files are harmless but still detected/blocked by type. Nothing malicious
is downloaded; uploads go to a public echo service that just reflects them.

Imported by web_gen.py (--files / --files-only) or run standalone.
"""

import asyncio
import gzip
import io
import json
import struct
import sys
import tarfile
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

try:
    import aiohttp
except ImportError:
    aiohttp = None

try:
    import pyzipper  # AES-encrypted zip (optional)
except ImportError:
    pyzipper = None

# FortiGate File Filter / block-page markers.
BLOCK_MARKERS = (
    "file blocked", "file filter", "web page blocked", "fortiguard",
    "blocked", "virus/malware detected", "high security alert",
    "content has been blocked", "file has been blocked",
)


@dataclass
class FileStats:
    total: int = 0
    blocked: int = 0
    allowed: int = 0
    errors: int = 0
    per_type: dict = field(default_factory=lambda: defaultdict(lambda: defaultdict(int)))


# --------------------------------------------------------------------------- #
# File generation (correct magic bytes; harmless content)
# --------------------------------------------------------------------------- #

def _make_pe(dll=False):
    """Minimal PE (MZ + IMAGE_NT_HEADERS) detected as a Windows executable."""
    e_lfanew = 0x80
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    machine = 0x8664  # AMD64
    num_sections = 1
    opt_size = 0xF0
    characteristics = 0x2022 if dll else 0x0022  # EXECUTABLE_IMAGE (+DLL)
    coff = struct.pack("<IHHIIIHH", 0x00004550,  # 'PE\0\0'
                       machine, num_sections, 0, 0, 0, opt_size, characteristics)
    optional = struct.pack("<H", 0x020B) + b"\x00" * (opt_size - 2)  # PE32+ magic
    return bytes(dos) + coff + optional + b"\x00" * 64


def _make_zip(encrypted=False):
    buf = io.BytesIO()
    payload = b"harmless test file for FortiGate file filter\n"
    if encrypted:
        if pyzipper is None:
            return None
        with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED,
                                 encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(b"infected")
            zf.writestr("readme.txt", payload)
    else:
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("readme.txt", payload)
    return buf.getvalue()


def _make_gz():
    return gzip.compress(b"harmless test file for FortiGate file filter\n")


def _make_tar():
    buf = io.BytesIO()
    data = b"harmless test file\n"
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("readme.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _pad(magic, size=256):
    return magic + b"\x00" * max(0, size - len(magic))


def _make_ole2():
    """OLE2 compound-file header (Office Binary .doc/.xls, and MSI)."""
    h = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 16
    h += struct.pack("<HHH", 0x003E, 0x0003, 0xFFFE)  # minor, major, byte order
    h += struct.pack("<HH", 0x0009, 0x0006)           # sector / mini-sector shift
    return _pad(h, 1536)


def _make_ooxml(kind):
    """Minimal Office Open XML (.docx/.xlsx) - a zip with the OOXML parts."""
    parts = {"_rels/.rels":
             b'<?xml version="1.0"?><Relationships '
             b'xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>'}
    if kind == "docx":
        parts["[Content_Types].xml"] = (
            b'<?xml version="1.0"?><Types '
            b'xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            b'<Override PartName="/word/document.xml" ContentType="application/vnd.'
            b'openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
        parts["word/document.xml"] = (
            b'<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.'
            b'org/wordprocessingml/2006/main"><w:body/></w:document>')
    else:  # xlsx
        parts["[Content_Types].xml"] = (
            b'<?xml version="1.0"?><Types '
            b'xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            b'<Override PartName="/xl/workbook.xml" ContentType="application/vnd.'
            b'openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/></Types>')
        parts["xl/workbook.xml"] = (
            b'<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.'
            b'org/spreadsheetml/2006/main"><sheets/></workbook>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in parts.items():
            z.writestr(name, data)
    return buf.getvalue()


def _make_iso():
    """ISO 9660 - Primary Volume Descriptor 'CD001' at offset 0x8001."""
    buf = bytearray(0x8800)
    buf[0x8000] = 0x01
    buf[0x8001:0x8006] = b"CD001"
    return bytes(buf)


def _make_dmg():
    """Apple DMG - 'koly' trailer (512-byte footer) at end of file."""
    return b"\x00" * 1024 + b"koly" + b"\x00" * 508


# (type key) -> (filename, bytes builder). Filenames carry a plausible extension;
# type detection is by magic bytes, so extension-less formats (elf/mach-o) still match.
GENERATORS = {
    # --- executables (your block-executables rule) ---
    "exe":    ("test-sample.exe", lambda: _make_pe(dll=False)),
    "dll":    ("test-sample.dll", lambda: _make_pe(dll=True)),
    "net":    ("test-sample.exe", lambda: _make_pe(dll=False)),   # .NET PE
    "scr":    ("test-sample.scr", lambda: _make_pe(dll=False)),
    "msi":    ("test-sample.msi", _make_ole2),
    "elf":    ("test-sample.elf", lambda: _pad(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8, 128)),
    "mach-o": ("test-sample.macho", lambda: _pad(b"\xcf\xfa\xed\xfe\x07\x00\x00\x01" + b"\x00" * 16, 128)),
    "bat":    ("test-sample.bat", lambda: b"@echo off\r\necho harmless test\r\n"),
    "hta":    ("test-sample.hta", lambda: b"<html><head><hta:application id='t'/></head><body>test</body></html>"),
    "jnlp":   ("test-sample.jnlp", lambda: b"<?xml version='1.0'?>\n<jnlp spec='1.0'><information><title>test</title></information></jnlp>"),
    # --- images / torrents (your block-images-torrents rule) ---
    "iso":     ("test-sample.iso", _make_iso),
    "dmg":     ("test-sample.dmg", _make_dmg),
    "torrent": ("test-sample.torrent", lambda: b"d8:announce9:test:test4:infod4:name4:test6:lengthi1eee"),
    # --- docs / archives (your log-docs-archives Monitor rule) ---
    "zip":  ("test-sample.zip", lambda: _make_zip(False)),
    "zip_encrypted": ("test-encrypted.zip", lambda: _make_zip(True)),
    "7z":   ("test-sample.7z", lambda: _pad(b"7z\xbc\xaf\x27\x1c\x00\x04")),
    "rar":  ("test-sample.rar", lambda: _pad(b"Rar!\x1a\x07\x01\x00")),
    "pdf":  ("test-sample.pdf", lambda: b"%PDF-1.7\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"),
    "docx": ("test-sample.docx", lambda: _make_ooxml("docx")),
    "xlsx": ("test-sample.xlsx", lambda: _make_ooxml("xlsx")),
    "doc":  ("test-sample.doc", _make_ole2),
    # --- extras (not in the shown policy; expected to pass) ---
    "gz":   ("test-sample.gz", _make_gz),
    "tar":  ("test-sample.tar", _make_tar),
    "cab":  ("test-sample.cab", lambda: _pad(b"MSCF\x00\x00\x00\x00")),
    "js":   ("test-sample.js", lambda: b"// harmless test\nconsole.log('test');\n"),
    "vbs":  ("test-sample.vbs", lambda: b"' harmless test\r\nWScript.Echo \"test\"\r\n"),
    "ps1":  ("test-sample.ps1", lambda: b"# harmless test\nWrite-Output 'test'\n"),
    "sh":   ("test-sample.sh", lambda: b"#!/bin/sh\necho harmless test\n"),
}

# Expected FortiGate action per type, for the report's pass/fail check.
# block = should be blocked; monitor = passes but is logged; pass = not in policy.
EXPECT = {
    "exe": "block", "dll": "block", "net": "block", "scr": "block", "msi": "block",
    "elf": "block", "mach-o": "block", "bat": "block", "hta": "block", "jnlp": "block",
    "iso": "block", "dmg": "block", "torrent": "block",
    "zip": "monitor", "zip_encrypted": "monitor", "7z": "monitor", "rar": "monitor",
    "pdf": "monitor", "docx": "monitor", "xlsx": "monitor", "doc": "monitor",
    "gz": "pass", "tar": "pass", "cab": "pass", "js": "pass", "vbs": "pass",
    "ps1": "pass", "sh": "pass",
}


def generate_files(types):
    """Return list of (ftype, filename, bytes). Skips unavailable types."""
    out = []
    for t in types:
        gen = GENERATORS.get(t)
        if not gen:
            continue
        fname, builder = gen
        blob = builder()
        if blob is None:
            if t == "zip_encrypted":
                print("[file-filter] skipping encrypted zip (pip install pyzipper to enable)")
            continue
        out.append((t, fname, blob))
    return out


# --------------------------------------------------------------------------- #
# Transfers
# --------------------------------------------------------------------------- #

def _classify(status, snippet):
    low = snippet.lower()
    if any(m in low for m in BLOCK_MARKERS):
        return "blocked"
    if 200 <= status < 400:
        return "allowed"
    return "error"


def _record(stats, ftype, result, verbose, direction, name, src_ip):
    stats.total += 1
    stats.per_type[ftype][result] += 1
    if result == "blocked":
        stats.blocked += 1
        tag = "BLOCK"
    elif result == "allowed":
        stats.allowed += 1
        tag = "ok"
    else:
        stats.errors += 1
        tag = "err"
    if verbose:
        ip = f" [{src_ip}]" if src_ip else ""
        print(f"[{tag:5}] {direction:4} {ftype:14} {name}{ip}")


async def upload_one(session, sem, ftype, fname, blob, url, stats, verbose, src_ip):
    async with sem:
        try:
            data = aiohttp.FormData()
            data.add_field("file", blob, filename=fname,
                           content_type="application/octet-stream")
            async with session.post(url, data=data, ssl=False) as resp:
                chunk = await resp.content.read(4096)
                _record(stats, ftype, _classify(resp.status, chunk.decode("utf-8", "ignore")),
                        verbose, "up", fname, src_ip)
        except Exception as exc:  # noqa: BLE001
            _record(stats, ftype, "error", verbose, "up", f"{fname} ({type(exc).__name__})", src_ip)


async def download_one(session, sem, url, stats, verbose, src_ip):
    ftype = url.rsplit(".", 1)[-1].split("?")[0].lower() if "." in url else "bin"
    async with sem:
        try:
            async with session.get(url, ssl=False) as resp:
                chunk = await resp.content.read(4096)
                _record(stats, ftype, _classify(resp.status, chunk.decode("utf-8", "ignore")),
                        verbose, "down", url, src_ip)
        except Exception as exc:  # noqa: BLE001
            _record(stats, ftype, "error", verbose, "down", f"{url} ({type(exc).__name__})", src_ip)


async def run_file_phase(cfg, sessions, sem, stats=None, verbose=False):
    """One pass: upload all generated types + download all configured URLs.

    `sessions` is a list of (src_ip, aiohttp.ClientSession) - reused from web_gen
    so file transfers round-robin across the same source IPs.
    """
    stats = stats or FileStats()
    upload_url = cfg.get("upload_url")
    types = cfg.get("generate_types", list(GENERATORS.keys()))
    download_urls = cfg.get("download_urls", [])

    files = generate_files(types)
    tasks = []
    i = 0
    if upload_url:
        for ftype, fname, blob in files:
            src_ip, session = sessions[i % len(sessions)]
            i += 1
            tasks.append(asyncio.create_task(
                upload_one(session, sem, ftype, fname, blob, upload_url, stats, verbose, src_ip)))
    for url in download_urls:
        src_ip, session = sessions[i % len(sessions)]
        i += 1
        tasks.append(asyncio.create_task(
            download_one(session, sem, url, stats, verbose, src_ip)))

    await asyncio.gather(*tasks)
    return stats


def print_file_report(stats: FileStats):
    print("\n" + "=" * 70)
    print("FILE FILTER RESULTS")
    print("=" * 70)
    print(f"  transfers : {stats.total}")
    print(f"  blocked   : {stats.blocked}")
    print(f"  allowed   : {stats.allowed}")
    print(f"  errors    : {stats.errors}")
    print("\n  by file type (verdict vs policy):")
    print(f"    {'type':16} {'expect':8} {'blocked':>8} {'allowed':>8} {'err':>5}  result")
    for t in sorted(stats.per_type):
        d = stats.per_type[t]
        blocked, allowed, err = d.get("blocked", 0), d.get("allowed", 0), d.get("error", 0)
        exp = EXPECT.get(t, "pass")
        # Decide pass/fail against policy (ignore pure errors - can't tell).
        if blocked == 0 and allowed == 0:
            result = "-"
        elif exp == "block":
            result = "OK" if blocked and not allowed else "CHECK <-"
        else:  # monitor or pass -> should not be blocked
            result = "OK" if allowed and not blocked else "CHECK <-"
        print(f"    {t:16} {exp:8} {blocked:8} {allowed:8} {err:5}  {result}")
    print("\n  expect: block=should be blocked  monitor=passes+logged  pass=not in policy")
    print("=" * 70)


# --------------------------------------------------------------------------- #
# Standalone
# --------------------------------------------------------------------------- #

async def _standalone(cfg, concurrency):
    timeout = aiohttp.ClientTimeout(total=30)
    conn = aiohttp.TCPConnector(ssl=False, force_close=True)
    async with aiohttp.ClientSession(timeout=timeout, connector=conn) as s:
        stats = await run_file_phase(cfg, [(None, s)], asyncio.Semaphore(concurrency),
                                     verbose=True)
    print_file_report(stats)


def main():
    import argparse
    p = argparse.ArgumentParser(description="FortiGate File Filter tester.")
    p.add_argument("--config", default="config.json")
    p.add_argument("--concurrency", type=int, default=20)
    args = p.parse_args()
    if aiohttp is None:
        sys.exit("aiohttp required. Activate venv and pip install -r requirements.txt")
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = Path(__file__).parent / config_path
    cfg = json.loads(config_path.read_text(encoding="utf-8")).get("file_filter", {})
    asyncio.run(_standalone(cfg, args.concurrency))


if __name__ == "__main__":
    main()
