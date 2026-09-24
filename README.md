# FortiGate Lab Web Traffic Generator

Async HTTP(S) traffic generator for exercising **FortiGate web filtering, antivirus,
and application control** in a lab. It fires large volumes of concurrent requests at
categorized target lists (malware/EICAR, phishing, gambling, hacking, proxy-avoidance,
weapons, drugs, warez, streaming, and clean baseline) and reports what got through vs.
what the FortiGate blocked.

It also generates a broad spread of **normal, everyday traffic** — news, shopping,
finance/banking, technology, education, health, travel, sports, government, food,
automotive, jobs, streaming/social, and a clean baseline — so the lab sees realistic
user browsing for app-control logging and category-allow verification, not just the
"should be blocked" categories.

Built to be developed anywhere but **run on a lab VM sitting behind the FortiGate**.

> All targets are either harmless industry test files (EICAR / AMTSO / WICAR /
> testmyids) or public sites that fall into a FortiGuard category. The tool only
> *requests* pages — it does not attack anything.

## Setup

```powershell
# from C:\automation\web_gen
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Usage

```powershell
# One pass over every enabled category
python web_gen.py

# List categories and their status
python web_gen.py --list

# Hammer everything for 5 minutes at high concurrency
python web_gen.py --loop --duration 300 --concurrency 200

# Only specific categories, verbose per-request output
python web_gen.py --categories gambling hacking av_malware_eicar -v

# Actually download the EICAR files (triggers AV scan on the wire)
python web_gen.py --categories av_malware_eicar av_amtso --full-download -v
```

### Key flags

| Flag | Meaning |
|------|---------|
| `--concurrency N` | Max simultaneous in-flight requests (default 100). Raise for more load. |
| `--loop --duration S` | Keep looping for S seconds instead of a fixed pass count. |
| `--iterations N` | Number of passes over the list (default 1). |
| `--categories ...` | Restrict to named categories (overrides the `enabled` flags). |
| `--full-download` | Pull entire response bodies (needed to make AV actually scan EICAR). |
| `--delay S` | Sleep between passes. |
| `--shuffle` | Randomize target order each pass. |
| `--no-cache-bust` | Don't append a random query param to each URL. |
| `-v` / `--verbose` | Print every request with its block/ok/err verdict. |

## File Filter testing (block-exec / monitor-docs policies)

[file_filter.py](file_filter.py) exercises FortiGate **File Filter** by moving an
assortment of file *types* across the firewall in **both directions**:

- **Upload** — generates small files locally with the correct **magic bytes**
  (MZ/PE `.exe`/`.dll`, ELF, Mach-O, OLE2 `.doc`/`.msi`, OOXML `.docx`/`.xlsx`,
  real + AES-encrypted `.zip`, `7z`/`rar`/`pdf`/`iso`/`dmg`/`torrent` signatures,
  script text for `.bat`/`.hta`/`.jnlp`/…) and `POST`s them to an echo endpoint.
- **Download** — GETs real, harmless public files (thinkbroadband zip, a signed
  PuTTY `.exe`).

File Filter matches on **type (magic) and extension, not content**, so the generated
files are harmless but still detected/blocked. Nothing malicious is downloaded.

Each type is tagged with its **expected** FortiGate action, and the report checks
actual-vs-expected so a policy gap is obvious (`CHECK <-`):

```
type             expect    blocked  allowed   err  result
exe              block           2        0     0  OK
torrent          block           0        1     0  CHECK <-   <- policy not catching!
zip              monitor         0        2     0  OK
```

The defaults align with a typical policy (block executables + images/torrents,
monitor docs/archives). Edit `generate_types`, `download_urls`, and `upload_url` in
the `file_filter` section of [config.json](config.json); adjust the `EXPECT` map in
[file_filter.py](file_filter.py) to match your own rules.

```powershell
python web_gen.py --files            # add File Filter phase to a normal run
python web_gen.py --files-only       # only the File Filter phase
python file_filter.py                # standalone
```

> Encrypted-zip generation needs **pyzipper** (`pip install -r requirements.txt`); if
> it's missing that one type is skipped with a note. Uploads go to a public echo
> service (`postman-echo.com`) — change `upload_url` if you prefer another.

## External threat feeds (prove the FortiGate feeds are matching)

The generator can pull the **same external threat-feed lists you point the FortiGate
at** (URLhaus / OpenPhish / Spamhaus / Feodo) and mix a small random assortment into
the traffic, so the FortiGate's external-connector matches show up in logs — an easy
way to demonstrate the feeds are live. Configured in the `threat_feeds` section of
[config.json](config.json):

- `urls` feed  → fired as `http://<entry>` (host[:port]/path)
- `ips` feed   → fired as `http://<host>/` (a host is picked from any CIDR)
- `domains` feed → fired as `https://<domain>/` **and** queried in the DNS phase

The feeds are re-polled every `poll_interval_sec` (default 600s) so list updates get
picked up. Injection defaults to `mix_rate` **0.025 (~2.5% of connections)**, capped
at `max_per_pass`. Feed hits are reported under the **`threat_feed`** category (and
DNS source).

```powershell
python web_gen.py --loop --duration 300 --dns            # feeds on by default
python web_gen.py --threat-rate 0.03                     # bump to 3%
python web_gen.py --no-threat-feeds                      # turn the mixing off
```

> ⚠️ **These are live malicious indicators.** Only run this behind a FortiGate that is
> actually enforcing the feeds — the point is that the connection gets blocked. As a
> safeguard the tool **never downloads the body** of a threat-feed target (ignores
> `--full-download` for them) and never saves anything; it only opens the connection
> so the FortiGate can match and block it. It also skips cache-busting on these so
> URL-feed matching stays exact.

## Source IPs (multiple clients from one machine)

If your lab VM has several IPs bound to its NIC (e.g. `10.21.1.10, .12, .15, .20,
.32, .41`), the generator can **round-robin outgoing traffic across them** so the
FortiGate sees each IP as a separate client — separate policy matches, separate log
sources, separate per-IP stats.

Set them in the `source_ips` list in [config.json](config.json) (pre-filled with the
lab IPs) or override at runtime:

```powershell
python web_gen.py --source-ips 10.21.1.10 10.21.1.12 10.21.1.15 --dns
```

Both HTTP (aiohttp `local_addr`) and DNS (pycares `local_ip`) are bound. The results
report includes a **by source IP** breakdown. Each IP must already be assigned to a
NIC on the machine — binding to an unassigned IP just yields connection errors (shown
in the report), not a crash. An empty `source_ips` list uses the OS default source.

> To add the IPs in Windows: *Network adapter → IPv4 properties → Advanced → IP
> addresses → Add* (the dialog in your screenshot), or
> `netsh interface ipv4 add address "Ethernet0" 10.21.1.12 255.255.255.0`.

## Weighting (realistic traffic mix)

Each category has a `weight` in [config.json](config.json) — its relative hit
frequency. Normal categories are weighted up (benign/streaming = 6, most everyday
categories = 3–5) and should-be-blocked categories are weighted down (= 1), so a run
looks like a real user population: mostly ordinary browsing with the occasional hit on
gambling/hacking/malware. In practice normal traffic is ~85% of volume and the
block-worthy categories are a ~1%-each long tail.

Two ways weighting is applied:

- **Weighted full pass (default):** every URL is fired each pass, repeated `weight`
  times. Comprehensive — everything gets exercised, just in realistic proportion. Add
  `--shuffle` to interleave categories instead of firing them in blocks.
- **Weighted-random sample:** `--requests N` fires N weighted-random requests per pass
  (with replacement). Best for sustained, rate-controlled load that still follows the
  weights.

```powershell
# Realistic weighted mix, interleaved, HTTP + DNS, for 5 minutes
python web_gen.py --loop --duration 300 --concurrency 200 --shuffle --dns

# Sustained 400 weighted-random requests per pass
python web_gen.py --loop --duration 600 --requests 400 --concurrency 200
```

Weights (minimum 1) show in `python web_gen.py --list`. To drop a category entirely,
set `"enabled": false` or use `--categories` to restrict the run.

## DNS / DGA traffic (FortiGate DNS filtering + Botnet C&C detection)

[dns_gen.py](dns_gen.py) fires large volumes of DNS queries to exercise FortiGate
**DNS filtering** and **Botnet C&C / DGA detection**. It resolves through the OS's
configured DNS server (i.e. through the FortiGate) using `aiodns` (c-ares) for real
async scale.

It generates three kinds of domains (see the `dns` section of [config.json](config.json)):

- **DGA** — algorithmically generated domains in three styles that mirror real
  botnet families: high-entropy random (Conficker/Necurs), **date-seeded**
  deterministic (CryptoLocker-style — same date produces the same list), and
  dictionary-word (matsnu/suppobox). Most return **NXDOMAIN**, which is exactly the
  beaconing pattern DGA detection flags.
- **suspicious** — a curated list of dodgy-looking / dynamic-DNS test domains.
- **benign** — clean domains for baseline.

Blocking is detected as **NXDOMAIN vs resolved**, and — when the FortiGate DNS filter
redirects a blocked lookup to a FortiGuard portal IP — as **blocked** (the
`block_ips` list in config, default `208.91.112.55/.52/.53`).

```powershell
# Integrated: run HTTP + DNS together
python web_gen.py --dns --loop --duration 300 --concurrency 200

# DNS only, 500 DGA domains
python web_gen.py --dns-only --dga-count 500 --concurrency 300

# Standalone module, verbose
python dns_gen.py --dga-count 500 -v

# Just preview the domains it would generate
python dns_gen.py --sample --dga-count 30

# Point at a specific resolver instead of the OS default
python dns_gen.py --servers 208.91.112.220 -v
```

Relevant flags: `--dns`, `--dns-only`, `--dga-count N`. Tune counts, TLDs, and the
domain lists in the `dns` section of `config.json`.

## Block detection

The tool sniffs the first 4 KB of each response for FortiGate block-page markers
(`FortiGuard`, `Web Page Blocked`, `Virus/Malware Detected`, etc.) and reports each
request as **ok / blocked / error**, broken down per category and per HTTP status.
Tune the markers in `FORTI_BLOCK_MARKERS` in [web_gen.py](web_gen.py) to match your
firmware's block page wording.

## Editing targets

All targets live in [config.json](config.json). Each category has:

- `enabled`: include it in default runs (override with `--categories`).
- `expect`: `block` / `allow` / `mixed` — reporting hint only.
- `urls`: the list to hit.

The `adult` category ships **empty and disabled** — populate it yourself if your lab
policy requires testing that category.

## Notes for running behind the FortiGate

- Certificate validation is **disabled** (`ssl=False`) so the FortiGate's block page /
  deep-inspection cert doesn't abort requests. Fine for a lab, never for production.
- To make antivirus fire, use `--full-download` so the EICAR/AMTSO payloads actually
  cross the wire and get scanned (a `HEAD`-like 4 KB peek may not trigger AV).
- Expect connection resets / timeouts on blocked HTTPS sites when the FortiGate does
  certificate-based blocking rather than serving a replacement page — those show up as
  `errors` rather than `blocked`. Enable SSL deep inspection on the policy to get
  replacement block pages you can detect.
