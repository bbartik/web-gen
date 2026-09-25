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

### What a bare run does

`python web_gen.py` with no flags: **one weighted pass** over every enabled web
category (~230 URLs, ~800 weighted requests), **100 concurrent**, 15s timeout,
cache-busting on, with **threat-feed targets mixed in (~2.5%)** and traffic
**round-robined across the source IPs in config**. The DNS, File Filter, IPS, App
Control and GeoIP phases are **off** until you add their flag.

### Flags and defaults

| Flag | Default | Effect |
|------|---------|--------|
| `--config PATH` | `config.json` | Config file (resolved next to the script). |
| `--categories ...` | *(all enabled)* | Restrict to named web categories (overrides `enabled`). |
| `--concurrency N` | `100` | Max simultaneous in-flight requests. |
| `--iterations N` | `1` | Passes over the list (ignored with `--loop`). |
| `--loop` | off | Loop until `--duration` elapses instead of a pass count. |
| `--duration S` | `60` | Seconds to run when `--loop` is set. |
| `--delay S` | `0.0` | Sleep between passes. |
| `--timeout S` | `15.0` | Per-request total timeout. |
| `--requests N` | *(off → full pass)* | Fire N weighted-random requests/pass instead of a full weighted pass. |
| `--shuffle` | off | Randomize/interleave target order each pass. |
| `--full-download` | off | Pull full response bodies (needed for AV to scan EICAR). |
| `--no-redirects` | off (follows) | Don't follow HTTP redirects. |
| `--cache-bust` / `--no-cache-bust` | **on** | Append a random `?cb=` to each URL (threat-feed URLs excluded). |
| `--dns` / `--dns-only` | off | Add / isolate the DNS + DGA phase. |
| `--dga-count N` | *(config: 300)* | Override number of DGA domains per pass. |
| `--files` / `--files-only` | off | Add / isolate the File Filter phase. |
| `--ips` / `--ips-only` | off | Add / isolate the IPS signature phase. |
| `--apps` / `--apps-only` | off | Add / isolate the App Control phase (BitTorrent/proxy/Tor). |
| `--no-tor` | off (Tor on) | With `--apps`, skip the slow real Tor circuit. |
| `--geo` / `--geo-only` | off | Add / isolate the GeoIP (sanctioned-country) phase. |
| `--no-threat-feeds` | off (feeds on) | Disable the threat-feed mix-in. |
| `--threat-rate R` | *(config: 0.025)* | Fraction of connections that are threat-feed targets. |
| `--source-ips ...` | *(config: `auto`)* | Bind outgoing traffic to these local IPs; `auto` = all of this machine's IPs; `""` = OS default. |
| `-v` / `--verbose` | off | Print every request/query with its verdict. |
| `--list` | — | List web categories (with enabled/expect/weight) and exit. |

### Config-side defaults (in [config.json](config.json))

| Setting | Default | Notes |
|---------|---------|-------|
| `source_ips` | `"auto"` | All IPv4s on this machine (skips loopback/169.254.x), or a list of IPs; `[]` = OS default source. |
| all phases `enabled` | `true` | Phase still needs its CLI flag to run (except HTTP + threat feeds). |
| `threat_feeds.mix_rate` | `0.025` (~2.5%) | Poll interval 600s. |
| `dns.dga.count` | `300` | Plus suspicious + benign domains. |
| `dns.record_types` | `["A","AAAA"]` | FortiGuard block IPs `208.91.112.55/.52/.53`. |
| `file_filter.upload_url` | `postman-echo.com/post` | Downloads: thinkbroadband zip + PuTTY exe. |
| `ips.target_url` | `http://example.com/` | Use an internal no-WAF host for cleanest results. |
| `app_control.tor.timeout` | `90`s | Tor runs once per run (slow). |
| `geoip.ips_per_country` | `2` | 24 default countries; CIDRs from ipdeny.com, polled hourly. |

## GeoIP testing (sanctioned / embargoed countries)

[geoip.py](geoip.py) generates traffic to IPs allocated to **embargoed / sanctioned
countries** so FortiGate **GeoIP (destination-country) firewall policies** match and
block it. It pulls per-country IPv4 CIDR lists (default from **ipdeny.com** aggregated
zones), picks random hosts in each country, and connects.

Default country set mirrors the common EAR/ITAR/OFAC lists (Cuba, Iran, Syria, North
Korea, Russia, Belarus, Venezuela, China, Myanmar, Afghanistan, Iraq, Libya, Sudan,
Somalia, Yemen, and more). Edit the `countries` list in the `geoip` section of
[config.json](config.json); `ips_per_country` controls how many random IPs per country
each pass. Add known in-country sites to `domains` for a cleaner signal.

```powershell
python web_gen.py --geo            # add GeoIP phase to a normal run
python web_gen.py --geo-only       # only GeoIP
python geoip.py                    # standalone
```

Notes:

- **Client-side detection is best-effort.** A GeoIP block is usually a silent drop or
  reset, and a random in-country IP may not host anything anyway — so `reached` means
  "got a response (not blocked)", `blk/rst` is a likely block, and `noresp` is
  ambiguous. **The FortiGate policy log (destination country + block) is the
  authoritative proof.**
- CIDR lists are cached and re-polled every `poll_interval_sec` (default 1h).
- Other IP-by-country sources you can point `cidr_url_template` at: MaxMind GeoLite2,
  or the `herrbischoff/country-ip-blocks` GitHub repo.

## Application Control (BitTorrent / Proxy / Tor)

[app_control.py](app_control.py) generates **real application-protocol traffic** so
FortiGate **Application Control** can identify and block it. Unlike web/DNS filtering,
App Control uses DPI on protocol behaviour — hitting a URL won't trigger it, so this
puts the actual protocols on the wire:

- **BitTorrent** — HTTP **tracker announce** (`info_hash`/`peer_id`/`port` + a
  BitTorrent user-agent) and **DHT ping** (UDP bencode) to real DHT bootstrap nodes.
- **Proxy** — HTTP **`CONNECT`** and **absolute-URI** requests (proxy semantics).
- **Tor** — a **real Tor circuit via torpy** (pure-Python Tor client), which makes
  genuine TLS connections to live Tor guard relays — exactly what App Control detects.

```powershell
python web_gen.py --apps            # add App Control to a normal run
python web_gen.py --apps-only       # only App Control
python web_gen.py --apps --no-tor   # skip the slow Tor circuit
python app_control.py --no-tor      # standalone
```

Important notes:

- **Client-side block detection is best-effort.** An App Control block is a
  mid-session reset, which is hard to distinguish from an ordinary reset — so the
  tool's `blocked?/passed` verdict is a hint. **The FortiGate App Control log/widget
  is the authoritative proof** (same as File Filter).
- **DHT `err` = no UDP reply**, not a failure — the packet was still sent across the
  FortiGate (which is the point).
- **Tor is real and slow** (builds a live circuit, ~10–40s) so it runs **once per
  run**, not every pass. If the circuit doesn't complete, the guard-relay connections
  were still made — check the FortiGate log. `torpy` is unmaintained and calls the
  `ssl.wrap_socket` API removed in Python 3.12+, so [app_control.py](app_control.py)
  ships a small SSLContext shim to keep it working on modern Python.
- Other named P2P apps (Ares, FrostWire, DC++, …) each need their own client and
  aren't synthesised — BitTorrent covers the P2P category.
- Targets (trackers, DHT nodes, proxy/Tor destinations) are configurable in the
  `app_control` section of [config.json](config.json).

## IPS testing (signature validation)

[ips.py](ips.py) fires an assortment of **well-known IPS signature patterns** so you
can confirm FortiGate Intrusion Prevention is catching them: Shellshock
(CVE-2014-6271), Log4Shell (CVE-2021-44228), Struts OGNL (CVE-2017-5638), SQLi, XSS,
path traversal, command injection, scanner user-agents (nikto/sqlmap/nmap/masscan/
ZmEu), and the classic `testmyids` GPL id-check.

IPS matches the pattern **in transit**, so no vulnerable target is needed — the tool
just carries each pattern (in a query string, header, or user-agent) to a neutral
sink. A block shows up as a **connection reset** or a FortiGate IPS block page:

```
by trigger:              blocked  passed   err
  shellshock                   1       0     0   <- IPS caught it
  log4shell                    1       0     0
  sqli-union                   0       1     0   <- IPS did NOT catch this
```

**Pick the target carefully** (`ips.target_url` in [config.json](config.json)):

- Use a target with **no upstream WAF**, or its WAF resets the patterns and you can't
  tell those from a FortiGate block. Default is `http://example.com/` (IANA test
  domain, no WAF). **Best of all: a plain HTTP server inside your lab** that returns
  200 for anything — then any block is unambiguously the FortiGate, and traffic stays
  internal.
- Use **`http://`** so IPS inspects the plaintext without SSL deep inspection.

Look up the matched signature IDs afterward in the FortiGate IPS log or the
[FortiGuard IPS Encyclopedia](https://www.fortiguard.com/encyclopedia/ips).

```powershell
python web_gen.py --ips              # add IPS phase to a normal run
python web_gen.py --ips-only         # only the IPS phase
python ips.py                        # standalone
```

> ⚠️ These are real attack-signature strings, but inert (JNDI points at loopback; the
> payloads only *carry* the pattern for matching — no exploitation, no victim app).
> Run only against your own lab FortiGate.

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

By default `source_ips` in [config.json](config.json) is `"auto"`: every IPv4 on the
machine's NICs is used (loopback and 169.254.x skipped), so moving to a new VM needs no
config change. To pin specific IPs, list them in config or override at runtime:

```powershell
python web_gen.py --source-ips 10.21.1.10 10.21.1.12 10.21.1.15 --dns
```

Both HTTP (aiohttp `local_addr`) and DNS (pycares `local_ip`) are bound. The results
report includes a **by source IP** breakdown. Each IP must already be assigned to a
NIC on the machine — at startup each one is test-bound, and any that aren't are listed
(with the machine's actual IPs) before the run aborts. An empty `source_ips` list uses
the OS default source.

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
