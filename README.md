# SWG / NGFW Traffic Generator

A lab traffic generator for testing **secure web gateways and next-gen firewalls** —
Palo Alto, FortiGate, Zscaler, Netskope or anything else inline. It produces the
traffic those devices are built to catch, reports what got through vs. what was
blocked, and leaves the device's own logs as the authoritative record.

| Phase | Flag | Exercises |
|-------|------|-----------|
| Web categories | *(default)* | URL filtering, AV (EICAR/AMTSO/WICAR), threat feeds |
| DNS / DGA | `--dns` | DNS security, DGA / C2 detection, sinkholing |
| File filter | `--files` | File-type blocking, uploads + downloads |
| IPS | `--ips` | Signature patterns (Shellshock, Log4Shell, SQLi, …) |
| App control | `--apps` | BitTorrent, proxy, real Tor circuit |
| GeoIP | `--geo` | Destination-country policy |
| WildFire / sandbox | `--wildfire` | Vendor test files (malicious verdict) + unique files forwarded for analysis |
| GenAI API | `--ai` | GenAI App-ID, AI access policy, prompt-injection + DLP on prompts |
| Real browsers | `--browser` | Video, browsing, search, social/SaaS, GenAI chat, downloads |

It also generates a broad spread of **normal, everyday traffic** — news, shopping,
finance, technology, education, health, travel, sports, government and more — so the
lab sees realistic user browsing, not just the "should be blocked" categories.

Built to be developed anywhere but **run on a lab VM sitting behind the device under
test**.

> All targets are either harmless industry test files (EICAR / AMTSO / WICAR /
> testmyids), public sites that fall into a URL-filtering category, or synthetic test
> data. The tool only *requests* pages — it does not attack anything.

## Setup

```powershell
# from C:\automation\web_gen
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
playwright install chromium   # only for --browser (fallback if Edge isn't installed)
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
Control, GeoIP, WildFire, GenAI and browser phases are **off** until you add their flag.

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
| `--wildfire` / `--wildfire-only` | off | Add / isolate the WildFire / sandbox phase. |
| `--ai` / `--ai-only` | off | Add / isolate the GenAI API phase (benign / injection / DLP prompts). |
| `--browser` / `--browser-only` | off | Add / isolate the real-browser phase (video, browsing, search, SaaS, downloads). |
| `--personas ...` | *(all enabled)* | With `--browser`, only run these personas. |
| `--browser-headed` | off (headless) | Show the browser windows. |
| `--browser-workers N` | *(config: 3)* | Parallel browsers. |
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
countries** so firewall **GeoIP (destination-country) firewall policies** match and
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
  ambiguous. **The firewall policy log (destination country + block) is the
  authoritative proof.**
- CIDR lists are cached and re-polled every `poll_interval_sec` (default 1h).
- Other IP-by-country sources you can point `cidr_url_template` at: MaxMind GeoLite2,
  or the `herrbischoff/country-ip-blocks` GitHub repo.

## Application Control (BitTorrent / Proxy / Tor)

[app_control.py](app_control.py) generates **real application-protocol traffic** so
firewall **Application Control** can identify and block it. Unlike web/DNS filtering,
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
  tool's `blocked?/passed` verdict is a hint. **The firewall App Control / App-ID log
  is the authoritative proof** (same as File Filter).
- **DHT `err` = no UDP reply**, not a failure — the packet was still sent across the
  firewall (which is the point).
- **Tor is real and slow** (builds a live circuit, ~10–40s) so it runs **once per
  run**, not every pass. If the circuit doesn't complete, the guard-relay connections
  were still made — check the firewall log. `torpy` is unmaintained and calls the
  `ssl.wrap_socket` API removed in Python 3.12+, so [app_control.py](app_control.py)
  ships a small SSLContext shim to keep it working on modern Python.
- Other named P2P apps (Ares, FrostWire, DC++, …) each need their own client and
  aren't synthesised — BitTorrent covers the P2P category.
- Targets (trackers, DHT nodes, proxy/Tor destinations) are configurable in the
  `app_control` section of [config.json](config.json).

## Real browsers (video, browsing, search, social/SaaS, downloads)

[browser_sim.py](browser_sim.py) drives **real headless Edge/Chromium** (Playwright)
as simulated users, so the firewall sees genuine browser traffic — real TLS
fingerprints, HTTP/2, video segment streams, redirects, cookies — which is what
App-ID / App Control, URL filtering and file inspection are built around.

```powershell
python web_gen.py --browser-only -v                         # every persona once
python web_gen.py --browser-only --personas video_watcher -v
python web_gen.py --browser-only --browser-headed --browser-workers 1   # watch it work
python web_gen.py --browser-only --loop --duration 1800     # half an hour of "users"
python browser_sim.py --personas downloader                 # standalone
```

**Personas** live in the `browser` section of [config.json](config.json); each is a
list of actions, shuffled per session, and each session gets a **fresh browser**:

| Persona | What it does |
|---------|--------------|
| `video_watcher` | YouTube search + play, Vimeo Staff Pick, Twitch, Netflix, Spotify |
| `news_reader` | BBC/CNN/AP/Reuters, scrolls and follows same-site links |
| `researcher` | Bing / DuckDuckGo / Google searches, opens a result; random Wikipedia |
| `shopper` | Amazon / eBay / Best Buy browsing + product searches |
| `social` | Reddit, Facebook, Instagram, X, LinkedIn, TikTok, Pinterest |
| `saas_worker` | Office, Outlook, Teams, Dropbox, Box, Drive, Zoom, Slack, Salesforce, GitHub |
| `risky_user` | Random sites from the URL-filter `categories` (gambling, proxy, hacking, …) |
| `downloader` | EICAR, the WildFire test PE, putty.exe, a zip and a PDF via the browser's own download path |
| `genai_user` | Types prompts into ChatGPT / Gemini / Duck.ai; visits 9 more GenAI apps |

**Action types** (mix freely in your own personas):

| `type` | Keys | Does |
|--------|------|------|
| `browse` | `url`, `follow_links`, `dwell` | Load, scroll, follow N same-site links |
| `visit` | `url`, `dwell` | Load and linger (enough for App-ID on SaaS/social) |
| `search` | `engine` (bing/google/duckduckgo), `query`/`queries`, `open_result` | Search, open a top result |
| `video` | `url`, or `query`/`queries` (YouTube), or `list_url` + `link_pattern`; `watch_seconds` | Play and verify playback advanced |
| `download` | `url` | Download (or open inline, e.g. PDF) through the browser |
| `chat` | `url`, `prompts`, `mix`, `wait_seconds` | Type GenAI prompts and confirm they were sent |
| `category` | `name`, `count` | Browse N random URLs from a `categories` entry |

Notes:

- **Source IPs:** browsers can't bind a source IP, so each source IP gets a tiny local
  proxy that makes its upstream connections *from* that IP. Sessions rotate across
  IPs; the firewall still sees direct client → site connections (DNS lookups use the
  OS default source).
- **QUIC is disabled** (`disable_quic`) so video and Google traffic stays TLS/TCP and
  is decryptable/inspectable.
- **Decryption:** `channel: "msedge"` drives the installed Edge, which trusts the
  Windows cert store — an installed forward-trust CA just works, and
  `ignore_https_errors` covers anything else. `channel: null` uses bundled Chromium.
- **Results:** `ok` / `BLOCK` (Palo or firewall block page seen) / `RESET`
  (connection reset/refused — usually the firewall) / `err` (timeouts, HTTP ≥ 400,
  bot checks). Video counts as ok only if playback actually advanced.
- **Resources:** ~300–500 MB RAM per parallel browser; 3 workers is comfortable.
- Some sites bot-check headless browsers or reject datacenter IPs (403/401/429) — that
  still generates the App-ID traffic; it just shows as `err`.

## WildFire / sandbox analysis

[wildfire.py](wildfire.py) gets files in front of cloud sandbox analysis. A firewall
only *forwards* a file whose hash it has never seen - a known hash is just a verdict
lookup - so re-downloading putty.exe never produces a submission. Two sources:

- **Vendor test files** - Palo Alto's official WildFire test files (`pe`, `elf`,
  `macos`, `apk` under `wildfire.paloaltonetworks.com/publicapi/test/`). Harmless, but
  every download is a brand-new sample that WildFire rules **malicious**: the end-to-end
  proof that forwarding, verdicts and verdict-based blocking work. Downloaded in full
  (forwarding happens once the transfer completes) and checked for the right magic
  bytes, never saved.
- **Unique generated files** - harmless EXE, DLL, ELF, PDF (plain and with a harmless
  JavaScript `app.alert`), DOCX, PS1/JS/VBS/BAT scripts and a zip containing an EXE,
  all with random content so every run has new hashes. Each type is **uploaded** (POST
  to `file_filter.upload_url`) and **downloaded** (a separate unique copy, served back
  by an endpoint that decodes it from the URL). Expect **benign** verdicts.

```powershell
python web_gen.py --wildfire-only -v
python wildfire.py                      # standalone
```

The report prints the **SHA-256 of every generated file** - search them in
**Monitor > WildFire Submissions**. Test files show up as malicious within a few
minutes. Nothing at all in Submissions usually means the security rule has no
**WildFire Analysis** profile, or the upload/download sites are HTTPS and not
decrypted (the test files use `http://` so they work without decryption; switch the
URLs to `https://` to test decryption too). The browser `downloader` persona also pulls
the WildFire test PE through a real browser.

## GenAI / AI access security (prompt injection, DLP on prompts)

[ai_sim.py](ai_sim.py) generates GenAI traffic for AI access controls (e.g. Palo Alto
AI Access Security), GenAI App-ID and DLP on prompts. Turn on **decryption for the
GenAI URL category** or the device only sees app names, not prompt content.

- **API phase** (`--ai`): real chat requests to 11 provider APIs (OpenAI, Anthropic,
  Gemini, Mistral, Cohere, Groq, DeepSeek, xAI, Perplexity, Together, Hugging Face) plus
  file uploads, all with a **placeholder key**. Providers answer 401, but the full
  prompt has already crossed the device — that's what App-ID and DLP inspect. Nothing
  is answered or billed. `sent` in the report = reached the provider.
- **Browser chat** (`--browser --personas genai_user`): types the same prompts into
  ChatGPT, Gemini and Duck.ai (all work logged-out), and only counts a prompt as `ok`
  when its text is seen leaving in a request. Also visits Claude, Copilot, Perplexity,
  DeepSeek, Mistral, HuggingChat, Poe, Character.AI and NotebookLM for App-ID.

Prompt sets (preview with `python ai_sim.py --show-prompts`):

| Set | Examples | Should trigger |
|-----|----------|----------------|
| `benign` | "What is a VLAN?", "Help me build a gaming PC" | Allowed / logged |
| `injection` | "Ignore all previous instructions…", DAN, fake `<system>` tags, hidden HTML-comment instructions, base64-encoded instructions | Prompt-injection detection |
| `dlp` | Customer record with SSN + card, AWS keys, private key, DB connection string, confidential memo, patient list | DLP on prompts |

The injection prompts use harmless payloads ("reveal your system prompt", "say
PWNED") — they test detection of the *pattern*, not getting anything out of a model.
The DLP data is **synthetic**: published payment test card numbers (4111…, 5555…),
randomly generated SSNs/MRNs, random key-shaped strings. Tune the weighting with
`ai.mix`, or replace any set with `ai.prompts.{benign,injection,dlp}`.

Where to look: GenAI apps in the Traffic / App-ID logs, the AI access dashboard, and
Data Filtering / DLP logs for the `dlp` prompts and the CSV upload. Prompt-injection
detection may be a separate license/feature from AI app access control on some
platforms — check which log it lands in before treating a miss as a failure.

```powershell
python web_gen.py --ai-only -v                                   # API phase
python web_gen.py --browser-only --personas genai_user -v        # chat UIs
python web_gen.py --ai --browser --personas genai_user --loop --duration 600
```

## IPS testing (signature validation)

[ips.py](ips.py) fires an assortment of **well-known IPS signature patterns** so you
can confirm firewall Intrusion Prevention is catching them: Shellshock
(CVE-2014-6271), Log4Shell (CVE-2021-44228), Struts OGNL (CVE-2017-5638), SQLi, XSS,
path traversal, command injection, scanner user-agents (nikto/sqlmap/nmap/masscan/
ZmEu), and the classic `testmyids` GPL id-check.

IPS matches the pattern **in transit**, so no vulnerable target is needed — the tool
just carries each pattern (in a query string, header, or user-agent) to a neutral
sink. A block shows up as a **connection reset** or a firewall IPS block page:

```
by trigger:              blocked  passed   err
  shellshock                   1       0     0   <- IPS caught it
  log4shell                    1       0     0
  sqli-union                   0       1     0   <- IPS did NOT catch this
```

**Pick the target carefully** (`ips.target_url` in [config.json](config.json)):

- Use a target with **no upstream WAF**, or its WAF resets the patterns and you can't
  tell those from a firewall block. Default is `http://example.com/` (IANA test
  domain, no WAF). **Best of all: a plain HTTP server inside your lab** that returns
  200 for anything — then any block is unambiguously the firewall, and traffic stays
  internal.
- Use **`http://`** so IPS inspects the plaintext without SSL deep inspection.

Look up the matched signature IDs afterward in the firewall IPS log or the
[FortiGuard IPS Encyclopedia](https://www.fortiguard.com/encyclopedia/ips).

```powershell
python web_gen.py --ips              # add IPS phase to a normal run
python web_gen.py --ips-only         # only the IPS phase
python ips.py                        # standalone
```

> ⚠️ These are real attack-signature strings, but inert (JNDI points at loopback; the
> payloads only *carry* the pattern for matching — no exploitation, no victim app).
> Run only against your own lab firewall.

## File Filter testing (block-exec / monitor-docs policies)

[file_filter.py](file_filter.py) exercises firewall **File Filter** by moving an
assortment of file *types* across the firewall in **both directions**:

- **Upload** — generates small files locally with the correct **magic bytes**
  (MZ/PE `.exe`/`.dll`, ELF, Mach-O, OLE2 `.doc`/`.msi`, OOXML `.docx`/`.xlsx`,
  real + AES-encrypted `.zip`, `7z`/`rar`/`pdf`/`iso`/`dmg`/`torrent` signatures,
  script text for `.bat`/`.hta`/`.jnlp`/…) and `POST`s them to an echo endpoint.
- **Download** — GETs real, harmless public files (thinkbroadband zip, a signed
  PuTTY `.exe`).

File Filter matches on **type (magic) and extension, not content**, so the generated
files are harmless but still detected/blocked. Nothing malicious is downloaded.

Each type is tagged with its **expected** firewall action, and the report checks
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

## External threat feeds (prove the firewall feeds are matching)

The generator can pull the **same external threat-feed lists you point the firewall
at** (URLhaus / OpenPhish / Spamhaus / Feodo) and mix a small random assortment into
the traffic, so the firewall's external-connector matches show up in logs — an easy
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

> ⚠️ **These are live malicious indicators.** Only run this behind a firewall that is
> actually enforcing the feeds — the point is that the connection gets blocked. As a
> safeguard the tool **never downloads the body** of a threat-feed target (ignores
> `--full-download` for them) and never saves anything; it only opens the connection
> so the firewall can match and block it. It also skips cache-busting on these so
> URL-feed matching stays exact.

## Source IPs (multiple clients from one machine)

If your lab VM has several IPs bound to its NIC (e.g. `10.21.1.10, .12, .15, .20,
.32, .41`), the generator can **round-robin outgoing traffic across them** so the
firewall sees each IP as a separate client — separate policy matches, separate log
sources, separate per-IP stats.

By default `source_ips` in [config.json](config.json) is `"auto"`: every IPv4 on the
machine's NICs that can reach the internet is used (loopback, 169.254.x and
virtual adapters with no route out are skipped, with a note at startup), so moving to a new VM needs no
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

## DNS / DGA traffic (firewall DNS filtering + Botnet C&C detection)

[dns_gen.py](dns_gen.py) fires large volumes of DNS queries to exercise firewall
**DNS filtering** and **Botnet C&C / DGA detection**. It resolves through the OS's
configured DNS server (i.e. through the firewall) using `aiodns` (c-ares) for real
async scale.

It generates three kinds of domains (see the `dns` section of [config.json](config.json)):

- **DGA** — algorithmically generated domains in three styles that mirror real
  botnet families: high-entropy random (Conficker/Necurs), **date-seeded**
  deterministic (CryptoLocker-style — same date produces the same list), and
  dictionary-word (matsnu/suppobox). Most return **NXDOMAIN**, which is exactly the
  beaconing pattern DGA detection flags.
- **suspicious** — a curated list of dodgy-looking / dynamic-DNS test domains.
- **benign** — clean domains for baseline.

Blocking is detected as **NXDOMAIN vs resolved**, and — when the firewall DNS filter
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

The tool sniffs the first 4 KB of each response for block-page wording and reports
each request as **ok / blocked / error**, broken down per category and per HTTP status.
Detection is vendor-neutral and shared by every phase in
[blockpages.py](blockpages.py): strong phrases (Palo Alto "Web Page Blocked" /
"blocked in accordance with company policy", FortiGate "Virus/Malware Detected",
generic "blocked by your organization", …) count on their own; weaker words only count
when the page also names a security vendor. Add your device's response-page wording to
`STRONG_PHRASES` if it isn't recognised. DNS sinkhole answers (Palo Alto and FortiGuard
defaults) are matched via `dns.block_ips` in config.

## Editing targets

All targets live in [config.json](config.json). Each category has:

- `enabled`: include it in default runs (override with `--categories`).
- `expect`: `block` / `allow` / `mixed` — reporting hint only.
- `urls`: the list to hit.

The `adult` category ships **empty and disabled** — populate it yourself if your lab
policy requires testing that category.

## Notes for running behind the device under test

- Certificate validation is **disabled** (`ssl=False`) so the firewall's block page /
  deep-inspection cert doesn't abort requests. Fine for a lab, never for production.
- To make antivirus fire, use `--full-download` so the EICAR/AMTSO payloads actually
  cross the wire and get scanned (a `HEAD`-like 4 KB peek may not trigger AV).
- Expect connection resets / timeouts on blocked HTTPS sites when the firewall does
  certificate-based blocking rather than serving a replacement page — those show up as
  `errors` rather than `blocked`. Enable SSL deep inspection on the policy to get
  replacement block pages you can detect.
