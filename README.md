# FortiGate Lab Web Traffic Generator

Async HTTP(S) traffic generator for exercising **FortiGate web filtering, antivirus,
and application control** in a lab. It fires large volumes of concurrent requests at
categorized target lists (malware/EICAR, phishing, gambling, hacking, proxy-avoidance,
weapons, drugs, warez, streaming, and clean baseline) and reports what got through vs.
what the FortiGate blocked.

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
