#!/usr/bin/env python3
# tests/test_pipeline.py
# ─────────────────────────────────────────────────────────────────────────────
# ASOC — Full Pipeline Test Script
#
# Kya test karta hai:
#   1.  Health check
#   2.  SQL Injection logs       → suspicious events detected
#   3.  SSH Brute Force logs     → brute_force events detected
#   4.  Clean / normal logs      → zero false positives
#   5.  Mixed attack logs        → multiple threat types
#   6.  Path Traversal logs      → path_traversal detected
#   7.  XSS attempt logs         → xss_attempt detected
#   8.  Empty logs               → graceful handling
#   9.  /status endpoint         → full state retrieval
#  10.  /blocked-ips endpoint    → IP list check
#  11.  HITL approval flow       → critical pending → approve → complete
#  12.  404 on unknown session   → error handling
#
# Modes:
#   python3 tests/test_pipeline.py              # in-process (no server needed)
#   python3 tests/test_pipeline.py --live       # against running server
#   python3 tests/test_pipeline.py --url http://localhost:8000  # custom URL
# ─────────────────────────────────────────────────────────────────────────────

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Protocol

import httpx
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

console = Console()


# ─────────────────────────────────────────────────────────────────────────────
# Client abstraction — wraps both TestClient and httpx.Client identically
# ─────────────────────────────────────────────────────────────────────────────

class HttpClient(Protocol):
    def post(self, url: str, **kw) -> Any: ...
    def get(self,  url: str, **kw) -> Any: ...


def _post(client, base: str, path: str, payload: dict) -> dict:
    r = client.post(f"{base}{path}", json=payload)
    if hasattr(r, "raise_for_status"):
        r.raise_for_status()
    return r.json()


def _get(client, base: str, path: str) -> dict:
    r = client.get(f"{base}{path}")
    if hasattr(r, "raise_for_status"):
        r.raise_for_status()
    return r.json()


def _get_status(r) -> int:
    return r.status_code


# ─────────────────────────────────────────────────────────────────────────────
# Log fixtures
# ─────────────────────────────────────────────────────────────────────────────

LOGS = {
    "sql_injection": [
        '10.13.37.5 - - [12/Apr/2025:09:01:01 -0500] "GET /products?id=1 HTTP/1.1" 200 1024',
        '10.13.37.5 - - [12/Apr/2025:09:01:02 -0500] "GET /login?user=admin\'-- HTTP/1.1" 200 512',
        '10.13.37.5 - - [12/Apr/2025:09:01:03 -0500] "GET /users?q=1 UNION SELECT username,password FROM users-- HTTP/1.1" 500 64',
        '10.13.37.5 - - [12/Apr/2025:09:01:04 -0500] "GET /search?term=1; DROP TABLE sessions-- HTTP/1.1" 400 32',
        "10.13.37.5 - - [12/Apr/2025:09:01:05 -0500] \"GET /api/data?id=1 AND SLEEP(5)-- HTTP/1.1\" 200 16",
        "10.13.37.5 - - [12/Apr/2025:09:01:06 -0500] \"GET /report?year=2024' OR '1'='1 HTTP/1.1\" 200 256",
    ],
    "brute_force_ssh": [
        "Apr 12 09:05:01 prod sshd[7001]: Failed password for root from 198.20.99.1 port 22 ssh2",
        "Apr 12 09:05:02 prod sshd[7002]: Failed password for root from 198.20.99.1 port 22 ssh2",
        "Apr 12 09:05:03 prod sshd[7003]: Failed password for invalid user ubuntu from 198.20.99.1 port 22 ssh2",
        "Apr 12 09:05:04 prod sshd[7004]: Failed password for invalid user admin from 198.20.99.1 port 22 ssh2",
        "Apr 12 09:05:05 prod sshd[7005]: Failed password for root from 198.20.99.1 port 22 ssh2",
        "Apr 12 09:05:06 prod sshd[7006]: Failed password for root from 198.20.99.1 port 22 ssh2",
        "Apr 12 09:05:07 prod sshd[7007]: Too many authentication failures for root from 198.20.99.1",
    ],
    "normal_traffic": [
        '192.168.1.100 - - [12/Apr/2025:10:00:01 -0500] "GET /index.html HTTP/1.1" 200 2048',
        '192.168.1.100 - - [12/Apr/2025:10:00:02 -0500] "GET /static/app.js HTTP/1.1" 200 15360',
        '192.168.1.101 - - [12/Apr/2025:10:00:03 -0500] "POST /api/login HTTP/1.1" 200 512',
        '192.168.1.102 - - [12/Apr/2025:10:00:04 -0500] "GET /dashboard HTTP/1.1" 200 8192',
        '192.168.1.103 - - [12/Apr/2025:10:00:05 -0500] "GET /profile HTTP/1.1" 200 1024',
        '10.0.0.1 - - [12/Apr/2025:10:00:06 -0500] "GET /health HTTP/1.1" 200 32',
        '192.168.1.104 - - [12/Apr/2025:10:00:07 -0500] "PUT /api/settings HTTP/1.1" 204 0',
        '192.168.1.100 - - [12/Apr/2025:10:00:08 -0500] "GET /logout HTTP/1.1" 302 0',
    ],
    "mixed_attack": [
        '10.13.37.5 - - [12/Apr/2025:11:00:01 -0500] "GET /admin/../../../etc/passwd HTTP/1.1" 403 64',
        '10.13.37.5 - - [12/Apr/2025:11:00:02 -0500] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 256',
        '10.13.37.5 - - [12/Apr/2025:11:00:03 -0500] "GET /login?id=1\' UNION SELECT * FROM admin-- HTTP/1.1" 500 32',
        '172.16.5.200 - - [12/Apr/2025:11:00:04 -0500] "HEAD / HTTP/1.1" 200 0',
        '172.16.5.200 - - [12/Apr/2025:11:00:05 -0500] "OPTIONS * HTTP/1.1" 200 0',
        '192.168.1.100 - - [12/Apr/2025:11:00:06 -0500] "GET /index.html HTTP/1.1" 200 2048',
        "Apr 12 11:00:07 prod sshd[8001]: Failed password for root from 45.76.100.2 port 22 ssh2",
        "Apr 12 11:00:08 prod sshd[8002]: Failed password for root from 45.76.100.2 port 22 ssh2",
        "Apr 12 11:00:09 prod sshd[8003]: Failed password for root from 45.76.100.2 port 22 ssh2",
        "Apr 12 11:00:10 prod sshd[8004]: Failed password for invalid user deploy from 45.76.100.2 port 22 ssh2",
        "Apr 12 11:00:11 prod sshd[8005]: Failed password for root from 45.76.100.2 port 22 ssh2",
        "Apr 12 11:00:12 prod sshd[8006]: Failed password for root from 45.76.100.2 port 22 ssh2",
    ],
    "path_traversal": [
        '198.51.100.7 - - [12/Apr/2025:12:00:01 -0500] "GET /index.php?page=../../../etc/passwd HTTP/1.1" 403 64',
        '198.51.100.7 - - [12/Apr/2025:12:00:02 -0500] "GET /../../../windows/system32/cmd.exe HTTP/1.1" 404 64',
        '198.51.100.7 - - [12/Apr/2025:12:00:03 -0500] "GET /..%2F..%2F..%2Fetc%2Fshadow HTTP/1.1" 403 32',
        '192.168.1.50 - - [12/Apr/2025:12:00:04 -0500] "GET /assets/logo.png HTTP/1.1" 200 8192',
    ],
    "xss": [
        '172.16.0.99 - - [12/Apr/2025:13:00:01 -0500] "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1" 200 256',
        '172.16.0.99 - - [12/Apr/2025:13:00:02 -0500] "POST /comment HTTP/1.1" 200 128',
        '172.16.0.99 - - [12/Apr/2025:13:00:03 -0500] "GET /page?id=1"><img src=x onerror=alert(1)> HTTP/1.1" 200 512',
        '10.0.0.1 - - [12/Apr/2025:13:00:04 -0500] "GET /health HTTP/1.1" 200 4',
    ],
    "empty": [],
}


# ─────────────────────────────────────────────────────────────────────────────
# Test result model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TestResult:
    name:    str
    passed:  bool              = False
    details: List[str]         = field(default_factory=list)
    data:    Optional[dict]    = None
    error:   Optional[str]     = None


# ─────────────────────────────────────────────────────────────────────────────
# Individual tests
# ─────────────────────────────────────────────────────────────────────────────

def t_health(client, base) -> TestResult:
    r = TestResult("Health check")
    try:
        d = _get(client, base, "/health")
        r.passed  = d.get("status") == "ok"
        r.details = [f"status={d['status']}", f"time={d.get('time','?')[:19]}"]
    except Exception as e:
        r.passed = False; r.error = str(e)
    return r


def t_sql_injection(client, base) -> TestResult:
    r = TestResult("SQL Injection — detection + pipeline")
    try:
        d = _post(client, base, "/analyze", {"logs": LOGS["sql_injection"], "session_id": "test-sql-001"})
        stats       = d["scanner_stats"]
        by_type     = stats.get("by_type", {})
        sql_count   = by_type.get("sql_injection", 0)
        r.passed    = sql_count >= 2 and d["pipeline_status"] == "completed"
        r.details   = [
            f"total lines      : {stats['total_lines']}",
            f"suspicious       : {stats['suspicious']}",
            f"sql_injection    : {sql_count}",
            f"severity         : {d['severity']}",
            f"pipeline_status  : {d['pipeline_status']}",
            f"action           : {(d['action_taken'] or 'none')[:72]}",
            f"blocked_ips      : {d['blocked_ips']}",
        ]
        r.data = d
    except Exception as e:
        r.passed = False; r.error = str(e)
    return r


def t_brute_force(client, base) -> TestResult:
    r = TestResult("SSH Brute Force — frequency detection")
    try:
        d = _post(client, base, "/analyze", {"logs": LOGS["brute_force_ssh"], "session_id": "test-brute-001"})
        by_type   = d["scanner_stats"].get("by_type", {})
        bf_count  = by_type.get("brute_force", 0)
        r.passed  = bf_count >= 1 and d["pipeline_status"] == "completed"
        r.details = [
            f"total lines      : {d['scanner_stats']['total_lines']}",
            f"brute_force hits : {bf_count}",
            f"source IP        : 198.20.99.1",
            f"severity         : {d['severity']}",
            f"pipeline_status  : {d['pipeline_status']}",
            f"action           : {(d['action_taken'] or 'none')[:72]}",
        ]
        r.data = d
    except Exception as e:
        r.passed = False; r.error = str(e)
    return r


def t_clean_logs(client, base) -> TestResult:
    r = TestResult("Normal traffic — zero false positives")
    try:
        d = _post(client, base, "/analyze", {"logs": LOGS["normal_traffic"], "session_id": "test-clean-001"})
        r.passed  = (d["scanner_stats"]["suspicious"] == 0 and d["blocked_ips"] == [])
        r.details = [
            f"total lines      : {d['scanner_stats']['total_lines']}",
            f"suspicious       : {d['scanner_stats']['suspicious']}",
            f"blocked_ips      : {d['blocked_ips']}",
            f"severity         : {d['severity']}",
            f"pipeline_status  : {d['pipeline_status']}",
        ]
        r.data = d
    except Exception as e:
        r.passed = False; r.error = str(e)
    return r


def t_mixed(client, base) -> TestResult:
    r = TestResult("Mixed attack — SQL + XSS + Path + Brute Force + Scan")
    try:
        d = _post(client, base, "/analyze", {"logs": LOGS["mixed_attack"], "session_id": "test-mixed-001"})
        by_type     = d["scanner_stats"].get("by_type", {})
        multi_type  = len(by_type) >= 2
        r.passed    = multi_type and d["pipeline_status"] == "completed"
        r.details   = [
            f"total lines      : {d['scanner_stats']['total_lines']}",
            f"suspicious       : {d['scanner_stats']['suspicious']}",
            f"threat types     : {list(by_type.keys())}",
            f"unique attacker IPs : {d['scanner_stats'].get('unique_ips')}",
            f"severity         : {d['severity']}",
            f"pipeline_status  : {d['pipeline_status']}",
            f"action           : {(d['action_taken'] or 'none')[:72]}",
        ]
        r.data = d
    except Exception as e:
        r.passed = False; r.error = str(e)
    return r


def t_path_traversal(client, base) -> TestResult:
    r = TestResult("Path Traversal — /etc/passwd, system32")
    try:
        d = _post(client, base, "/analyze", {"logs": LOGS["path_traversal"], "session_id": "test-pt-001"})
        by_type  = d["scanner_stats"].get("by_type", {})
        pt_count = by_type.get("path_traversal", 0)
        r.passed  = pt_count >= 1 and d["pipeline_status"] == "completed"
        r.details = [
            f"path_traversal   : {pt_count}",
            f"severity         : {d['severity']}",
            f"pipeline_status  : {d['pipeline_status']}",
        ]
        r.data = d
    except Exception as e:
        r.passed = False; r.error = str(e)
    return r


def t_xss(client, base) -> TestResult:
    r = TestResult("XSS Attempts — script tags + event handlers")
    try:
        d = _post(client, base, "/analyze", {"logs": LOGS["xss"], "session_id": "test-xss-001"})
        by_type   = d["scanner_stats"].get("by_type", {})
        xss_count = by_type.get("xss_attempt", 0)
        r.passed  = xss_count >= 1 and d["pipeline_status"] == "completed"
        r.details = [
            f"xss_attempt      : {xss_count}",
            f"severity         : {d['severity']}",
            f"pipeline_status  : {d['pipeline_status']}",
        ]
        r.data = d
    except Exception as e:
        r.passed = False; r.error = str(e)
    return r


def t_empty(client, base) -> TestResult:
    r = TestResult("Empty logs — graceful no-op")
    try:
        d = _post(client, base, "/analyze", {"logs": LOGS["empty"], "session_id": "test-empty-001"})
        r.passed  = d["pipeline_status"] == "completed" and d["scanner_stats"]["suspicious"] == 0
        r.details = [
            f"pipeline_status  : {d['pipeline_status']}",
            f"suspicious       : {d['scanner_stats']['suspicious']}",
            f"severity         : {d['severity']}",
        ]
        r.data = d
    except Exception as e:
        r.passed = False; r.error = str(e)
    return r


def t_status_endpoint(client, base) -> TestResult:
    r = TestResult("/status — full state retrieval")
    try:
        # Use the sql session we already created
        d = _get(client, base, "/status/test-sql-001")
        has_events   = isinstance(d.get("parsed_events"), list) and len(d["parsed_events"]) > 0
        has_stats    = d.get("scanner_stats") is not None
        has_analysis = d.get("threat_analysis") is not None or d.get("severity") is not None
        r.passed  = has_events and has_stats
        r.details = [
            f"parsed_events    : {len(d.get('parsed_events', []))} events",
            f"threat_analysis  : {'set' if d.get('threat_analysis') else 'none (no API key)'}",
            f"scanner_stats    : {'set' if has_stats else 'missing'}",
            f"severity         : {d.get('severity')}",
            f"ingested_at      : {(d.get('ingested_at') or '')[:19]}",
            f"completed_at     : {(d.get('completed_at') or 'pending')[:19]}",
        ]
        r.data = d
    except Exception as e:
        r.passed = False; r.error = str(e)
    return r


def t_blocked_ips(client, base) -> TestResult:
    r = TestResult("/blocked-ips — IP list endpoint")
    try:
        d = _get(client, base, "/blocked-ips/test-sql-001")
        r.passed  = "blocked_ips" in d
        r.details = [
            f"session_id       : {d.get('session_id')}",
            f"blocked_ips      : {d.get('blocked_ips')}",
        ]
        r.data = d
    except Exception as e:
        r.passed = False; r.error = str(e)
    return r


def t_hitl_flow(client, base) -> TestResult:
    r = TestResult("HITL — critical pause → /approve → resume")
    try:
        SID = "test-hitl-001"

        # ── Step 1: Inject a critical-severity session ────────────────────────
        # Live mode   → POST /debug/inject-critical (server ka endpoint)
        # In-process  → directly patch server_main._sessions (same process)
        if base:
            # Live mode — use debug endpoint
            inject = _post(client, base, f"/debug/inject-critical?session_id={SID}", {})
            assert inject.get("awaiting_approval") is True, f"Inject failed: {inject}"
        else:
            # In-process — direct memory patch
            import sys, os
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            import main as server_main
            from core.state import create_initial_state, ThreatAnalysis
            from agents.scanner import scanner_agent
            state = create_initial_state(logs=LOGS["sql_injection"], session_id=SID)
            state = scanner_agent(state)
            state["threat_analysis"] = ThreatAnalysis(
                threat_type="SQL Injection", severity="critical", confidence=0.97,
                source_ip="10.13.37.5",
                attack_summary="Critical SQL injection — UNION SELECT confirmed",
                indicators=["UNION SELECT username,password", "AND SLEEP(5)"],
                recommendation="escalate", raw_ai_response="{}"
            )
            state["severity"]          = "critical"
            state["awaiting_approval"] = True
            state["pipeline_status"]   = "awaiting_approval"
            server_main._sessions[SID] = state

        # ── Step 2: Verify /status shows awaiting_approval ────────────────────
        status = _get(client, base, f"/status/{SID}")
        assert status.get("awaiting_approval") is True, \
            f"Expected awaiting_approval=True, got {status.get('awaiting_approval')}"

        # ── Step 3: POST /approve ─────────────────────────────────────────────
        approved = _post(client, base, "/approve", {
            "session_id": SID,
            "approver":   "sarah.ali@company.com"
        })

        # ── Step 4: Verify pipeline completed ────────────────────────────────
        final = _get(client, base, f"/status/{SID}")
        r.passed = (
            approved.get("pipeline_status") == "completed"
            and not final.get("awaiting_approval", True)
        )
        r.details = [
            f"inject status    : awaiting_approval=True",
            f"approver         : sarah.ali@company.com",
            f"action           : {(approved.get('action_taken') or 'none')[:70]}",
            f"blocked_ips      : {approved.get('blocked_ips', [])}",
            f"pipeline_status  : {approved.get('pipeline_status')}",
            f"final awaiting   : {final.get('awaiting_approval')}",
        ]
        r.data = approved
    except Exception as e:
        r.passed = False; r.error = str(e)
    return r


def t_404(client, base) -> TestResult:
    r = TestResult("404 on unknown session_id — error handling")
    try:
        try:
            _get(client, base, "/status/non-existent-xyz-session")
            r.passed  = False
            r.details = ["Expected 404 but got 200"]
        except Exception as exc:
            # TestClient raises exception on 4xx; check message contains 404
            code = getattr(getattr(exc, 'response', None), 'status_code', None)
            got_404 = code == 404 or "404" in str(exc)
            r.passed  = got_404
            r.details = [f"HTTP 404 correctly returned (code={code})"]
    except Exception as e:
        r.passed = False; r.error = str(e)
    return r


# ─────────────────────────────────────────────────────────────────────────────
# Rich rendering helpers
# ─────────────────────────────────────────────────────────────────────────────

SEV_STYLE = {"critical":"bold red","high":"red","medium":"yellow","low":"green"}
STA_STYLE = {"completed":"green","awaiting_approval":"yellow","error":"red"}

def _sev(s):
    t = Text(str(s or "none").upper()); t.stylize(SEV_STYLE.get(s,"white")); return t

def render_result(r: TestResult, idx: int):
    icon  = "[bold green]PASS[/]" if r.passed else "[bold red]FAIL[/]"
    color = "green" if r.passed else "red"
    body  = "\n".join(f"  {d}" for d in r.details)
    if r.error:
        body += f"\n  [red]ERROR: {r.error}[/red]"
    console.print(Panel(
        body or "  (no details)",
        title=f" {idx:02d}. {r.name} — {icon} ",
        border_style=color, padding=(0,1)
    ))


def render_pipeline_table(label: str, data: Optional[dict]):
    if not data: return
    stats = data.get("scanner_stats") or {}
    if not stats: return
    console.print(f"\n[bold cyan]     Scanner breakdown — {label}[/]")
    t = Table(box=box.SIMPLE, show_header=False, padding=(0,3))
    t.add_column("k", style="dim"); t.add_column("v")
    rows = [
        ("Lines scanned",  str(stats.get("total_lines","—"))),
        ("Suspicious",     str(stats.get("suspicious","—"))),
        ("Clean",          str(stats.get("clean","—"))),
        ("Unique IPs",     str(stats.get("unique_ips","—"))),
        ("Duration",       f"{stats.get('duration_ms','—')} ms"),
        ("Threat types",   str(stats.get("by_type",{}))),
        ("Severity",       ""),
        ("Action",         (data.get("action_taken") or "—")[:70]),
    ]
    for k, v in rows:
        if k == "Severity":
            t.add_row(k, _sev(data.get("severity")))
        else:
            t.add_row(k, v)
    console.print(t)


def render_summary(results: List[TestResult]):
    passed = sum(1 for r in results if r.passed)
    total  = len(results)
    color  = "green" if passed == total else ("yellow" if passed > total//2 else "red")
    t = Table(title="Test Summary", box=box.ROUNDED, border_style=color)
    t.add_column("#",      width=4, justify="right")
    t.add_column("Test",   width=52)
    t.add_column("Result", width=8, justify="center")
    for i, r in enumerate(results, 1):
        icon = "[green]PASS[/]" if r.passed else "[red]FAIL[/]"
        t.add_row(str(i), r.name, icon)
    console.print(t)
    verdict = "All tests passed!" if passed == total else f"{total-passed} test(s) failed"
    console.print(f"\n[{color}]  {passed}/{total} — {verdict}[/]\n")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def make_in_process_client():
    """FastAPI TestClient — no network needed."""
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from fastapi.testclient import TestClient
    import main as server_main
    return TestClient(server_main.app), ""


def make_live_client(url: str):
    """httpx client for external server."""
    return httpx.Client(timeout=30), url.rstrip("/")


def main():
    parser = argparse.ArgumentParser(description="ASOC test suite")
    parser.add_argument("--live",    action="store_true", help="Use running server instead of in-process")
    parser.add_argument("--url",     default="http://127.0.0.1:8000", help="Server URL (--live mode)")
    args = parser.parse_args()

    console.print(Rule("[bold]ASOC — Full Pipeline Test Suite[/]"))

    if args.live or args.url != "http://127.0.0.1:8000":
        client, base = make_live_client(args.url)
        console.print(f"  Mode   : [yellow]live[/] → [cyan]{base}[/]")
    else:
        client, base = make_in_process_client()
        console.print(f"  Mode   : [green]in-process[/] (FastAPI TestClient)")

    console.print(f"  Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    TESTS = [
        ("health",          t_health),
        ("sql_injection",   t_sql_injection),
        ("brute_force",     t_brute_force),
        ("clean_logs",      t_clean_logs),
        ("mixed",           t_mixed),
        ("path_traversal",  t_path_traversal),
        ("xss",             t_xss),
        ("empty",           t_empty),
        ("status",          t_status_endpoint),
        ("blocked_ips",     t_blocked_ips),
        ("hitl",            t_hitl_flow),
        ("404",             t_404),
    ]

    PIPELINE_DETAIL_TESTS = {"sql_injection", "brute_force", "mixed", "clean_logs"}

    results: List[TestResult] = []
    for key, fn in TESTS:
        r = fn(client, base)
        results.append(r)
        render_result(r, len(results))
        if key in PIPELINE_DETAIL_TESTS:
            render_pipeline_table(r.name, r.data)
        console.print()

    render_summary(results)
    sys.exit(0 if all(r.passed for r in results) else 1)


if __name__ == "__main__":
    main()