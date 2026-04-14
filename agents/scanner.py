
import re
import time
import uuid
from collections import defaultdict
from datetime import datetime
from typing import List, Optional, Tuple

from core.state import AgentState, ParsedEvent


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 1 — Log Format Regex Patterns
# ═════════════════════════════════════════════════════════════════════════════

# Apache / Nginx Combined Log Format:
# 192.168.1.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326
APACHE_LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'          # IP address
    r'\s+\S+\s+\S+\s+'                            # ident, authuser
    r'\[(?P<timestamp>[^\]]+)\]'                  # [timestamp]
    r'\s+"(?P<method>\w+)\s+'                     # HTTP method
    r'(?P<url>\S+)'                               # URL / path
    r'[^"]*"'                                     # rest of request
    r'\s+(?P<status>\d{3})'                       # status code
    r'\s+(?P<size>\S+)',                          # response size
    re.IGNORECASE
)

# SSH Auth Log Format (syslog style):
# Apr 12 14:23:01 server sshd[1234]: Failed password for root from 192.168.1.5 port 22 ssh2
SSH_LOG_PATTERN = re.compile(
    r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)'         # Apr 12 14:23:01
    r'\s+\S+'                                      # hostname
    r'\s+sshd\[\d+\]:\s+'                         # sshd[pid]:
    r'(?P<message>.+)',                            # rest of message
    re.IGNORECASE
)

# IP extractor — fallback for non-standard lines
IP_ANYWHERE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 2 — Threat Detection Patterns
# Each entry: (pattern, event_type, confidence_score, description)
# ═════════════════════════════════════════════════════════════════════════════

THREAT_PATTERNS: List[Tuple[re.Pattern, str, float, str]] = [

    # ── SQL Injection ────────────────────────────────────────────────────────
    (re.compile(
        r"(union\s+select|select\s+\*|drop\s+table|insert\s+into"
        r"|delete\s+from|update\s+\w+\s+set"
        r"|or\s+1\s*=\s*1|and\s+1\s*=\s*1"
        r"|'\s*(or|and)\s*'[^']*'\s*=\s*'"
        r"|--\s*$|/\*.*\*/)",
        re.IGNORECASE
    ), "sql_injection", 0.90, "Classic SQL injection payload"),

    (re.compile(
        r"(%27|%22|%3D|%3B|%2D%2D)"              # URL-encoded SQL chars: ' " = ; --
        r"|(0x[0-9a-f]+)",                         # hex encoding
        re.IGNORECASE
    ), "sql_injection", 0.75, "URL-encoded SQL injection"),

    (re.compile(
        r"(sleep\s*\(\s*\d+|benchmark\s*\(|waitfor\s+delay"
        r"|pg_sleep|dbms_pipe\.receive_message)",
        re.IGNORECASE
    ), "sql_injection", 0.95, "Blind/time-based SQL injection"),

    # ── XSS Attempts ─────────────────────────────────────────────────────────
    (re.compile(
        r"(<script[\s>]|</script>|javascript\s*:"
        r"|on(load|error|click|mouseover)\s*="
        r"|<\s*img[^>]+src\s*=\s*[\"']?\s*javascript)",
        re.IGNORECASE
    ), "xss_attempt", 0.85, "Cross-site scripting payload"),

    (re.compile(
        r"(%3Cscript|%3C%2Fscript|%22%3E%3Cscript)",
        re.IGNORECASE
    ), "xss_attempt", 0.80, "URL-encoded XSS payload"),

    # ── Path Traversal ───────────────────────────────────────────────────────
    (re.compile(
        r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f"
        r"|/etc/passwd|/etc/shadow|/proc/self"
        r"|/windows/system32|boot\.ini)",
        re.IGNORECASE
    ), "path_traversal", 0.90, "Directory traversal attempt"),

    # ── SSH Brute Force ──────────────────────────────────────────────────────
    (re.compile(
        r"(failed password for (invalid user\s+)?\w+"
        r"|authentication failure"
        r"|invalid user \w+ from"
        r"|connection closed by authenticating user)",
        re.IGNORECASE
    ), "brute_force", 0.85, "SSH authentication failure"),

    (re.compile(
        r"(too many authentication failures"
        r"|maximum authentication attempts exceeded"
        r"|repeated login failures)",
        re.IGNORECASE
    ), "brute_force", 0.98, "SSH brute force threshold reached"),

    # ── HTTP Brute Force ─────────────────────────────────────────────────────
    (re.compile(
        r'(POST\s+/(?:login|signin|auth|wp-login\.php|admin|account/login)'
        r'[^\s]*\s+HTTP)',
        re.IGNORECASE
    ), "brute_force", 0.65, "HTTP login endpoint POST"),

    # ── Port / Service Scanning ──────────────────────────────────────────────
    (re.compile(
        r"(nmap|masscan|zmap|nikto|dirbuster|gobuster"
        r"|sqlmap|metasploit|burpsuite|hydra|medusa"
        r"|python-requests/|zgrab|shodan)",
        re.IGNORECASE
    ), "port_scan", 0.95, "Known scanner/exploit tool User-Agent"),

    (re.compile(
        r"(HEAD\s+/\s+HTTP|OPTIONS\s+\*\s+HTTP"
        r"|PROPFIND\s+|TRACE\s+/)",
        re.IGNORECASE
    ), "port_scan", 0.70, "HTTP method probe / service fingerprinting"),
]


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 3 — Brute Force Detector (stateful — tracks per-IP frequency)
# ═════════════════════════════════════════════════════════════════════════════

# Thresholds: agar ek IP se itne failures aayein to brute_force flag karo
SSH_FAIL_THRESHOLD   = 5    # 5 SSH failures = brute force
HTTP_LOGIN_THRESHOLD = 10   # 10 HTTP login POSTs = brute force


def _detect_brute_force_by_frequency(
    lines: List[str],
) -> dict:
    """
    Poori log list scan karo aur count karo:
      - Har IP se kitni SSH failures huin
      - Har IP se kitne HTTP login POSTs hue

    Returns:
        {
          "ssh":  {"192.168.1.5": 8, "10.0.0.2": 3},
          "http": {"192.168.1.9": 15}
        }
    """
    ssh_fails  = defaultdict(int)
    http_logins = defaultdict(int)

    ssh_fail_re  = re.compile(r"failed password|invalid user|authentication failure", re.I)
    http_login_re = re.compile(r'POST\s+/(?:login|signin|auth|wp-login)', re.I)

    for line in lines:
        ip = _extract_ip(line)
        if not ip:
            continue
        if ssh_fail_re.search(line):
            ssh_fails[ip] += 1
        elif http_login_re.search(line):
            http_logins[ip] += 1

    # Filter — sirf IPs jo threshold cross kar chuki hain
    flagged_ssh  = {ip: c for ip, c in ssh_fails.items()  if c >= SSH_FAIL_THRESHOLD}
    flagged_http = {ip: c for ip, c in http_logins.items() if c >= HTTP_LOGIN_THRESHOLD}

    return {"ssh": flagged_ssh, "http": flagged_http}


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 4 — Helper Functions
# ═════════════════════════════════════════════════════════════════════════════

def _extract_ip(line: str) -> Optional[str]:
    """Log line se pehla valid IP extract karo."""
    match = IP_ANYWHERE.search(line)
    if match:
        ip = match.group(1)
        # Private / loopback IPs ko skip karo (optional — comment out if needed)
        if not ip.startswith(("127.", "0.", "::1")):
            return ip
    return None


def _extract_url(line: str) -> Optional[str]:
    """Apache/Nginx log line se URL extract karo."""
    match = APACHE_LOG_PATTERN.match(line)
    if match:
        return match.group("url")
    # fallback — quoted string mein pehla path-like token
    url_fallback = re.search(r'"(?:GET|POST|PUT|DELETE|HEAD)\s+(\S+)', line, re.I)
    if url_fallback:
        return url_fallback.group(1)
    return None


def _extract_timestamp(line: str) -> str:
    """Log line se timestamp nikalo, ya current time return karo."""
    # Apache format: [10/Oct/2000:13:55:36 -0700]
    apache_ts = re.search(r'\[([^\]]+)\]', line)
    if apache_ts:
        return apache_ts.group(1)
    # Syslog format: Apr 12 14:23:01
    syslog_ts = re.search(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
    if syslog_ts:
        return syslog_ts.group(1)
    return datetime.utcnow().isoformat()


def _make_event(
    idx: int,
    event_type: str,
    source_ip: str,
    raw_line: str,
    confidence: float,
    target_url: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> ParsedEvent:
    """ParsedEvent TypedDict construct karo."""
    return ParsedEvent(
        event_id   = f"evt_{idx:04d}_{uuid.uuid4().hex[:6]}",
        event_type = event_type,
        source_ip  = source_ip,
        target_url = target_url or _extract_url(raw_line),
        timestamp  = timestamp or _extract_timestamp(raw_line),
        raw_line   = raw_line.strip(),
        confidence = round(confidence, 2),
    )


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 5 — Main Scanner Agent Function
# ═════════════════════════════════════════════════════════════════════════════

def scanner_agent(state: AgentState) -> AgentState:
    """
    LangGraph node — Agent A: Scanner.

    Reads:   state["raw_logs"]
    Writes:  state["parsed_events"], state["scanner_stats"],
             state["pipeline_status"]

    Algorithm:
        1. Har log line pe saare THREAT_PATTERNS run karo
        2. Frequency-based brute force check karo (per-IP thresholding)
        3. Duplicate events deduplicate karo (same IP + same type)
        4. ParsedEvent list state mein store karo
    """
    start_time = time.monotonic()

    state["pipeline_status"] = "scanning"
    raw_logs: List[str] = state.get("raw_logs", [])

    if not raw_logs:
        state["parsed_events"] = []
        state["scanner_stats"] = {
            "total_lines": 0,
            "suspicious":  0,
            "duration_ms": 0,
            "by_type":     {},
        }
        return state

    events:      List[ParsedEvent] = []
    event_idx:   int               = 0
    seen:        set                = set()   # dedupe: (ip, event_type, url)

    # ── Pass 1: Pattern matching on each line ─────────────────────────────────
    for line in raw_logs:
        line = line.strip()
        if not line:
            continue

        source_ip = _extract_ip(line)
        if not source_ip:
            continue

        matched_this_line = False

        for pattern, event_type, confidence, _desc in THREAT_PATTERNS:
            if not pattern.search(line):
                continue

            target_url  = _extract_url(line)
            dedup_key   = (source_ip, event_type, target_url or "")

            # Deduplicate — same IP doing same attack on same URL
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            events.append(_make_event(
                idx        = event_idx,
                event_type = event_type,
                source_ip  = source_ip,
                raw_line   = line,
                confidence = confidence,
                target_url = target_url,
            ))
            event_idx      += 1
            matched_this_line = True
            break  # ek line pe ek event — highest-priority match wins

    # ── Pass 2: Frequency-based brute force detection ─────────────────────────
    # Ye un IPs ko pakadta hai jo individually normal lagte hain but
    # repeatedly fail ho rahe hain (e.g. 20 failed SSH logins)
    brute_map = _detect_brute_force_by_frequency(raw_logs)

    already_flagged_ips = {e["source_ip"] for e in events if e["event_type"] == "brute_force"}

    for ip, count in brute_map["ssh"].items():
        if ip in already_flagged_ips:
            continue
        # Representative line dhundo is IP ke liye
        sample_line = next(
            (l for l in raw_logs if ip in l and re.search(r"failed password|invalid user", l, re.I)),
            f"[frequency-detected] {ip} had {count} SSH failures"
        )
        events.append(_make_event(
            idx        = event_idx,
            event_type = "brute_force",
            source_ip  = ip,
            raw_line   = sample_line,
            confidence = min(0.70 + (count / 100), 0.99),  # count se confidence badhti hai
            target_url = None,
        ))
        event_idx += 1

    for ip, count in brute_map["http"].items():
        if ip in already_flagged_ips:
            continue
        sample_line = next(
            (l for l in raw_logs if ip in l and re.search(r"POST\s+/(?:login|signin|auth)", l, re.I)),
            f"[frequency-detected] {ip} had {count} HTTP login attempts"
        )
        events.append(_make_event(
            idx        = event_idx,
            event_type = "brute_force",
            source_ip  = ip,
            raw_line   = sample_line,
            confidence = min(0.65 + (count / 100), 0.99),
        ))
        event_idx += 1

    # ── Build stats ───────────────────────────────────────────────────────────
    by_type: dict = defaultdict(int)
    for e in events:
        by_type[e["event_type"]] += 1

    duration_ms = round((time.monotonic() - start_time) * 1000, 2)

    # ── Write to state ────────────────────────────────────────────────────────
    state["parsed_events"] = events
    state["scanner_stats"] = {
        "total_lines":  len(raw_logs),
        "suspicious":   len(events),
        "clean":        len(raw_logs) - len(events),
        "duration_ms":  duration_ms,
        "by_type":      dict(by_type),
        "unique_ips":   len({e["source_ip"] for e in events}),
    }

    return state