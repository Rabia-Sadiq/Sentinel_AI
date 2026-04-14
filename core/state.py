
from typing import TypedDict, List, Optional, Literal
from datetime import datetime


# ─── Sub-types ────────────────────────────────────────────────────────────────

class ParsedEvent(TypedDict):
    """Scanner agent ka output — ek suspicious log line se extract kiya gaya event."""
    event_id:    str                          # unique ID e.g. "evt_001"
    event_type:  Literal[
        "sql_injection",
        "brute_force",
        "port_scan",
        "xss_attempt",
        "path_traversal",
        "unknown"
    ]
    source_ip:   str                          # attacker ka IP address
    target_url:  Optional[str]                # kaunsa endpoint hit hua
    timestamp:   str                          # log line ka original timestamp
    raw_line:    str                          # original log line (debugging ke liye)
    confidence:  float                        # 0.0 – 1.0, regex match ki certainty


class ThreatAnalysis(TypedDict):
    """Analyzer agent ka output — AI ka full threat assessment."""
    threat_type:     str                      # e.g. "SQL Injection", "Brute Force"
    severity:        Literal["low", "medium", "high", "critical"]
    confidence:      float                    # AI ka confidence score 0.0 – 1.0
    source_ip:       str                      # primary attacker IP
    attack_summary:  str                      # human-readable description
    indicators:      List[str]                # specific patterns jo mili hain
    recommendation:  Literal[
        "monitor",                            # sirf dekho, kuch nahi karo
        "alert",                              # team ko notify karo
        "block_ip",                           # IP block karo
        "block_and_alert",                    # dono karo
        "escalate"                            # human review chahiye
    ]
    raw_ai_response: str                      # full Claude response (audit ke liye)


class ResponderAction(TypedDict):
    """Responder agent ka output — kya action liya gaya."""
    action_type:   Literal[
        "ip_blocked",
        "alert_sent",
        "escalated",
        "skipped",                            # low severity, no action needed
        "pending_approval"                    # human approval ka wait hai
    ]
    target_ip:     str
    method:        Literal["iptables", "cloud_firewall", "simulated"]
    success:       bool
    message:       str                        # e.g. "IP 192.168.1.1 blocked via iptables"
    executed_at:   str                        # ISO timestamp


# ─── Main AgentState ──────────────────────────────────────────────────────────

class AgentState(TypedDict):
    """
    ASOC ka central shared state.

    Flow:
        [raw_logs]
            |
            v  Scanner Agent
        [parsed_events]
            |
            v  Analyzer Agent
        [threat_analysis]
            |
            v  Responder Agent
        [responder_action]  +  [blocked_ips]  +  [pipeline_status]
    """

    # ── INPUT (FastAPI endpoint se aata hai) ──────────────────────────────────
    raw_logs:          List[str]
    # e.g. ['192.168.1.5 - - [12/Apr/2025] "GET /login?id=1 OR 1=1" 200']

    session_id:        str
    # har /analyze request ka unique ID — Redis mein history store karne ke liye

    ingested_at:       str
    # jab logs receive hue — ISO 8601 format e.g. "2025-04-12T14:30:00"

    # ── SCANNER OUTPUT ────────────────────────────────────────────────────────
    parsed_events:     List[ParsedEvent]
    # scanner ne jo suspicious events nikale — khali list agar kuch nahi mila

    scanner_stats:     Optional[dict]
    # e.g. {"total_lines": 500, "suspicious": 12, "duration_ms": 43}

    # ── ANALYZER OUTPUT ───────────────────────────────────────────────────────
    threat_analysis:   Optional[ThreatAnalysis]
    # None agar parsed_events khali tha (scanner ne kuch nahi pakda)

    severity:          Optional[Literal["low", "medium", "high", "critical"]]
    # shortcut field — graph mein conditional routing ke liye use hota hai
    # e.g. severity == "low"  -> responder skip karo
    #      severity == "high" -> auto block
    #      severity == "critical" -> human approval lao

    # ── RESPONDER OUTPUT ──────────────────────────────────────────────────────
    responder_action:  Optional[ResponderAction]
    # None agar responder ne kuch nahi kiya (low severity)

    blocked_ips:       List[str]
    # session mein block ki gayi sari IPs — duplicate blocking rokne ke liye

    # ── HUMAN-IN-THE-LOOP ─────────────────────────────────────────────────────
    awaiting_approval: bool
    # True = critical threat mili, human ka decision pending hai

    approved_by:       Optional[str]
    # agar human ne approve kiya — unka username/email

    # ── PIPELINE METADATA ─────────────────────────────────────────────────────
    pipeline_status:   Literal[
        "started",
        "scanning",
        "analyzing",
        "responding",
        "awaiting_approval",
        "completed",
        "error"
    ]

    error_message:     Optional[str]
    # koi bhi agent fail ho to yahan message store hoga

    completed_at:      Optional[str]
    # pipeline complete hone ka timestamp


# ─── Factory Function ─────────────────────────────────────────────────────────

def create_initial_state(logs: List[str], session_id: str) -> AgentState:
    """
    Har naye /analyze request ke liye fresh state banao.

    Usage:
        state = create_initial_state(logs=request.logs, session_id="abc-123")
        result = graph.invoke(state)
    """
    return AgentState(
        # Input
        raw_logs           = logs,
        session_id         = session_id,
        ingested_at        = datetime.utcnow().isoformat(),

        # Scanner
        parsed_events      = [],
        scanner_stats      = None,

        # Analyzer
        threat_analysis    = None,
        severity           = None,

        # Responder
        responder_action   = None,
        blocked_ips        = [],

        # Human loop
        awaiting_approval  = False,
        approved_by        = None,

        # Pipeline
        pipeline_status    = "started",
        error_message      = None,
        completed_at       = None,
    )