
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from core.graph import build_graph, build_graph_with_memory
from core.state import AgentState, create_initial_state
from agents.responder import approve_and_respond

app = FastAPI(
    title       = "ASOC — Autonomous Security Operations Center",
    description = "Multi-agent threat detection and response system",
    version     = "1.0.0",
)

# In-memory session store (Redis se replace karo production mein)
_sessions: Dict[str, AgentState] = {}

# Two graph variants — stateless for normal, memory for HITL
_graph        = build_graph()
_graph_memory = build_graph_with_memory()


# ─── Request / Response Models ────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    logs:       List[str]
    session_id: Optional[str] = None   # caller provide kar sakta hai, warna auto-generate


class AnalyzeResponse(BaseModel):
    session_id:      str
    pipeline_status: str
    severity:        Optional[str]
    action_taken:    Optional[str]
    threat_summary:  Optional[str]
    blocked_ips:     List[str]
    scanner_stats:   Optional[dict]
    awaiting_approval: bool


class ApproveRequest(BaseModel):
    session_id: str
    approver:   str


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    """
    Logs submit karo — full Scanner → Analyzer → Responder pipeline run hoti hai.
    Critical threats ke liye pipeline pause ho jaati hai, /approve se resume hogi.
    """
    session_id = req.session_id or f"sess_{uuid.uuid4().hex[:10]}"
    state      = create_initial_state(logs=req.logs, session_id=session_id)

    severity_hint = None  # will be set after graph runs

    try:
        config = {"configurable": {"thread_id": session_id}}
        result = _graph_memory.invoke(state, config=config)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pipeline error: {str(e)}")

    _sessions[session_id] = result

    # Normalize: agar graph END tak pohoncha lekin status abhi bhi
    # "analyzing" hai (low severity short-circuit) to completed mark karo
    if result["pipeline_status"] in ("analyzing", "scanning", "started"):
        result["pipeline_status"] = "completed"
        from datetime import datetime, timezone
        if not result.get("completed_at"):
            result["completed_at"] = datetime.now(timezone.utc).isoformat()

    action_msg = None
    if result.get("responder_action"):
        action_msg = result["responder_action"].get("message")

    threat_summary = None
    if result.get("threat_analysis"):
        threat_summary = result["threat_analysis"].get("attack_summary")

    return AnalyzeResponse(
        session_id        = session_id,
        pipeline_status   = result["pipeline_status"],
        severity          = result.get("severity"),
        action_taken      = action_msg,
        threat_summary    = threat_summary,
        blocked_ips       = result.get("blocked_ips", []),
        scanner_stats     = result.get("scanner_stats"),
        awaiting_approval = result.get("awaiting_approval", False),
    )


@app.get("/status/{session_id}")
def get_status(session_id: str):
    """Session ka full state return karo."""
    state = _sessions.get(session_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")
    return {
        "session_id":       session_id,
        "pipeline_status":  state["pipeline_status"],
        "severity":         state.get("severity"),
        "parsed_events":    state.get("parsed_events", []),
        "threat_analysis":  state.get("threat_analysis"),
        "responder_action": state.get("responder_action"),
        "blocked_ips":      state.get("blocked_ips", []),
        "awaiting_approval":state.get("awaiting_approval", False),
        "approved_by":      state.get("approved_by"),
        "scanner_stats":    state.get("scanner_stats"),
        "ingested_at":      state.get("ingested_at"),
        "completed_at":     state.get("completed_at"),
    }


@app.post("/approve")
def approve(req: ApproveRequest):
    """
    Critical threat ke liye human approval do.
    Pipeline resume ho jaati hai aur IP block hoti hai.
    """
    state = _sessions.get(req.session_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Session '{req.session_id}' not found")

    if not state.get("awaiting_approval"):
        raise HTTPException(status_code=400, detail="Session awaiting approval mein nahi hai")

    updated = approve_and_respond(state, approver=req.approver)
    _sessions[req.session_id] = updated

    return {
        "session_id":     req.session_id,
        "approved_by":    req.approver,
        "action_taken":   updated["responder_action"]["message"] if updated.get("responder_action") else None,
        "blocked_ips":    updated.get("blocked_ips", []),
        "pipeline_status":updated["pipeline_status"],
    }


@app.get("/blocked-ips/{session_id}")
def blocked_ips(session_id: str):
    state = _sessions.get(session_id)
    if not state:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"session_id": session_id, "blocked_ips": state.get("blocked_ips", [])}


# ── Debug / Test endpoint (disable in production) ────────────────────────────
@app.post("/debug/inject-critical")
def debug_inject_critical(session_id: str):
    """
    Test-only endpoint — critical threat state inject karo HITL test ke liye.
    Production mein is endpoint ko remove ya disable karo.
    """
    from core.state import ThreatAnalysis
    from agents.scanner import scanner_agent

    logs = [
        '10.13.37.5 - - [12/Apr/2025:09:01:03 -0500] "GET /users?q=1 UNION SELECT username,password FROM users-- HTTP/1.1" 500 64',
        '10.13.37.5 - - [12/Apr/2025:09:01:05 -0500] "GET /api/data?id=1 AND SLEEP(5)-- HTTP/1.1" 200 16',
    ]
    state = create_initial_state(logs=logs, session_id=session_id)
    state = scanner_agent(state)
    state["threat_analysis"] = ThreatAnalysis(
        threat_type    = "SQL Injection",
        severity       = "critical",
        confidence     = 0.97,
        source_ip      = "10.13.37.5",
        attack_summary = "Critical SQL injection — UNION SELECT data exfiltration confirmed",
        indicators     = ["UNION SELECT username,password", "AND SLEEP(5)"],
        recommendation = "escalate",
        raw_ai_response= "{}",
    )
    state["severity"]          = "critical"
    state["awaiting_approval"] = True
    state["pipeline_status"]   = "awaiting_approval"
    _sessions[session_id]      = state
    return {"injected": True, "session_id": session_id, "awaiting_approval": True}