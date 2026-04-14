
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Optional

import google.genai as genai
import google.api_core.exceptions as gex
from dotenv import load_dotenv

from core.state import AgentState, ThreatAnalysis

load_dotenv()

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 1 — Client Setup
# ═════════════════════════════════════════════════════════════════════════════

_client: Optional[genai.Client] = None

MODEL        = "gemini-2.0-flash"   # fast, free tier available, great for classification
MAX_RETRIES  = 3
RETRY_DELAYS = [1, 2, 4]            # exponential backoff in seconds


def _get_client() -> genai.Client:
    """
    Module-level singleton — ek hi baar banta hai.
    GEMINI_API_KEY .env se load hoti hai.
    """
    global _client
    if _client is None:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "GEMINI_API_KEY environment variable nahi mili.\n"
                ".env file mein likho:  GEMINI_API_KEY=AIzaSy-your-key-here\n"
                "Free key yahan milegi: https://aistudio.google.com/app/apikey"
            )
        _client = genai.Client(api_key=api_key)
    return _client


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 2 — Prompts
# ═════════════════════════════════════════════════════════════════════════════

SYSTEM_PROMPT = """You are an expert cybersecurity analyst working in a Security Operations Center (SOC).

Your job is to analyze security events detected from server logs and produce a structured threat assessment.

RULES:
- Always respond with ONLY valid JSON — no markdown, no explanation, no preamble
- Be precise about severity: low/medium/high/critical
- source_ip must be the primary attacker's IP address
- indicators must be concrete strings found in the logs (max 5)
- recommendation must be one of: monitor, alert, block_ip, block_and_alert, escalate
- attack_summary must be 1-2 sentences, plain English

SEVERITY GUIDE:
- critical : active exploitation confirmed, data breach likely, immediate action required
- high     : clear attack pattern, high confidence, auto-block recommended
- medium   : suspicious activity, moderate confidence, needs monitoring
- low      : anomalous but likely benign, log and watch"""


def _build_user_prompt(state: AgentState) -> str:
    """
    Scanner output ko readable prompt mein convert karo.
    AI ko context dete hain: kitne events, kaunsi IPs, kya patterns.
    """
    events = state["parsed_events"]
    stats  = state.get("scanner_stats") or {}

    events_text = json.dumps(
        [
            {
                "event_id":   e["event_id"],
                "type":       e["event_type"],
                "source_ip":  e["source_ip"],
                "target_url": e["target_url"],
                "confidence": e["confidence"],
                "raw_log":    e["raw_line"][:200],
            }
            for e in events
        ],
        indent=2,
    )

    return f"""Analyze these security events detected from our server logs.

SCANNER STATISTICS:
- Total log lines scanned : {stats.get('total_lines', 'unknown')}
- Suspicious events found : {stats.get('suspicious', len(events))}
- Unique attacker IPs     : {stats.get('unique_ips', 'unknown')}
- Scan duration           : {stats.get('duration_ms', 'unknown')} ms

DETECTED EVENTS:
{events_text}

Return ONLY this JSON structure (no markdown, no extra text):
{{
  "threat_type":    "<primary attack category>",
  "severity":       "<low|medium|high|critical>",
  "confidence":     <0.0 to 1.0>,
  "source_ip":      "<primary attacker IP>",
  "attack_summary": "<1-2 sentence plain English summary>",
  "indicators":     ["<indicator1>", "<indicator2>", ...],
  "recommendation": "<monitor|alert|block_ip|block_and_alert|escalate>"
}}"""


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 3 — Gemini API Call with Retry
# ═════════════════════════════════════════════════════════════════════════════

def _call_gemini(prompt: str, retries: int = MAX_RETRIES) -> str:
    """
    Gemini API call karo with retry logic.

    Key feature: response_mime_type="application/json" — Gemini guaranteed
    JSON return karta hai, markdown wrapping nahi hogi.

    Returns: raw JSON string
    Raises:  RuntimeError agar saare retries fail ho jayein
    """
    from google.genai import types

    client     = _get_client()
    last_error = None

    # System + user prompt combine karo (Gemini ka system_instruction)
    config = types.GenerateContentConfig(
        system_instruction = SYSTEM_PROMPT,
        response_mime_type = "application/json",   # force pure JSON output
        temperature        = 0.1,                  # low temp = consistent, deterministic
        max_output_tokens  = 512,
    )

    for attempt in range(retries):
        try:
            response = client.models.generate_content(
                model    = MODEL,
                contents = prompt,
                config   = config,
            )
            return response.text

        except gex.ResourceExhausted:
            # 429 Rate limit — wait and retry
            wait = RETRY_DELAYS[min(attempt, len(RETRY_DELAYS) - 1)]
            time.sleep(wait)
            last_error = "Rate limit (429) — free tier quota exceeded"

        except gex.ServiceUnavailable:
            # 503 — Gemini temporarily down
            wait = RETRY_DELAYS[min(attempt, len(RETRY_DELAYS) - 1)]
            time.sleep(wait)
            last_error = "Service unavailable (503)"

        except gex.InvalidArgument as e:
            # 400 — bad request, retry nahi karega
            raise RuntimeError(f"Gemini invalid request: {e}") from e

        except gex.PermissionDenied as e:
            # 403 — bad API key
            raise RuntimeError(
                f"Gemini permission denied — API key check karo: {e}"
            ) from e

        except Exception as e:
            wait = RETRY_DELAYS[min(attempt, len(RETRY_DELAYS) - 1)]
            time.sleep(wait)
            last_error = str(e)

    raise RuntimeError(
        f"Gemini API {retries} retries ke baad bhi fail. Last error: {last_error}"
    )


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 4 — Response Parser
# ═════════════════════════════════════════════════════════════════════════════

VALID_SEVERITIES      = {"low", "medium", "high", "critical"}
VALID_RECOMMENDATIONS = {"monitor", "alert", "block_ip", "block_and_alert", "escalate"}


def _parse_ai_response(raw_text: str, state: AgentState) -> ThreatAnalysis:
    """
    Gemini ka JSON response parse karke ThreatAnalysis TypedDict banao.

    response_mime_type="application/json" set kiya tha isliye
    clean JSON aayega — lekin defensive parsing still good practice hai.
    """
    # Markdown code blocks hataao (just in case)
    clean = re.sub(r"```(?:json)?\s*|\s*```", "", raw_text).strip()

    try:
        data = json.loads(clean)
    except json.JSONDecodeError:
        json_match = re.search(r'\{.*\}', clean, re.DOTALL)
        if json_match:
            try:
                data = json.loads(json_match.group())
            except json.JSONDecodeError:
                data = {}
        else:
            data = {}

    # ── Validate + sanitize every field ──────────────────────────────────────
    severity = str(data.get("severity", "medium")).lower()
    if severity not in VALID_SEVERITIES:
        severity = "medium"

    recommendation = str(data.get("recommendation", "alert")).lower()
    if recommendation not in VALID_RECOMMENDATIONS:
        recommendation = "alert"

    confidence = float(data.get("confidence", 0.7))
    confidence = max(0.0, min(1.0, confidence))

    source_ip = str(data.get("source_ip", ""))
    if not source_ip and state["parsed_events"]:
        source_ip = state["parsed_events"][0]["source_ip"]

    indicators = data.get("indicators", [])
    if not isinstance(indicators, list):
        indicators = [str(indicators)]
    indicators = [str(i) for i in indicators[:5]]

    return ThreatAnalysis(
        threat_type    = str(data.get("threat_type", "Unknown Threat")),
        severity       = severity,           # type: ignore[arg-type]
        confidence     = round(confidence, 2),
        source_ip      = source_ip,
        attack_summary = str(data.get("attack_summary", "Suspicious activity detected.")),
        indicators     = indicators,
        recommendation = recommendation,     # type: ignore[arg-type]
        raw_ai_response= raw_text,
    )


def _fallback_analysis(state: AgentState, error_msg: str) -> ThreatAnalysis:
    """
    Agar API fail ho — safe fallback.
    Scanner ne jo pakda usse use karte hain, severity high rakhte hain.
    """
    events    = state["parsed_events"]
    source_ip = events[0]["source_ip"] if events else "unknown"
    types     = list({e["event_type"] for e in events})

    return ThreatAnalysis(
        threat_type    = ", ".join(types) if types else "Unknown",
        severity       = "high",
        confidence     = 0.5,
        source_ip      = source_ip,
        attack_summary = f"AI analysis failed ({error_msg}). Manual review required.",
        indicators     = [e["raw_line"][:100] for e in events[:3]],
        recommendation = "escalate",
        raw_ai_response= f"ERROR: {error_msg}",
    )


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 5 — Main Analyzer Agent Function
# ═════════════════════════════════════════════════════════════════════════════

def analyzer_agent(state: AgentState) -> AgentState:
    """
    LangGraph node — Agent B: Analyzer (Gemini).

    Reads:   state["parsed_events"], state["scanner_stats"]
    Writes:  state["threat_analysis"], state["severity"],
             state["pipeline_status"], state["error_message"]
    """
    state["pipeline_status"] = "analyzing"
    events = state.get("parsed_events", [])

    # ── Early exit: koi suspicious events nahi ───────────────────────────────
    if not events:
        state["threat_analysis"] = None
        state["severity"]        = "low"
        state["pipeline_status"] = "analyzing"
        state["completed_at"]    = datetime.now(timezone.utc).isoformat()
        return state

    # ── Build prompt ──────────────────────────────────────────────────────────
    prompt = _build_user_prompt(state)

    # ── Call Gemini ───────────────────────────────────────────────────────────
    try:
        raw_response = _call_gemini(prompt)
        analysis     = _parse_ai_response(raw_response, state)

    except Exception as e:
        error_msg              = str(e)
        state["error_message"] = f"Analyzer error: {error_msg}"
        analysis               = _fallback_analysis(state, error_msg)

    # ── Write to state ────────────────────────────────────────────────────────
    state["threat_analysis"] = analysis
    state["severity"]        = analysis["severity"]

    return state