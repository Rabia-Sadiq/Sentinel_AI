
import ipaddress
import os
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Optional

from core.state import AgentState, ResponderAction


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 1 — Environment Detection
# ═════════════════════════════════════════════════════════════════════════════

def _is_linux() -> bool:
    return platform.system().lower() == "linux"


def _has_iptables() -> bool:
    """iptables available aur executable hai?"""
    if not _is_linux():
        return False
    try:
        result = subprocess.run(
            ["which", "iptables"],
            capture_output=True, text=True, timeout=2
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _is_root() -> bool:
    """Root privileges hain? (iptables ke liye zaruri)"""
    return os.geteuid() == 0 if hasattr(os, "geteuid") else False


def _detect_blocking_method() -> str:
    """
    Best available blocking method detect karo.
    Returns: "iptables" | "simulated"
    """
    if _is_linux() and _has_iptables() and _is_root():
        return "iptables"
    return "simulated"


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 2 — IP Validation
# ═════════════════════════════════════════════════════════════════════════════

# Yeh IPs kabhi block nahi honge — critical infrastructure
PROTECTED_IPS = {
    "127.0.0.1",      # localhost
    "0.0.0.0",        # wildcard
    "255.255.255.255", # broadcast
}

# Private network ranges — production mein carefully handle karo
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
]


def _validate_ip(ip: str) -> tuple[bool, str]:
    """
    IP block karne se pehle validate karo.

    Returns: (is_valid: bool, reason: str)
    """
    if not ip or ip == "unknown":
        return False, "IP address missing ya unknown hai"

    if ip in PROTECTED_IPS:
        return False, f"Protected IP hai — kabhi block nahi hoga: {ip}"

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False, f"Invalid IP format: {ip}"

    if ip_obj.is_loopback:
        return False, f"Loopback IP block nahi hoga: {ip}"

    if ip_obj.is_multicast:
        return False, f"Multicast IP block nahi hoga: {ip}"

    # Private IPs: warning do lekin block allow karo (internal attacker possible)
    for network in PRIVATE_RANGES:
        if ip_obj in network:
            # Private IPs block karo lekin log karo
            return True, f"WARNING: Private IP {ip} — internal network attack possible"

    return True, "OK"


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 3 — Blocking Backends
# ═════════════════════════════════════════════════════════════════════════════

def _block_via_iptables(ip: str) -> tuple[bool, str]:
    """
    Linux iptables se IP block karo.

    Commands run kiye jaate hain:
      1. Check: kya rule already exists?
      2. Block INPUT (incoming traffic)
      3. Block OUTPUT (outgoing connections to attacker)
      4. Save rules (iptables-save)

    Returns: (success: bool, message: str)
    """
    try:
        # Check: kya ye IP pehle se blocked hai?
        check = subprocess.run(
            ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=5
        )
        if check.returncode == 0:
            return True, f"IP {ip} pehle se blocked hai (iptables rule exists)"

        # Block incoming traffic from this IP
        result_in = subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=5
        )
        if result_in.returncode != 0:
            return False, f"iptables INPUT block fail: {result_in.stderr.strip()}"

        # Block outgoing traffic to this IP (prevent reverse shells)
        result_out = subprocess.run(
            ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=5
        )

        # Save rules so they survive reboot
        subprocess.run(
            ["iptables-save"],
            capture_output=True, timeout=5
        )

        direction = "INPUT+OUTPUT" if result_out.returncode == 0 else "INPUT only"
        return True, f"IP {ip} blocked via iptables ({direction})"

    except subprocess.TimeoutExpired:
        return False, f"iptables command timeout hua — IP {ip} block nahi hua"
    except FileNotFoundError:
        return False, "iptables binary nahi mili — PATH check karo"
    except PermissionError:
        return False, "iptables permission denied — root privileges chahiye"


def _block_via_simulation(ip: str, reason: str = "") -> tuple[bool, str]:
    """
    Simulated block — actual iptables nahi chalta.
    Development, Windows, Mac, aur test environments ke liye.

    Log file mein record karta hai taake aap dekh sako kya hota.
    """
    log_path = os.path.join(
        os.path.dirname(__file__), "..", "logs", "simulated_blocks.log"
    )
    log_path = os.path.normpath(log_path)

    timestamp = datetime.now(timezone.utc).isoformat()
    env_info  = f"{platform.system()} / root={_is_root()} / iptables={_has_iptables()}"

    log_entry = (
        f"[{timestamp}] SIMULATED BLOCK | IP: {ip} | "
        f"Env: {env_info} | Note: {reason or 'production mein iptables use hoga'}\n"
    )

    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, "a") as f:
            f.write(log_entry)
    except OSError:
        pass  # Log write fail hona blocking action ko nahi rokna chahiye

    return True, (
        f"[SIMULATED] IP {ip} block record kiya gaya. "
        f"Actual environment: {platform.system()}. "
        f"Production Linux pe yeh iptables se block hoga."
    )


def _execute_block(ip: str) -> tuple[bool, str, str]:
    """
    Best available method se IP block karo.

    Returns: (success: bool, message: str, method: str)
    """
    method = _detect_blocking_method()

    if method == "iptables":
        success, message = _block_via_iptables(ip)
    else:
        note = _build_simulation_note()
        success, message = _block_via_simulation(ip, note)

    return success, message, method


def _build_simulation_note() -> str:
    """Explain karo kyun simulation chal rahi hai."""
    reasons = []
    if not _is_linux():
        reasons.append(f"OS={platform.system()} (Linux nahi)")
    elif not _has_iptables():
        reasons.append("iptables not found")
    elif not _is_root():
        reasons.append("not root (sudo chahiye)")
    return ", ".join(reasons) if reasons else "test mode"


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 4 — Action Decision Matrix
# ═════════════════════════════════════════════════════════════════════════════
#
# severity   | awaiting_approval | action
# ─────────────────────────────────────────────────────────────
# critical   | False             | → pause, request human approval
# critical   | True, approved    | → block + alert
# high       | any               | → auto block + alert
# medium     | any               | → alert only (no block)
# low        | any               | → monitor (log only)
# ─────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _handle_critical(state: AgentState) -> AgentState:
    """
    Critical threat — human approval check karo.

    Agar pehle se approved hai (approved_by set hai) → block karo.
    Warna → awaiting_approval = True set karo aur ruk jao.
    """
    analysis   = state["threat_analysis"]
    target_ip  = analysis["source_ip"]
    approved   = bool(state.get("approved_by"))

    if not approved:
        # Pipeline ruk jaati hai — FastAPI /approve endpoint ka wait
        state["awaiting_approval"]  = True
        state["pipeline_status"]    = "awaiting_approval"
        state["responder_action"]   = ResponderAction(
            action_type  = "pending_approval",
            target_ip    = target_ip,
            method       = "iptables",
            success      = False,
            message      = (
                f"CRITICAL threat detected from {target_ip}. "
                f"Waiting for human approval before blocking. "
                f"POST /approve?session_id={state['session_id']}&approver=<name>"
            ),
            executed_at  = _now_iso(),
        )
        return state

    # Human approved — ab block karo
    return _do_block(state, target_ip, force_alert=True)


def _handle_high(state: AgentState) -> AgentState:
    """High severity → auto block without asking."""
    target_ip = state["threat_analysis"]["source_ip"]
    return _do_block(state, target_ip, force_alert=True)


def _handle_medium(state: AgentState) -> AgentState:
    """Medium severity → alert only, no block."""
    analysis  = state["threat_analysis"]
    target_ip = analysis["source_ip"]

    state["responder_action"] = ResponderAction(
        action_type = "alert_sent",
        target_ip   = target_ip,
        method      = "simulated",
        success     = True,
        message     = (
            f"ALERT: {analysis['threat_type']} detected from {target_ip}. "
            f"Severity: medium. Monitoring in place. "
            f"Summary: {analysis['attack_summary']}"
        ),
        executed_at = _now_iso(),
    )
    state["pipeline_status"] = "responding"
    return state


def _handle_low(state: AgentState) -> AgentState:
    """Low severity → monitor only, no action taken."""
    target_ip = state["threat_analysis"]["source_ip"] if state["threat_analysis"] else "unknown"

    state["responder_action"] = ResponderAction(
        action_type = "skipped",
        target_ip   = target_ip,
        method      = "simulated",
        success     = True,
        message     = f"Low severity — logged for monitoring. No action taken.",
        executed_at = _now_iso(),
    )
    state["pipeline_status"] = "responding"
    return state


def _do_block(state: AgentState, target_ip: str, force_alert: bool = False) -> AgentState:
    """
    Actual blocking logic — IP validate karo, phir block karo.
    Duplicate blocking check karta hai.
    """
    # Duplicate check
    if target_ip in state.get("blocked_ips", []):
        state["responder_action"] = ResponderAction(
            action_type = "ip_blocked",
            target_ip   = target_ip,
            method      = "simulated",
            success     = True,
            message     = f"IP {target_ip} already blocked in this session — skipped",
            executed_at = _now_iso(),
        )
        state["pipeline_status"] = "responding"
        return state

    # Validate IP
    valid, validation_msg = _validate_ip(target_ip)
    if not valid:
        state["responder_action"] = ResponderAction(
            action_type = "skipped",
            target_ip   = target_ip,
            method      = "simulated",
            success     = False,
            message     = f"Block skipped: {validation_msg}",
            executed_at = _now_iso(),
        )
        state["error_message"]   = validation_msg
        state["pipeline_status"] = "responding"
        return state

    # Execute block
    success, message, method = _execute_block(target_ip)

    action_type = "ip_blocked" if success else "escalated"

    if success:
        blocked = list(state.get("blocked_ips", []))
        blocked.append(target_ip)
        state["blocked_ips"] = blocked

    # Append validation warning to message if private IP
    if "WARNING" in validation_msg:
        message = f"{message} | {validation_msg}"

    state["responder_action"]  = ResponderAction(
        action_type = action_type,    # type: ignore[arg-type]
        target_ip   = target_ip,
        method      = method,         # type: ignore[arg-type]
        success     = success,
        message     = message,
        executed_at = _now_iso(),
    )
    state["pipeline_status"]   = "responding"
    state["awaiting_approval"] = False
    return state


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 5 — Main Responder Agent Function
# ═════════════════════════════════════════════════════════════════════════════

def responder_agent(state: AgentState) -> AgentState:
    """
    LangGraph node — Agent C: Responder.

    Reads:   state["severity"], state["threat_analysis"],
             state["awaiting_approval"], state["approved_by"],
             state["blocked_ips"]

    Writes:  state["responder_action"], state["blocked_ips"],
             state["awaiting_approval"], state["pipeline_status"],
             state["completed_at"]

    Routing logic:
        critical (unapproved) → pause + request approval
        critical (approved)   → block + alert
        high                  → auto block + alert
        medium                → alert only
        low / None            → monitor only
    """
    state["pipeline_status"] = "responding"

    severity = state.get("severity") or "low"
    analysis = state.get("threat_analysis")

    # ── No threats found ──────────────────────────────────────────────────────
    if not analysis or not state.get("parsed_events"):
        state["responder_action"] = ResponderAction(
            action_type = "skipped",
            target_ip   = "none",
            method      = "simulated",
            success     = True,
            message     = "No threats detected — system clean",
            executed_at = _now_iso(),
        )
        state["pipeline_status"] = "completed"
        state["completed_at"]    = _now_iso()
        return state

    # ── Route by severity ─────────────────────────────────────────────────────
    if severity == "critical":
        state = _handle_critical(state)
    elif severity == "high":
        state = _handle_high(state)
    elif severity == "medium":
        state = _handle_medium(state)
    else:  # low
        state = _handle_low(state)

    # ── Mark pipeline complete (unless waiting for human) ─────────────────────
    if state["pipeline_status"] != "awaiting_approval":
        state["pipeline_status"] = "completed"
        state["completed_at"]    = _now_iso()

    return state


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 6 — Human Approval Helper (called by FastAPI /approve endpoint)
# ═════════════════════════════════════════════════════════════════════════════

def approve_and_respond(state: AgentState, approver: str) -> AgentState:
    """
    Human approval ke baad pipeline resume karo.

    FastAPI endpoint se call hota hai:
        POST /approve?session_id=xxx&approver=john.doe

    Usage:
        state = load_state_from_redis(session_id)
        state = approve_and_respond(state, approver="john.doe")
        save_state_to_redis(session_id, state)
    """
    if not state.get("awaiting_approval"):
        state["error_message"] = "State awaiting_approval=False hai — approval ki zarurat nahi"
        return state

    state["approved_by"]        = approver
    state["awaiting_approval"]  = False

    # Dobara responder chalao — ab approved hai
    return responder_agent(state)