

from typing import Literal

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from agents.analyzer import analyzer_agent
from agents.responder import responder_agent
from agents.scanner import scanner_agent
from core.state import AgentState


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 1 — Human Review Node
# ═════════════════════════════════════════════════════════════════════════════

def human_review_node(state: AgentState) -> AgentState:
    """
    LangGraph node — human approval checkpoint.

    Yeh node khud kuch nahi karta — sirf state ko pass-through karta hai.
    Actual "pause" interrupt_before=["human_review_node"] se aata hai
    jo graph.compile() mein set hota hai.

    Flow:
      1. Graph yahan RUKTA hai (interrupt fires)
      2. state["awaiting_approval"] = True already set hai (responder ne kiya)
      3. FastAPI /approve endpoint state update karta hai:
             state["approved_by"] = "approver_name"
             state["awaiting_approval"] = False
      4. graph.invoke() dobara call hoti hai same thread_id se
      5. Yeh node complete hota hai aur [responder] pe jaata hai
    """
    # State pass-through — interrupt_before ne pause kiya tha,
    # ab resume ho rahi hai yaani approval mil gayi
    state["awaiting_approval"] = False
    state["pipeline_status"]   = "responding"
    return state


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 2 — Conditional Routing Functions
# ═════════════════════════════════════════════════════════════════════════════

def route_after_analysis(
    state: AgentState,
) -> Literal["responder", "human_review_node", "__end__"]:
    """
    Analyzer ke baad kahan jaana hai decide karo.

    severity == "low"      → END (koi action nahi chahiye)
    severity == "medium"   → responder (alert bhejo)
    severity == "high"     → responder (auto block)
    severity == "critical" → human_review_node (pause + approval)
    None / unknown         → END (safe default)
    """
    severity = state.get("severity") or "low"

    if severity == "critical":
        return "human_review_node"
    elif severity in ("high", "medium"):
        return "responder"
    else:
        # low ya None — pipeline yahan khatam
        return END


def route_after_human_review(
    state: AgentState,
) -> Literal["responder", "__end__"]:
    """
    Human review node ke baad kahan jaana hai.

    Agar approved_by set hai → responder ko jao (block karo)
    Agar nahi (edge case)    → END safely
    """
    if state.get("approved_by"):
        return "responder"
    return END


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 3 — Graph Builder
# ═════════════════════════════════════════════════════════════════════════════

def _build_base_graph() -> StateGraph:
    """
    Saare nodes aur edges add karo — checkpointer ke baghair.
    build_graph() aur build_graph_with_memory() dono isko use karte hain.
    """
    graph = StateGraph(AgentState)

    # ── Nodes ─────────────────────────────────────────────────────────────────
    graph.add_node("scanner",           scanner_agent)
    graph.add_node("analyzer",          analyzer_agent)
    graph.add_node("human_review_node", human_review_node)
    graph.add_node("responder",         responder_agent)

    # ── Entry point ───────────────────────────────────────────────────────────
    graph.add_edge(START, "scanner")

    # ── scanner → analyzer (always) ───────────────────────────────────────────
    graph.add_edge("scanner", "analyzer")

    # ── analyzer → conditional fork ───────────────────────────────────────────
    graph.add_conditional_edges(
        source   = "analyzer",
        path     = route_after_analysis,
        path_map = {
            "responder":         "responder",
            "human_review_node": "human_review_node",
            END:                 END,
        },
    )

    # ── human_review_node → conditional fork (approved or not) ────────────────
    graph.add_conditional_edges(
        source   = "human_review_node",
        path     = route_after_human_review,
        path_map = {
            "responder": "responder",
            END:         END,
        },
    )

    # ── responder → END (always) ──────────────────────────────────────────────
    graph.add_edge("responder", END)

    return graph


def build_graph():
    """
    Stateless compiled graph — no checkpointing.

    Use karo jab:
      - Sirf low/medium/high threats hain
      - Human approval ki zarurat nahi
      - Testing aur development mein

    Usage:
        graph = build_graph()
        result = graph.invoke(initial_state)
    """
    return _build_base_graph().compile()


def build_graph_with_memory():
    """
    Stateful compiled graph — MemorySaver checkpointer ke saath.

    HITL (Human-in-the-loop) ke liye REQUIRED.
    interrupt_before=["human_review_node"] critical threats pe pipeline pause karta hai.
    graph.invoke() dobara same thread_id se call karo resume ke liye.

    Usage:
        graph = build_graph_with_memory()

        # First invocation — critical threat pe pause hoga
        config = {"configurable": {"thread_id": session_id}}
        result = graph.invoke(initial_state, config=config)

        # ... FastAPI /approve endpoint state update karta hai ...

        # Resume — approval ke baad
        resume_state = {**result, "approved_by": "john.doe", "awaiting_approval": False}
        final = graph.invoke(resume_state, config=config)
    """
    checkpointer = MemorySaver()
    return _build_base_graph().compile(
        checkpointer     = checkpointer,
        interrupt_before = ["human_review_node"],
    )


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 4 — Graph Visualization Helper
# ═════════════════════════════════════════════════════════════════════════════

def print_graph_structure(use_memory: bool = False) -> None:
    """
    Terminal mein graph structure print karo — debugging ke liye.
    """
    graph = build_graph_with_memory() if use_memory else build_graph()

    print("ASOC LangGraph Structure")
    print("=" * 50)
    try:
        # LangGraph ASCII diagram
        print(graph.get_graph().draw_ascii())
    except Exception:
        # Fallback: manually print nodes and edges
        g = graph.get_graph()
        print("\nNodes:")
        for node in g.nodes:
            print(f"  [{node}]")
        print("\nEdges:")
        for edge in g.edges:
            print(f"  {edge[0]} ──► {edge[1]}")
    print("=" * 50)
    if use_memory:
        print("interrupt_before: [human_review_node]")
        print("checkpointer: MemorySaver")