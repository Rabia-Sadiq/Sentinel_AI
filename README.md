# 🛡️ Sentinel AI — Autonomous Security Operations Center

> A multi-agent AI system that automatically detects, analyzes, and responds to cybersecurity threats in real time — with Human-in-the-Loop control for critical decisions.

---

## 📌 Overview

**Sentinel AI** is an intelligent, automated Security Operations Center (SOC) built with a three-agent pipeline. It reads raw server logs, identifies attack patterns using regex-based detection, classifies threats using Google Gemini AI, and takes automated action — including blocking attacker IPs — all without human intervention, unless the threat is critical.

This project demonstrates practical use of **multi-agent AI architecture**, **LangGraph pipelines**, **FastAPI**, and **Human-in-the-Loop (HITL)** design patterns in a real-world cybersecurity context.

---

## ✨ Key Features

- **Multi-Agent Pipeline** — Three specialized AI agents working in sequence: Scanner → Analyzer → Responder
- **Threat Detection** — Detects SQL Injection, XSS, Brute Force (SSH + HTTP), Path Traversal, and Port Scanning
- **AI-Powered Analysis** — Uses Google Gemini (`gemini-2.0-flash`) to classify severity and recommend action
- **Automated Response** — Automatically blocks malicious IPs via `iptables` on Linux (simulated on Windows/Mac)
- **Human-in-the-Loop** — Critical threats pause the pipeline and require human approval before action is taken
- **REST API** — Full FastAPI server with endpoints for log submission, status checking, and approval
- **Zero False Positives** — Tested against normal traffic with no false alerts
- **12/12 Tests Passing** — Complete test suite covering all attack types and edge cases

---

## 🏗️ System Architecture

```
Raw Server Logs (Apache / Nginx / SSH)
              │
              ▼
    ┌─────────────────┐
    │   Agent A       │  ← scanner.py
    │   SCANNER       │  Regex pattern matching
    │                 │  Frequency-based brute force detection
    └────────┬────────┘
             │  ParsedEvent list
             ▼
    ┌─────────────────┐
    │   Agent B       │  ← analyzer.py
    │   ANALYZER      │  Google Gemini AI
    │                 │  Threat classification + severity scoring
    └────────┬────────┘
             │  ThreatAnalysis (severity: low/medium/high/critical)
             ▼
    ┌─────────────────────────────────────────────┐
    │              ROUTING (LangGraph)            │
    │  low      → END (log only)                  │
    │  medium   → Alert sent                      │
    │  high     → Auto IP block                   │
    │  critical → Human approval required ──┐     │
    └───────────────────────────────────────┼─────┘
                                            │
                               POST /approve (Human decision)
                                            │
                                            ▼
    ┌─────────────────┐
    │   Agent C       │  ← responder.py
    │   RESPONDER     │  iptables IP blocking
    │                 │  Alert generation
    └─────────────────┘
```

---

## 🔍 Threat Detection Capabilities

| Threat Type | Detection Method | Confidence |
|-------------|-----------------|------------|
| SQL Injection | Regex: `UNION SELECT`, `DROP TABLE`, `OR 1=1`, `SLEEP()` | 75–95% |
| XSS Attempts | Regex: `<script>`, `javascript:`, `onerror=` | 80–85% |
| Path Traversal | Regex: `../`, `/etc/passwd`, `/windows/system32` | 90% |
| SSH Brute Force | Pattern + frequency (5+ failures per IP) | 85–98% |
| HTTP Brute Force | POST to `/login` frequency (10+ per IP) | 65–99% |
| Port Scanning | Known scanner User-Agents: `nmap`, `sqlmap`, `nikto` | 95% |

---

## 🤖 Agent Details

### Agent A — Scanner (`agents/scanner.py`)
Reads raw log lines (Apache, Nginx, SSH format) and applies regex pattern matching to detect suspicious activity. Also performs frequency-based brute force detection by counting per-IP failure rates across the entire log batch. Outputs structured `ParsedEvent` objects with confidence scores.

### Agent B — Analyzer (`agents/analyzer.py`)
Takes the list of parsed events and sends them to Google Gemini AI with a detailed system prompt instructing it to act as a SOC analyst. Returns a structured `ThreatAnalysis` with severity level, recommended action, attack summary, and key indicators. Includes retry logic with exponential backoff (1s → 2s → 4s) for API resilience.

### Agent C — Responder (`agents/responder.py`)
Reads the severity level and executes the appropriate response:
- **critical** → Pauses pipeline, requests human approval via `/approve` endpoint
- **high** → Automatically blocks the attacker's IP
- **medium** → Sends an alert for the security team
- **low** → Logs the event, no action taken

IP blocking uses Linux `iptables` in production environments. On Windows/Mac (development), it logs a simulated block to file.

---

## 🗂️ Project Structure

```
Sentinel_AI/
├── asoc/
│   ├── agents/
│   │   ├── scanner.py        # Agent A: Log parsing + threat detection
│   │   ├── analyzer.py       # Agent B: Gemini AI threat classification
│   │   └── responder.py      # Agent C: IP blocking + alerting
│   ├── core/
│   │   ├── state.py          # Shared AgentState TypedDict
│   │   ├── graph.py          # LangGraph pipeline definition
│   │   └── redis_client.py   # (Planned: Redis session persistence)
│   ├── logs/
│   │   ├── sample.log
│   │   └── simulated_blocks.log
│   ├── tests/
│   │   ├── test_pipeline.py  # Full end-to-end test suite (12 tests)
│   │   ├── test_scanner.py
│   │   └── test_analyzer.py
│   ├── main.py               # FastAPI server
│   ├── .env.example          # Environment variable template
│   └── requirements.txt
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.11+
- A free Google Gemini API key from [aistudio.google.com](https://aistudio.google.com/app/apikey)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/Sentinel_AI.git
cd Sentinel_AI/asoc

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set up environment variables
cp .env.example .env
# Edit .env and add your Gemini API key:
# GEMINI_API_KEY=AIzaSy-your-key-here

# 5. Start the server
uvicorn main:app --reload
```

Server will be running at: `http://localhost:8000`

Interactive API docs: `http://localhost:8000/docs`

---

## 📡 API Endpoints

### `POST /analyze`
Submit server logs for threat analysis. The full pipeline runs automatically.

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "logs": [
      "10.13.37.5 - - [12/Apr/2025] \"GET /users?q=1 UNION SELECT username,password FROM users-- HTTP/1.1\" 500 64",
      "10.13.37.5 - - [12/Apr/2025] \"GET /api/data?id=1 AND SLEEP(5)-- HTTP/1.1\" 200 16"
    ]
  }'
```

**Response:**
```json
{
  "session_id": "sess_a1b2c3d4e5",
  "pipeline_status": "completed",
  "severity": "high",
  "action_taken": "[SIMULATED] IP 10.13.37.5 block record kiya gaya.",
  "threat_summary": "Attacker attempted SQL injection with UNION SELECT data exfiltration.",
  "blocked_ips": ["10.13.37.5"],
  "awaiting_approval": false
}
```

---

### `GET /status/{session_id}`
Retrieve the full pipeline state for a session.

```bash
curl http://localhost:8000/status/sess_a1b2c3d4e5
```

---

### `POST /approve`
Approve a critical threat response (Human-in-the-Loop).

```bash
curl -X POST http://localhost:8000/approve \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "sess_a1b2c3d4e5",
    "approver": "sarah.ali@company.com"
  }'
```

---

### `GET /blocked-ips/{session_id}`
List all IPs blocked in a session.

```bash
curl http://localhost:8000/blocked-ips/sess_a1b2c3d4e5
```

---

### `GET /health`
Server health check.

```bash
curl http://localhost:8000/health
# {"status": "ok", "time": "2026-04-14T09:48:48"}
```

---

## 🧪 Running Tests

```bash
# Run all 12 tests (in-process, no server needed)
python tests/test_pipeline.py

# Run against a live server
python tests/test_pipeline.py --live --url http://localhost:8000
```

### Test Results

```
Test Summary
┌────┬──────────────────────────────────────────────────────┬────────┐
│ #  │ Test                                                 │ Result │
├────┼──────────────────────────────────────────────────────┼────────┤
│  1 │ Health check                                         │  PASS  │
│  2 │ SQL Injection — detection + pipeline                 │  PASS  │
│  3 │ SSH Brute Force — frequency detection                │  PASS  │
│  4 │ Normal traffic — zero false positives                │  PASS  │
│  5 │ Mixed attack — SQL + XSS + Path + Brute Force + Scan │  PASS  │
│  6 │ Path Traversal — /etc/passwd, system32               │  PASS  │
│  7 │ XSS Attempts — script tags + event handlers          │  PASS  │
│  8 │ Empty logs — graceful no-op                          │  PASS  │
│  9 │ /status — full state retrieval                       │  PASS  │
│ 10 │ /blocked-ips — IP list endpoint                      │  PASS  │
│ 11 │ HITL — critical pause → /approve → resume            │  PASS  │
│ 12 │ 404 on unknown session_id — error handling           │  PASS  │
└────┴──────────────────────────────────────────────────────┴────────┘

12/12 — All tests passed!
```

---

## 🔄 Human-in-the-Loop (HITL) Flow

When a **critical** severity threat is detected, the pipeline pauses and waits for human approval before taking any destructive action (IP blocking).

```
1. POST /analyze  →  Critical SQL injection detected
                  →  pipeline_status: "awaiting_approval"
                  →  awaiting_approval: true

2. Security team reviews threat details via GET /status/{id}

3. POST /approve  →  {"approver": "john.doe@company.com"}
                  →  Pipeline resumes
                  →  IP blocked
                  →  pipeline_status: "completed"
```

This ensures no automated system can block IPs without human oversight for the most serious threats.

---

## 🛠️ Tech Stack

| Technology | Purpose |
|------------|---------|
| **Python 3.11** | Core language |
| **FastAPI** | REST API server |
| **LangGraph** | Multi-agent pipeline orchestration |
| **Google Gemini AI** (`gemini-2.0-flash`) | Threat classification and analysis |
| **google-genai SDK** | Gemini API client |
| **iptables** | Linux IP blocking (production) |
| **Rich** | Beautiful terminal test output |
| **httpx** | HTTP client for live testing |
| **python-dotenv** | Environment variable management |

---

## 🔐 Security Notes

- The `.env` file containing your API key is **never committed to Git** (protected by `.gitignore`)
- The `/debug/inject-critical` endpoint should be **removed in production**
- IP blocking validates against a protected list — `localhost` and critical infrastructure IPs are never blocked
- Private network IPs are blocked but flagged with a warning (internal attacker possible)

---

## 📈 Future Improvements

- **Redis Integration** — Replace in-memory `_sessions` dict with Redis for persistence across server restarts
- **Authentication** — Add API key or JWT auth to all endpoints
- **Dashboard UI** — Real-time threat monitoring frontend
- **Email/Slack Alerts** — Notify security team on medium+ severity threats
- **Rate Limiting** — Prevent API abuse
- **Cloud Firewall Integration** — AWS Security Groups / GCP Firewall Rules as blocking backend

---

## 📄 License

This project is for educational and portfolio purposes.
