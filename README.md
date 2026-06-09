# pcap-chat

Browser-based packet capture analysis driven by natural-language questions. Upload a `.pcap` / `.pcapng`, ask questions in plain English, watch the LLM use `tshark` tools to investigate, and see results live in a Wireshark-style packet table and dissection pane.

The LLM never sees the raw pcap. It works through a sandboxed tool catalog: display filters, conversation/endpoint stats, protocol hierarchies, DNS/HTTP listings, packet dissections, and stream follows.

## Features

- **Streaming responses.** Text streams token-by-token while tool calls execute mid-thought.
- **Tool trace.** See every `tshark` invocation, its arguments, and its output as the agent investigates.
- **Wireshark-style packet table.** When the agent runs a filter, results render as a clickable, sortable column table.
- **Packet detail tree.** Click any frame (in the table, or via a frame reference in the chat) to see the full multi-layer dissection with expand/collapse.
- **Clickable frame references.** Mentions like *"frame 5024"* in assistant replies become clickable — they jump to that packet's dissection.
- **Three LLM backends.** Anthropic Claude, OpenAI GPT, or local Ollama (for air-gapped analysis).

## Quick start

### Requirements
- Python 3.10+
- `tshark` on `$PATH` (install Wireshark)
- An API key for Anthropic or OpenAI, **or** Ollama running locally

### Install
```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env: add ANTHROPIC_API_KEY and/or OPENAI_API_KEY
```

### Run
```bash
uvicorn app:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>. Drop a pcap and start asking questions.

## Architecture

```
┌─ frontend (vanilla JS) ────────────────────────┐
│  • SSE consumer for streaming chat              │
│  • packet table + detail tree                   │
│  • clickable frame references                   │
└─────────────────────────────────────────────────┘
              │  POST /api/chat-stream (SSE)
              │  GET  /api/packet/{sid}/{n}
              ▼
┌─ FastAPI ──────────────────────────────────────┐
│  app.py          — routes, SSE wrapping         │
│  agent/loop.py   — StreamingAgent generator     │
│  agent/prompts.py— system prompt                │
│  llm/*.py        — Anthropic/OpenAI/Ollama      │
│  pcap/tools.py   — tool catalog & dispatch      │
│  pcap/tshark.py  — safe subprocess wrappers     │
│  pcap/parsers.py — pipe-row + dissection tree   │
│  pcap/loader.py  — upload validation            │
│  sessions.py     — in-memory session store     │
│  config.py       — limits & env config          │
└─────────────────────────────────────────────────┘
              │  shell=False, validated args
              ▼
            tshark
```

### Streaming flow

1. Browser POSTs to `/api/chat-stream` with `{session_id, message, provider, model?}`.
2. Backend opens a `StreamingResponse` of `text/event-stream`.
3. The agent loop yields events:
   - `text` — chunk of assistant text
   - `tool_start` — about to run a tool (id, name, input)
   - `tool_end` — tool completed (id, success, text preview, optional `table`, optional `detail`)
   - `turn_end` — model finished a turn (more may follow if tools were called)
   - `done` / `truncated` / `error`
4. When `tool_end` carries a `table`, the frontend renders the packet table.
5. When `tool_end` carries a `detail`, the frontend renders the dissection tree.
6. The frontend wraps "frame N" references in clickable spans; clicking them calls `/api/packet/{sid}/{n}` and re-renders the detail pane.

## Security

This is a *local-first analysis tool*. By default it binds to `127.0.0.1`. Pcaps often contain credentials, PII, and other sensitive data; do **not** expose this service to a network without adding auth, TLS, and rate limiting.

### Guarantees built in
- **No shell injection.** `tshark` is invoked with argument lists, never via shell. Filters and filenames pass through validation before any subprocess call.
- **No path traversal.** Uploaded pcap paths are constrained to `UPLOAD_DIR` and re-validated on every tool call.
- **Magic-byte upload check.** Files must start with a pcap or pcapng magic number; the original filename is discarded in favor of a server-generated UUID.
- **Hard limits.** Upload size (500 MB), tshark wall-clock (30s), tshark output bytes (10 MB), filter length (1000 chars), tool result rows (200), agent turns per question (12), session TTL (4h).
- **API keys stay server-side.** They live in `.env` and are never sent to the browser.
- **Filter syntax errors only.** `tshark` stderr is surfaced to the LLM only when it indicates a recoverable filter error (so the LLM can self-correct). All other errors are logged server-side and returned as generic messages.
- **Sessions clean up.** On session close, the uploaded pcap is deleted. A background task evicts expired sessions every minute.

### What's NOT included
- Multi-user auth — anyone who can reach the port can use any session.
- HTTPS — terminate TLS in front of uvicorn if you expose this.
- Output sanitization for binary content in `follow_stream` — be mindful with adversarial pcaps.

## Tool catalog

The LLM calls these as needed. Each one is described in detail to the model at the start of every turn.

| Tool | Returns |
|---|---|
| `run_display_filter` | Rows matching a Wireshark display filter |
| `get_protocol_hierarchy` | Protocol/byte breakdown |
| `get_conversations` | Top endpoint pairs by traffic |
| `get_endpoints` | Top endpoints by traffic |
| `list_dns_queries` | DNS queries with A/AAAA answers |
| `list_http_requests` | HTTP request method/host/URI/UA |
| `get_packet_detail` | Full dissection of one frame |
| `follow_stream` | Reassembled TCP/UDP/HTTP/TLS stream |

## File layout

```
pcap-chat/
├── README.md
├── backend/
│   ├── .env.example
│   ├── requirements.txt
│   ├── app.py              # FastAPI app + SSE endpoint
│   ├── config.py           # env vars + limits
│   ├── sessions.py         # in-memory session store
│   ├── agent/
│   │   ├── loop.py         # StreamingAgent
│   │   └── prompts.py      # system prompt
│   ├── llm/
│   │   ├── base.py         # provider interface + StreamEvent
│   │   ├── anthropic_provider.py
│   │   ├── openai_provider.py
│   │   └── ollama_provider.py
│   └── pcap/
│       ├── parsers.py      # pipe-row + dissection tree parsers
│       ├── tshark.py       # safe subprocess wrappers
│       ├── tools.py        # tool catalog & dispatch
│       └── loader.py       # upload validation
└── frontend/
    ├── index.html
    ├── style.css
    └── app.js
```

## Configuration

All limits and provider settings live in `backend/config.py` or `backend/.env`:

```
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
OLLAMA_BASE_URL=http://127.0.0.1:11434
```

The model defaults are `claude-sonnet-4-6` (Anthropic), `gpt-4o` (OpenAI), and `llama3.1` (Ollama). Override per-request in the UI's model field, or change the defaults in each provider file.

## Roadmap

Things this version does NOT do but are good next steps:

- Multi-user / auth
- Persistent session storage (currently in-memory)
- Column sort / search in the packet table
- Saved investigations (export chat + tool trace + selected packet)
- Stream-as-it-happens for `follow_stream` (currently buffered)
- Mobile layout polish
- Per-session pcap encryption-at-rest
