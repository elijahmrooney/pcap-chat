"""
Central configuration: limits and environment-derived settings.

Everything tunable lives here so the rest of the codebase imports from one
place. Secrets (API keys) come from the environment / .env and are never
hard-coded.
"""
from __future__ import annotations

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # python-dotenv is optional; env vars may be set by the shell instead.
    pass


# --- Paths ----------------------------------------------------------------

# backend/ directory (this file lives in backend/).
BACKEND_DIR = Path(__file__).resolve().parent

# Uploaded pcaps land here. Created on startup if missing.
UPLOAD_DIR = BACKEND_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# frontend/ directory (served as static files).
FRONTEND_DIR = BACKEND_DIR.parent / "frontend"


# --- Hard limits ----------------------------------------------------------

MAX_UPLOAD_BYTES = 500 * 1024 * 1024            # 500 MB
TSHARK_TIMEOUT_SECONDS = 30
TSHARK_MAX_OUTPUT_BYTES = 10 * 1024 * 1024      # 10 MB
TOOL_RESULT_MAX_ROWS = 200
MAX_FILTER_LENGTH = 1000
MAX_AGENT_TURNS = 12
SESSION_TTL_SECONDS = 4 * 60 * 60               # 4 hours


# --- Provider settings ----------------------------------------------------

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")


# --- Server ---------------------------------------------------------------

HOST = os.getenv("PCAP_CHAT_HOST", "127.0.0.1")
PORT = int(os.getenv("PCAP_CHAT_PORT", "8000"))
