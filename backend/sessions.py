"""
In-memory session store.

A session ties a browser to one uploaded pcap and its conversation history.
Sessions are keyed by a server-generated UUID and expire after SESSION_TTL.
A background task evicts expired sessions and deletes their pcap files.

This store is process-local and not persisted — restarting the server drops
all sessions. That is intentional for a local-first analysis tool.
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from config import SESSION_TTL_SECONDS
from llm.base import Message

logger = logging.getLogger(__name__)


@dataclass
class Session:
    id: str
    pcap_path: Path
    filename: str
    created_at: float
    last_active: float
    history: list[Message] = field(default_factory=list)

    def touch(self) -> None:
        self.last_active = time.time()

    def is_expired(self, now: float, ttl: int) -> bool:
        return (now - self.last_active) > ttl


class SessionStore:
    """Thread-safe in-memory session registry."""

    def __init__(self, ttl: int = SESSION_TTL_SECONDS) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()
        self._ttl = ttl

    def create(self, pcap_path: Path, filename: str) -> Session:
        sid = uuid.uuid4().hex
        now = time.time()
        session = Session(
            id=sid,
            pcap_path=pcap_path,
            filename=filename,
            created_at=now,
            last_active=now,
        )
        with self._lock:
            self._sessions[sid] = session
        logger.info("Created session %s for %s", sid, filename)
        return session

    def get(self, sid: str) -> Session | None:
        with self._lock:
            session = self._sessions.get(sid)
            if session is not None:
                session.touch()
            return session

    def close(self, sid: str) -> bool:
        """Remove a session and delete its pcap file. Returns True if found."""
        with self._lock:
            session = self._sessions.pop(sid, None)
        if session is None:
            return False
        self._delete_pcap(session)
        logger.info("Closed session %s", sid)
        return True

    def evict_expired(self) -> int:
        """Remove all expired sessions. Returns the number evicted."""
        now = time.time()
        expired: list[Session] = []
        with self._lock:
            for sid in list(self._sessions.keys()):
                session = self._sessions[sid]
                if session.is_expired(now, self._ttl):
                    expired.append(self._sessions.pop(sid))
        for session in expired:
            self._delete_pcap(session)
            logger.info("Evicted expired session %s", session.id)
        return len(expired)

    @staticmethod
    def _delete_pcap(session: Session) -> None:
        try:
            if session.pcap_path.is_file():
                session.pcap_path.unlink()
        except OSError:
            logger.warning("Failed to delete pcap for session %s", session.id)


# Module-level singleton.
store = SessionStore()


def start_cleanup_thread(interval_seconds: int = 60) -> threading.Thread:
    """Spawn a daemon thread that evicts expired sessions periodically."""

    def _loop() -> None:
        while True:
            time.sleep(interval_seconds)
            try:
                store.evict_expired()
            except Exception:
                logger.exception("Session cleanup pass failed")

    thread = threading.Thread(target=_loop, daemon=True, name="session-cleanup")
    thread.start()
    return thread
