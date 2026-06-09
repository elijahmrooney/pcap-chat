"""
FastAPI application: routes, SSE streaming endpoint, upload, session, health.

Endpoints
---------
GET  /                              -> frontend index.html
GET  /static/*                      -> frontend static assets
POST /api/upload                    -> validate + store pcap, create session
POST /api/chat-stream               -> SSE stream of agent events
GET  /api/packet/{sid}/{n}          -> dissection tree for one frame (no LLM)
POST /api/session/{sid}/close       -> close a session, delete its pcap
GET  /api/health                    -> liveness

Binds to 127.0.0.1 by default (see config.HOST). Pcaps contain sensitive
data — do not expose this service publicly without adding auth + TLS.
"""
from __future__ import annotations

import json
import logging

from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from agent.loop import StreamingAgent, get_provider
from agent.prompts import build_seed_summary
from config import FRONTEND_DIR, HOST, PORT
from llm.base import Message, ProviderError
from pcap import loader, tshark
from sessions import start_cleanup_thread, store

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="pcap-chat")


@app.on_event("startup")
def _on_startup() -> None:
    start_cleanup_thread(interval_seconds=60)
    logger.info("pcap-chat started; session cleanup running.")


# --- Static frontend ------------------------------------------------------

app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(str(FRONTEND_DIR / "index.html"))


# --- Health ---------------------------------------------------------------

@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


# --- Upload ---------------------------------------------------------------

@app.post("/api/upload")
async def upload(file: UploadFile) -> JSONResponse:
    data = await file.read()
    try:
        stored_path, display_name = loader.save_upload(data, file.filename or "capture.pcap")
    except loader.UploadError as e:
        raise HTTPException(status_code=400, detail=str(e))

    session = store.create(stored_path, display_name)
    return JSONResponse(
        {
            "session_id": session.id,
            "filename": display_name,
        }
    )


# --- Packet detail (no LLM) ----------------------------------------------

@app.get("/api/packet/{sid}/{packet_number}")
def packet_detail(sid: str, packet_number: int) -> JSONResponse:
    session = store.get(sid)
    if session is None:
        raise HTTPException(status_code=404, detail="Unknown or expired session.")
    try:
        result = tshark.get_packet_detail(session.pcap_path, packet_number)
    except tshark.TsharkError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return JSONResponse(
        {
            "packet_number": result.packet_number,
            "tree": result.tree,
            "text": result.text,
        }
    )


# --- Session close --------------------------------------------------------

@app.post("/api/session/{sid}/close")
def close_session(sid: str) -> JSONResponse:
    found = store.close(sid)
    if not found:
        raise HTTPException(status_code=404, detail="Unknown session.")
    return JSONResponse({"closed": True})


# --- Chat stream (SSE) ----------------------------------------------------

def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _seed_history_if_needed(session) -> None:
    """On the first turn, prepend an automatic capture summary as context."""
    if session.history:
        return
    try:
        summary = tshark.capture_summary(session.pcap_path)
        blurb = build_seed_summary(
            summary.get("protocol_hierarchy", ""),
            summary.get("top_ip_conversations", ""),
            summary.get("first_packet_epoch", ""),
        )
        session.history.append(Message(role="user", text=blurb))
        session.history.append(
            Message(role="assistant", text="Capture summary noted. Ready for your questions.")
        )
    except tshark.TsharkError:
        logger.warning("Could not build seed summary for session %s", session.id)


@app.post("/api/chat-stream")
async def chat_stream(request: Request) -> StreamingResponse:
    body = await request.json()
    sid = body.get("session_id", "")
    message = body.get("message", "")
    provider_name = body.get("provider", "anthropic")
    model = body.get("model") or None

    session = store.get(sid)
    if session is None:
        raise HTTPException(status_code=404, detail="Unknown or expired session.")
    if not isinstance(message, str) or not message.strip():
        raise HTTPException(status_code=400, detail="Message must be non-empty text.")

    try:
        provider = get_provider(provider_name)
    except ProviderError as e:
        raise HTTPException(status_code=400, detail=str(e))

    _seed_history_if_needed(session)

    agent = StreamingAgent(
        provider=provider,
        pcap_path=session.pcap_path,
        history=session.history,
        user_message=message,
        model=model,
    )

    def event_generator():
        try:
            for evt in agent.run():
                yield _sse(evt["event"], evt.get("data", {}))
        except Exception:
            logger.exception("Agent stream crashed")
            yield _sse("error", {"message": "The analysis stream failed unexpectedly."})
        finally:
            # Persist this turn's messages into session history.
            session.history.extend(agent.new_messages)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=HOST, port=PORT)
