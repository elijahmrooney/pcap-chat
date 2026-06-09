"""
Ollama provider with NDJSON streaming.

Ollama returns one JSON object per line when stream=true. Each line's
`message.content` is a text delta. The final line has `done=true` and may
include `message.tool_calls` (Ollama does NOT stream tool-call arg deltas;
tool calls only appear in the final done line).

Docs: https://github.com/ollama/ollama/blob/main/docs/api.md
"""
from __future__ import annotations

import json
import logging
import uuid
from typing import Any, Iterator

import httpx

from config import OLLAMA_BASE_URL

from .base import LLMProvider, Message, ProviderError, StreamEvent, ToolCall

logger = logging.getLogger(__name__)


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(self) -> None:
        self.base_url = OLLAMA_BASE_URL.rstrip("/")
        self.timeout = httpx.Timeout(connect=5.0, read=600.0, write=30.0, pool=5.0)

    def default_model(self) -> str:
        return "llama3.1"

    def format_tools(self, catalog: list[Any]) -> list[dict]:
        return [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.input_schema,
                },
            }
            for t in catalog
        ]

    def _messages_to_ollama(self, system: str, messages: list[Message]) -> list[dict]:
        out: list[dict] = [{"role": "system", "content": system}]
        for msg in messages:
            if msg.role == "user":
                out.append({"role": "user", "content": msg.text})
            elif msg.role == "assistant":
                entry: dict = {"role": "assistant", "content": msg.text or ""}
                if msg.tool_calls:
                    entry["tool_calls"] = [
                        {"function": {"name": tc.name, "arguments": tc.input}}
                        for tc in msg.tool_calls
                    ]
                out.append(entry)
            elif msg.role == "tool":
                out.append({"role": "tool", "content": msg.text})
            else:
                raise ProviderError(f"Unknown message role: {msg.role}")
        return out

    def stream_step(
        self,
        system: str,
        messages: list[Message],
        tools: list[dict],
        model: str | None = None,
    ) -> Iterator[StreamEvent]:
        payload = {
            "model": model or self.default_model(),
            "messages": self._messages_to_ollama(system, messages),
            "tools": tools,
            "stream": True,
        }

        final_tool_calls: list[ToolCall] = []
        had_text = False

        try:
            with httpx.Client(timeout=self.timeout) as client:
                with client.stream(
                    "POST",
                    f"{self.base_url}/api/chat",
                    json=payload,
                ) as resp:
                    if resp.status_code != 200:
                        body = resp.read().decode("utf-8", errors="replace")[:500]
                        raise ProviderError(
                            f"Ollama returned HTTP {resp.status_code}. {body}"
                        )
                    for line in resp.iter_lines():
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                        except json.JSONDecodeError:
                            logger.warning("Ollama emitted non-JSON line: %r", line[:200])
                            continue

                        msg = data.get("message", {}) or {}
                        content = msg.get("content", "") or ""
                        if content:
                            had_text = True
                            yield StreamEvent(type="text_delta", text=content)

                        if data.get("done"):
                            raw_calls = msg.get("tool_calls", []) or []
                            for rc in raw_calls:
                                fn = rc.get("function", {}) or {}
                                name = fn.get("name", "")
                                args = fn.get("arguments", {}) or {}
                                if isinstance(args, str):
                                    try:
                                        args = json.loads(args)
                                    except json.JSONDecodeError:
                                        args = {}
                                if not name:
                                    continue
                                final_tool_calls.append(
                                    ToolCall(
                                        id=rc.get("id") or f"ollama_{uuid.uuid4().hex[:12]}",
                                        name=name,
                                        input=args if isinstance(args, dict) else {},
                                    )
                                )
                            break

        except httpx.ConnectError as e:
            raise ProviderError(
                f"Could not connect to Ollama at {self.base_url}. Is Ollama running?"
            ) from e
        except httpx.TimeoutException as e:
            raise ProviderError("Ollama request timed out.") from e

        for tc in final_tool_calls:
            yield StreamEvent(type="tool_call", tool_call=tc)

        yield StreamEvent(
            type="step_end",
            finished=(not final_tool_calls),
        )
