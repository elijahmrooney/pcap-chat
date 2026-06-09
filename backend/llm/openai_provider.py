"""
OpenAI provider with streaming.

Chat Completions streaming: each chunk has delta.content (text deltas) and
delta.tool_calls (partial tool-call deltas keyed by index).

For tool calls, we buffer per-index:
    - id appears in the first delta for that index
    - name appears in delta.function.name (first delta)
    - arguments stream as delta.function.arguments string deltas

We yield a single `tool_call` StreamEvent per index once we have enough to
parse the arguments JSON, typically when finish_reason arrives.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Iterator

from config import OPENAI_API_KEY

from .base import LLMProvider, Message, ProviderError, StreamEvent, ToolCall

logger = logging.getLogger(__name__)


class OpenAIProvider(LLMProvider):
    name = "openai"

    def __init__(self) -> None:
        if not OPENAI_API_KEY:
            raise ProviderError("OPENAI_API_KEY is not set. Add it to your .env file.")
        try:
            import openai  # noqa: F401
        except ImportError as e:
            raise ProviderError("The 'openai' package is not installed.") from e
        from openai import OpenAI
        self.client = OpenAI(api_key=OPENAI_API_KEY)

    def default_model(self) -> str:
        return "gpt-4o"

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

    def _messages_to_openai(self, system: str, messages: list[Message]) -> list[dict]:
        out: list[dict] = [{"role": "system", "content": system}]
        for msg in messages:
            if msg.role == "user":
                out.append({"role": "user", "content": msg.text})
            elif msg.role == "assistant":
                entry: dict = {"role": "assistant", "content": msg.text or None}
                if msg.tool_calls:
                    entry["tool_calls"] = [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.name,
                                "arguments": json.dumps(tc.input),
                            },
                        }
                        for tc in msg.tool_calls
                    ]
                out.append(entry)
            elif msg.role == "tool":
                out.append({
                    "role": "tool",
                    "tool_call_id": msg.tool_call_id,
                    "content": msg.text,
                })
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
        from openai import APIError, APIStatusError

        # Per-tool-call buffers, keyed by the index OpenAI assigns.
        buffers: dict[int, dict] = {}
        finish_reason: str | None = None

        try:
            stream = self.client.chat.completions.create(
                model=model or self.default_model(),
                messages=self._messages_to_openai(system, messages),
                tools=tools,
                tool_choice="auto",
                max_tokens=4096,
                stream=True,
            )

            for chunk in stream:
                if not chunk.choices:
                    continue
                choice = chunk.choices[0]
                delta = choice.delta

                if getattr(delta, "content", None):
                    yield StreamEvent(type="text_delta", text=delta.content)

                tcs = getattr(delta, "tool_calls", None)
                if tcs:
                    for tcd in tcs:
                        idx = tcd.index
                        buf = buffers.setdefault(idx, {"id": "", "name": "", "args": ""})
                        if tcd.id:
                            buf["id"] = tcd.id
                        fn = getattr(tcd, "function", None)
                        if fn:
                            if fn.name:
                                buf["name"] = fn.name
                            if fn.arguments:
                                buf["args"] += fn.arguments

                if choice.finish_reason:
                    finish_reason = choice.finish_reason

        except APIStatusError as e:
            logger.warning("OpenAI stream status error: %s", e)
            raise ProviderError(f"OpenAI API error: {e.status_code}") from e
        except APIError as e:
            logger.exception("OpenAI stream error")
            raise ProviderError("OpenAI API call failed.") from e

        # Flush all assembled tool calls.
        for idx in sorted(buffers.keys()):
            buf = buffers[idx]
            if not buf["name"]:
                continue
            try:
                args = json.loads(buf["args"]) if buf["args"] else {}
            except json.JSONDecodeError:
                args = {}
            yield StreamEvent(
                type="tool_call",
                tool_call=ToolCall(
                    id=buf["id"] or f"openai_tool_{idx}",
                    name=buf["name"],
                    input=args if isinstance(args, dict) else {},
                ),
            )

        yield StreamEvent(
            type="step_end",
            finished=(finish_reason != "tool_calls" and not buffers),
        )
