"""
Anthropic (Claude) provider with streaming.

The streaming API emits content-block events; tool_use blocks have their input
JSON streamed as input_json_delta chunks which we buffer until the block ends.

Docs: https://docs.claude.com/en/api/messages-streaming
"""
from __future__ import annotations

import json
import logging
from typing import Any, Iterator

from config import ANTHROPIC_API_KEY

from .base import LLMProvider, Message, ProviderError, StreamEvent, ToolCall

logger = logging.getLogger(__name__)


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self) -> None:
        if not ANTHROPIC_API_KEY:
            raise ProviderError("ANTHROPIC_API_KEY is not set. Add it to your .env file.")
        try:
            import anthropic  # noqa: F401
        except ImportError as e:
            raise ProviderError("The 'anthropic' package is not installed.") from e
        from anthropic import Anthropic
        self.client = Anthropic(api_key=ANTHROPIC_API_KEY)

    def default_model(self) -> str:
        return "claude-sonnet-4-6"

    def format_tools(self, catalog: list[Any]) -> list[dict]:
        return [
            {"name": t.name, "description": t.description, "input_schema": t.input_schema}
            for t in catalog
        ]

    def _messages_to_anthropic(self, messages: list[Message]) -> list[dict]:
        out: list[dict] = []
        i = 0
        while i < len(messages):
            msg = messages[i]
            if msg.role == "user":
                out.append({"role": "user", "content": msg.text})
                i += 1
            elif msg.role == "assistant":
                blocks: list[dict] = []
                if msg.text:
                    blocks.append({"type": "text", "text": msg.text})
                for tc in msg.tool_calls:
                    blocks.append({
                        "type": "tool_use",
                        "id": tc.id,
                        "name": tc.name,
                        "input": tc.input,
                    })
                out.append({"role": "assistant", "content": blocks})
                i += 1
            elif msg.role == "tool":
                tool_blocks: list[dict] = []
                while i < len(messages) and messages[i].role == "tool":
                    tm = messages[i]
                    tool_blocks.append({
                        "type": "tool_result",
                        "tool_use_id": tm.tool_call_id,
                        "content": tm.text,
                    })
                    i += 1
                out.append({"role": "user", "content": tool_blocks})
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
        from anthropic import APIError, APIStatusError

        anthropic_messages = self._messages_to_anthropic(messages)

        # Per-block state while we iterate.
        current_blocks: dict[int, dict] = {}
        stop_reason: str | None = None

        try:
            with self.client.messages.stream(
                model=model or self.default_model(),
                max_tokens=4096,
                system=system,
                tools=tools,
                messages=anthropic_messages,
            ) as stream:
                for event in stream:
                    etype = getattr(event, "type", "")
                    if etype == "content_block_start":
                        block = event.content_block
                        idx = event.index
                        if block.type == "tool_use":
                            current_blocks[idx] = {
                                "type": "tool_use",
                                "id": block.id,
                                "name": block.name,
                                "input_buffer": "",
                            }
                        elif block.type == "text":
                            current_blocks[idx] = {"type": "text"}
                    elif etype == "content_block_delta":
                        idx = event.index
                        delta = event.delta
                        if delta.type == "text_delta":
                            yield StreamEvent(type="text_delta", text=delta.text)
                        elif delta.type == "input_json_delta":
                            if idx in current_blocks:
                                current_blocks[idx]["input_buffer"] += delta.partial_json
                    elif etype == "content_block_stop":
                        idx = event.index
                        block = current_blocks.pop(idx, None)
                        if block and block.get("type") == "tool_use":
                            raw = block.get("input_buffer", "")
                            try:
                                parsed = json.loads(raw) if raw else {}
                            except json.JSONDecodeError:
                                parsed = {}
                            yield StreamEvent(
                                type="tool_call",
                                tool_call=ToolCall(
                                    id=block["id"],
                                    name=block["name"],
                                    input=parsed if isinstance(parsed, dict) else {},
                                ),
                            )
                    elif etype == "message_delta":
                        sr = getattr(event.delta, "stop_reason", None)
                        if sr:
                            stop_reason = sr
                    elif etype == "message_stop":
                        pass
        except APIStatusError as e:
            logger.warning("Anthropic stream status error: %s", e)
            raise ProviderError(f"Anthropic API error: {e.status_code}") from e
        except APIError as e:
            logger.exception("Anthropic stream error")
            raise ProviderError("Anthropic API call failed.") from e

        yield StreamEvent(
            type="step_end",
            finished=(stop_reason != "tool_use"),
        )
