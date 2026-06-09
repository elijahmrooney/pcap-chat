"""
Streaming agent loop.

Driven as a generator: yields dicts of the shape {"event": str, "data": dict}.
The HTTP layer turns these into Server-Sent Events.

The loop also accumulates `new_messages` — the canonical Messages produced
during this user turn, to be appended to session history after streaming
completes.

Event types yielded:
    text         — a chunk of assistant text. data={"chunk": str}
    tool_start   — a tool call is about to execute.
                   data={"id", "name", "input"}
    tool_end     — tool completed.
                   data={"id", "success", "text", "table"|null, "detail"|null}
    turn_end     — model finished a turn (may be followed by another).
    truncated    — agent loop hit MAX_AGENT_TURNS without final answer.
    done         — everything finished cleanly.
    error        — something failed; data={"message": str}
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterator

from config import MAX_AGENT_TURNS
from llm.base import LLMProvider, Message, ProviderError
from pcap import tools as tool_catalog

from .prompts import SYSTEM_PROMPT

logger = logging.getLogger(__name__)


def _preview(text: str, max_len: int = 1500) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"\n... [{len(text) - max_len} more characters]"


class StreamingAgent:
    """Runs one user-message-to-final-answer cycle as a stream of events."""

    def __init__(
        self,
        provider: LLMProvider,
        pcap_path: Path,
        history: list[Message],
        user_message: str,
        model: str | None = None,
    ) -> None:
        self.provider = provider
        self.pcap_path = pcap_path
        self.history = history
        self.user_message = user_message
        self.model = model
        self.new_messages: list[Message] = []

    def run(self) -> Iterator[dict]:
        # Working set: prior history plus the new user message.
        working = list(self.history)
        new_user = Message(role="user", text=self.user_message)
        working.append(new_user)
        self.new_messages.append(new_user)

        tools_for_provider = self.provider.format_tools(tool_catalog.TOOLS)

        for turn in range(MAX_AGENT_TURNS):
            current_text = ""
            current_tool_calls = []

            try:
                for event in self.provider.stream_step(
                    system=SYSTEM_PROMPT,
                    messages=working,
                    tools=tools_for_provider,
                    model=self.model,
                ):
                    if event.type == "text_delta":
                        current_text += event.text
                        yield {"event": "text", "data": {"chunk": event.text}}
                    elif event.type == "tool_call" and event.tool_call:
                        current_tool_calls.append(event.tool_call)
                    elif event.type == "step_end":
                        # Provider signals the model's turn is over.
                        break
            except ProviderError as e:
                yield {"event": "error", "data": {"message": str(e)}}
                return
            except Exception:
                logger.exception("Streaming step crashed")
                yield {"event": "error", "data": {"message": "LLM stream failed unexpectedly."}}
                return

            assistant_msg = Message(
                role="assistant",
                text=current_text,
                tool_calls=current_tool_calls,
            )
            working.append(assistant_msg)
            self.new_messages.append(assistant_msg)

            if not current_tool_calls:
                # Model produced a final answer.
                yield {"event": "done", "data": {}}
                return

            # Execute tool calls.
            for tc in current_tool_calls:
                yield {
                    "event": "tool_start",
                    "data": {"id": tc.id, "name": tc.name, "input": tc.input},
                }
                result = tool_catalog.execute_tool(self.pcap_path, tc.name, tc.input)
                payload = result.to_payload()
                yield {
                    "event": "tool_end",
                    "data": {
                        "id": tc.id,
                        "name": tc.name,
                        "success": payload["success"],
                        "text": _preview(payload["text"]),
                        "table": payload["table"],
                        "detail": payload["detail"],
                    },
                }
                tool_msg = Message(
                    role="tool",
                    text=result.text,
                    tool_call_id=tc.id,
                )
                working.append(tool_msg)
                self.new_messages.append(tool_msg)

            yield {"event": "turn_end", "data": {}}

        # Hit MAX_AGENT_TURNS without a final answer.
        yield {"event": "truncated", "data": {}}
        yield {"event": "done", "data": {}}


def get_provider(name: str) -> LLMProvider:
    name = (name or "").lower()
    if name == "anthropic":
        from llm.anthropic_provider import AnthropicProvider
        return AnthropicProvider()
    if name == "openai":
        from llm.openai_provider import OpenAIProvider
        return OpenAIProvider()
    if name == "ollama":
        from llm.ollama_provider import OllamaProvider
        return OllamaProvider()
    raise ProviderError(f"Unknown provider '{name}'.")
