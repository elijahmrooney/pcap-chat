"""
LLM provider abstraction with streaming support.

Canonical message format (unchanged):
    role="user":      text content only
    role="assistant": text and/or tool_calls
    role="tool":      one tool result, referenced by tool_call_id

For streaming, providers yield StreamEvent objects. The agent loop drives the
conversation by consuming these events.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Iterator


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict


@dataclass
class Message:
    role: str  # "user" | "assistant" | "tool"
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str = ""


# --- Streaming events ----------------------------------------------------


@dataclass
class StreamEvent:
    """One event yielded by a streaming provider.

    type values:
        "text_delta"  — a chunk of text the model emitted. `text` carries it.
        "tool_call"   — a fully-assembled tool call ready to execute.
                        `tool_call` carries it. (Providers buffer partial
                        JSON internally; we don't expose deltas to the
                        agent loop.)
        "step_end"    — model finished this turn. `finished` is True if
                        the model is done (no more turns expected),
                        False if it ended with a tool_use stop reason.
    """

    type: str
    text: str = ""
    tool_call: ToolCall | None = None
    finished: bool = False


class ProviderError(Exception):
    """Raised on provider/network/auth failures. Message is shown to the user."""


class LLMProvider(ABC):
    name: str = "unknown"

    @abstractmethod
    def stream_step(
        self,
        system: str,
        messages: list[Message],
        tools: list[dict],
        model: str | None = None,
    ) -> Iterator[StreamEvent]:
        """Stream one model turn. Yields text_delta, tool_call, and step_end events."""

    @abstractmethod
    def format_tools(self, catalog: list[Any]) -> list[dict]:
        """Convert the provider-agnostic Tool catalog into this provider's tool spec."""

    @abstractmethod
    def default_model(self) -> str:
        ...
