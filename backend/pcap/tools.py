"""
The tool catalog.

Each tool is defined once here in a provider-agnostic shape:
    name, description, JSON schema for parameters, and an implementation
    function that returns a ToolResult.

ToolResult carries three things:
    text   — for the LLM (always present)
    table  — optional structured rows for the frontend's packet table
    detail — optional parsed dissection tree for the frontend's detail pane

LLM providers translate the tool spec into their own tool-calling formats and
only see the `text` field.

SECURITY
--------
Tool inputs are treated as untrusted. We re-validate types and ranges here
even though the LLM is "supposed to" follow the schema.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from config import TOOL_RESULT_MAX_ROWS

from . import tshark


# --- Result types ---------------------------------------------------------


@dataclass
class TableData:
    title: str
    columns: list[dict]
    rows: list[dict]
    truncated: bool = False
    total_matched: int = 0

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "columns": self.columns,
            "rows": self.rows,
            "truncated": self.truncated,
            "total_matched": self.total_matched,
        }


@dataclass
class DetailData:
    packet_number: int
    tree: list[dict]

    def to_dict(self) -> dict:
        return {"packet_number": self.packet_number, "tree": self.tree}


@dataclass
class ToolResult:
    text: str
    table: TableData | None = None
    detail: DetailData | None = None
    success: bool = True

    def to_payload(self) -> dict:
        return {
            "success": self.success,
            "text": self.text,
            "table": self.table.to_dict() if self.table else None,
            "detail": self.detail.to_dict() if self.detail else None,
        }


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    input_schema: dict
    fn: Callable[[Path, dict], ToolResult]


# --- Input coercion helpers ----------------------------------------------


def _coerce_limit(value: Any, default: int) -> int:
    try:
        n = int(value) if value is not None else default
    except (TypeError, ValueError):
        n = default
    if n < 1:
        n = 1
    if n > TOOL_RESULT_MAX_ROWS:
        n = TOOL_RESULT_MAX_ROWS
    return n


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"Argument '{name}' must be a string.")
    return value


def _require_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        try:
            return int(value)
        except (TypeError, ValueError):
            raise ValueError(f"Argument '{name}' must be an integer.")
    return value


def _row_to_tool_result(rr: tshark.RowResult) -> ToolResult:
    return ToolResult(
        text=rr.text,
        table=TableData(
            title=rr.title,
            columns=rr.columns,
            rows=rr.rows,
            truncated=rr.truncated,
            total_matched=rr.total_matched,
        ),
    )


# --- Tool implementations -----------------------------------------------


def _run_display_filter(pcap: Path, inp: dict) -> ToolResult:
    flt = inp.get("filter")
    if flt is not None and not isinstance(flt, str):
        raise ValueError("'filter' must be a string or omitted.")
    limit = _coerce_limit(inp.get("limit"), default=50)
    return _row_to_tool_result(tshark.run_display_filter(pcap, flt, limit))


def _get_protocol_hierarchy(pcap: Path, inp: dict) -> ToolResult:
    return ToolResult(text=tshark.get_protocol_hierarchy(pcap))


def _get_conversations(pcap: Path, inp: dict) -> ToolResult:
    conv_type = _require_str(inp.get("type"), "type")
    return ToolResult(text=tshark.get_conversations(pcap, conv_type))


def _get_endpoints(pcap: Path, inp: dict) -> ToolResult:
    ep_type = _require_str(inp.get("type"), "type")
    return ToolResult(text=tshark.get_endpoints(pcap, ep_type))


def _list_dns_queries(pcap: Path, inp: dict) -> ToolResult:
    limit = _coerce_limit(inp.get("limit"), default=100)
    return _row_to_tool_result(tshark.list_dns_queries(pcap, limit))


def _list_http_requests(pcap: Path, inp: dict) -> ToolResult:
    limit = _coerce_limit(inp.get("limit"), default=100)
    return _row_to_tool_result(tshark.list_http_requests(pcap, limit))


def _get_packet_detail(pcap: Path, inp: dict) -> ToolResult:
    pkt_no = _require_int(inp.get("packet_number"), "packet_number")
    dr = tshark.get_packet_detail(pcap, pkt_no)
    return ToolResult(
        text=dr.text,
        detail=DetailData(packet_number=dr.packet_number, tree=dr.tree),
    )


def _follow_stream(pcap: Path, inp: dict) -> ToolResult:
    protocol = _require_str(inp.get("protocol"), "protocol")
    stream_index = _require_int(inp.get("stream_index"), "stream_index")
    return ToolResult(text=tshark.follow_stream(pcap, protocol, stream_index))


# --- The catalog -----------------------------------------------------------

TOOLS: list[Tool] = [
    Tool(
        name="run_display_filter",
        description=(
            "Run a Wireshark display filter against the capture and return matching "
            "packets, one row per line. Use this for anything not covered by a more "
            "specific tool. Examples: 'tcp.port == 443', "
            "'http.request.method == \"POST\"', 'dns and ip.src == 10.0.0.5'."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "filter": {
                    "type": "string",
                    "description": "Wireshark display filter syntax. Omit for no filter.",
                },
                "limit": {
                    "type": "integer",
                    "description": f"Max rows to return (1-{TOOL_RESULT_MAX_ROWS}). Default 50.",
                },
            },
        },
        fn=_run_display_filter,
    ),
    Tool(
        name="get_protocol_hierarchy",
        description="Protocol breakdown with packet and byte counts. Good for an initial overview.",
        input_schema={"type": "object", "properties": {}},
        fn=_get_protocol_hierarchy,
    ),
    Tool(
        name="get_conversations",
        description="Top conversations (endpoint pairs) by traffic for a given protocol layer.",
        input_schema={
            "type": "object",
            "properties": {
                "type": {"type": "string", "enum": ["ip", "tcp", "udp", "eth"]},
            },
            "required": ["type"],
        },
        fn=_get_conversations,
    ),
    Tool(
        name="get_endpoints",
        description="Top endpoints by traffic for a given protocol layer.",
        input_schema={
            "type": "object",
            "properties": {
                "type": {"type": "string", "enum": ["ip", "tcp", "udp", "eth"]},
            },
            "required": ["type"],
        },
        fn=_get_endpoints,
    ),
    Tool(
        name="list_dns_queries",
        description="DNS queries with the queried name and any answer A/AAAA records.",
        input_schema={
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": f"Max rows (1-{TOOL_RESULT_MAX_ROWS}). Default 100.",
                },
            },
        },
        fn=_list_dns_queries,
    ),
    Tool(
        name="list_http_requests",
        description="HTTP requests: method, host, URI, and User-Agent. (Cleartext HTTP only.)",
        input_schema={
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": f"Max rows (1-{TOOL_RESULT_MAX_ROWS}). Default 100.",
                },
            },
        },
        fn=_list_http_requests,
    ),
    Tool(
        name="get_packet_detail",
        description=(
            "Full multi-layer dissection of a single packet by frame number. "
            "Use after finding an interesting packet via another tool."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "packet_number": {"type": "integer", "description": "Frame number (1-based)."},
            },
            "required": ["packet_number"],
        },
        fn=_get_packet_detail,
    ),
    Tool(
        name="follow_stream",
        description=(
            "Reconstruct a TCP/UDP/HTTP/TLS stream by its stream index "
            "(tcp.stream / udp.stream in display filters)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "protocol": {"type": "string", "enum": ["tcp", "udp", "http", "tls"]},
                "stream_index": {"type": "integer", "description": "Zero-based stream index."},
            },
            "required": ["protocol", "stream_index"],
        },
        fn=_follow_stream,
    ),
]


def tool_by_name(name: str) -> Tool | None:
    for t in TOOLS:
        if t.name == name:
            return t
    return None


def execute_tool(pcap_path: Path, name: str, inputs: dict) -> ToolResult:
    """Run a tool by name and return its ToolResult.

    On any error, returns a ToolResult with success=False and an error message
    in `text`, so the LLM can see the failure and try again.
    """
    tool = tool_by_name(name)
    if tool is None:
        return ToolResult(text=f"Error: unknown tool '{name}'.", success=False)
    if not isinstance(inputs, dict):
        return ToolResult(text="Error: tool inputs must be a JSON object.", success=False)
    try:
        return tool.fn(pcap_path, inputs)
    except ValueError as e:
        return ToolResult(text=f"Error: {e}", success=False)
    except tshark.TsharkError as e:
        return ToolResult(text=f"Error: {e}", success=False)
    except Exception:
        import logging
        logging.getLogger(__name__).exception("Tool %s crashed", name)
        return ToolResult(text="Error: tool execution failed unexpectedly.", success=False)
