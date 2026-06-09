"""
Safe wrapper around the `tshark` command-line tool.

SECURITY DESIGN
---------------
1. We NEVER use `shell=True`. All arguments are passed as a list to subprocess
   so shell metacharacters in user-controlled values cannot trigger command
   injection.
2. The pcap path is validated to be inside UPLOAD_DIR (path-traversal guard).
3. Every invocation has a wall-clock timeout.
4. stdout is capped.
5. Display filters have a hard length cap and control-char check.
6. tshark stderr is logged server-side but NOT returned verbatim except for
   filter syntax errors (which the LLM uses to self-correct).

RESULT SHAPES
-------------
- Row-producing queries (run_display_filter, list_dns_queries,
  list_http_requests) return RowResult: text-for-LLM + parsed rows + column
  metadata. The frontend renders the packet table from this.
- get_packet_detail returns DetailResult: text-for-LLM + parsed dissection
  tree. The frontend renders the detail pane from this.
- Everything else returns plain str.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from config import (
    MAX_FILTER_LENGTH,
    TSHARK_MAX_OUTPUT_BYTES,
    TSHARK_TIMEOUT_SECONDS,
    UPLOAD_DIR,
)

from .parsers import parse_dissection_tree, parse_pipe_rows

logger = logging.getLogger(__name__)


class TsharkError(Exception):
    """Raised when tshark fails. Message is safe to return to caller."""


# --- Result types ---------------------------------------------------------


@dataclass
class RowResult:
    text: str
    title: str
    columns: list[dict] = field(default_factory=list)
    rows: list[dict] = field(default_factory=list)
    truncated: bool = False
    total_matched: int = 0


@dataclass
class DetailResult:
    text: str
    packet_number: int
    tree: list[dict] = field(default_factory=list)


# --- Subprocess core ------------------------------------------------------


def _resolve_tshark_binary() -> str:
    path = shutil.which("tshark")
    if not path:
        raise TsharkError(
            "tshark is not installed or not on PATH. "
            "Install Wireshark / tshark and try again."
        )
    return path


def _validate_pcap_path(pcap_path: Path) -> Path:
    resolved = pcap_path.resolve()
    upload_root = UPLOAD_DIR.resolve()
    try:
        resolved.relative_to(upload_root)
    except ValueError:
        raise TsharkError("Invalid pcap path.")
    if not resolved.is_file():
        raise TsharkError("Pcap file not found.")
    return resolved


def _validate_filter(display_filter: str | None) -> str | None:
    if display_filter is None or display_filter == "":
        return None
    if not isinstance(display_filter, str):
        raise TsharkError("Display filter must be a string.")
    if len(display_filter) > MAX_FILTER_LENGTH:
        raise TsharkError(
            f"Display filter too long (max {MAX_FILTER_LENGTH} characters)."
        )
    if any(ord(c) < 0x20 for c in display_filter):
        raise TsharkError("Display filter contains control characters.")
    return display_filter


def run_tshark(pcap_path: Path, extra_args: list[str]) -> str:
    binary = _resolve_tshark_binary()
    resolved_pcap = _validate_pcap_path(pcap_path)
    cmd = [binary, "-r", str(resolved_pcap), *extra_args]

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            timeout=TSHARK_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise TsharkError(
            f"tshark timed out after {TSHARK_TIMEOUT_SECONDS}s. "
            "Try a narrower filter or smaller result limit."
        )
    except FileNotFoundError:
        raise TsharkError("tshark binary disappeared mid-run.")

    if completed.returncode != 0:
        logger.warning(
            "tshark exited %d. cmd=%r stderr=%r",
            completed.returncode,
            cmd,
            completed.stderr[:500],
        )
        stderr_text = completed.stderr.decode("utf-8", errors="replace")
        if "Invalid display filter" in stderr_text or "syntax error" in stderr_text:
            first_line = stderr_text.strip().splitlines()[0][:300]
            raise TsharkError(f"Invalid display filter: {first_line}")
        raise TsharkError("tshark failed to process the capture.")

    stdout = completed.stdout
    if len(stdout) > TSHARK_MAX_OUTPUT_BYTES:
        stdout = stdout[:TSHARK_MAX_OUTPUT_BYTES]
        logger.info("tshark output truncated to %d bytes", TSHARK_MAX_OUTPUT_BYTES)

    return stdout.decode("utf-8", errors="replace")


# --- Column metadata for row tables --------------------------------------

DISPLAY_FILTER_COLUMNS = [
    {"key": "frame", "label": "No.", "width": "60px"},
    {"key": "time", "label": "Time", "width": "70px"},
    {"key": "src", "label": "Source", "width": "1fr"},
    {"key": "dst", "label": "Destination", "width": "1fr"},
    {"key": "proto", "label": "Proto", "width": "70px"},
    {"key": "info", "label": "Info", "width": "2.5fr"},
]
_DISPLAY_FILTER_KEYS = [c["key"] for c in DISPLAY_FILTER_COLUMNS]

DNS_COLUMNS = [
    {"key": "frame", "label": "No.", "width": "60px"},
    {"key": "time", "label": "Time", "width": "70px"},
    {"key": "src", "label": "Source", "width": "1fr"},
    {"key": "name", "label": "Query", "width": "2fr"},
    {"key": "type", "label": "Type", "width": "60px"},
    {"key": "answer_a", "label": "A", "width": "1fr"},
    {"key": "answer_aaaa", "label": "AAAA", "width": "1fr"},
]
_DNS_KEYS = [c["key"] for c in DNS_COLUMNS]

HTTP_COLUMNS = [
    {"key": "frame", "label": "No.", "width": "60px"},
    {"key": "src", "label": "Source", "width": "1fr"},
    {"key": "dst", "label": "Destination", "width": "1fr"},
    {"key": "method", "label": "Method", "width": "70px"},
    {"key": "host", "label": "Host", "width": "1.5fr"},
    {"key": "uri", "label": "URI", "width": "2fr"},
    {"key": "user_agent", "label": "User-Agent", "width": "1.5fr"},
]
_HTTP_KEYS = [c["key"] for c in HTTP_COLUMNS]


# --- High-level tshark operations ----------------------------------------


def capture_summary(pcap_path: Path) -> dict:
    out = run_tshark(pcap_path, ["-q", "-z", "io,phs"])
    convs = run_tshark(pcap_path, ["-q", "-z", "conv,ip"])
    times_out = run_tshark(
        pcap_path,
        ["-T", "fields", "-e", "frame.time_epoch", "-Y", "frame.number == 1"],
    )
    count_out = run_tshark(pcap_path, ["-q", "-z", "io,stat,0"])
    return {
        "protocol_hierarchy": out,
        "top_ip_conversations": convs,
        "io_stat": count_out,
        "first_packet_epoch": times_out.strip(),
    }


def _row_query(
    pcap_path: Path,
    extra_args: list[str],
    column_keys: list[str],
    columns_meta: list[dict],
    limit: int,
    title: str,
    empty_msg: str,
) -> RowResult:
    text_full = run_tshark(pcap_path, extra_args)
    raw_rows = parse_pipe_rows(text_full, column_keys)
    total = len(raw_rows)
    truncated = total > limit
    rows = raw_rows[:limit]

    if not rows:
        text = empty_msg
    else:
        lines = ["|".join(r.get(k, "") for k in column_keys) for r in rows]
        text = "\n".join(lines)
        if truncated:
            text += (
                f"\n... [truncated to {limit} of {total} rows; "
                "refine the filter to see more]"
            )

    return RowResult(
        text=text,
        title=title,
        columns=columns_meta,
        rows=rows,
        truncated=truncated,
        total_matched=total,
    )


def run_display_filter(
    pcap_path: Path, display_filter: str | None, limit: int
) -> RowResult:
    validated = _validate_filter(display_filter)
    args = [
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_relative",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info",
        "-E", "separator=|",
        "-E", "occurrence=f",
    ]
    if validated:
        args.extend(["-Y", validated])
    title = (
        f"display filter: {display_filter}" if validated else "all packets"
    )
    return _row_query(
        pcap_path,
        args,
        _DISPLAY_FILTER_KEYS,
        DISPLAY_FILTER_COLUMNS,
        limit,
        title,
        empty_msg="(no packets matched)",
    )


def list_dns_queries(pcap_path: Path, limit: int) -> RowResult:
    args = [
        "-Y", "dns",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_relative",
        "-e", "ip.src",
        "-e", "dns.qry.name",
        "-e", "dns.qry.type",
        "-e", "dns.a",
        "-e", "dns.aaaa",
        "-E", "separator=|",
        "-E", "occurrence=f",
    ]
    return _row_query(
        pcap_path, args, _DNS_KEYS, DNS_COLUMNS, limit,
        title="DNS queries",
        empty_msg="(no DNS traffic in this capture)",
    )


def list_http_requests(pcap_path: Path, limit: int) -> RowResult:
    args = [
        "-Y", "http.request",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "http.request.method",
        "-e", "http.host",
        "-e", "http.request.uri",
        "-e", "http.user_agent",
        "-E", "separator=|",
        "-E", "occurrence=f",
    ]
    return _row_query(
        pcap_path, args, _HTTP_KEYS, HTTP_COLUMNS, limit,
        title="HTTP requests",
        empty_msg="(no HTTP requests in this capture)",
    )


def get_conversations(pcap_path: Path, conv_type: str) -> str:
    allowed = {"ip", "tcp", "udp", "eth"}
    if conv_type not in allowed:
        raise TsharkError(f"Unknown conversation type. Use one of: {sorted(allowed)}")
    return run_tshark(pcap_path, ["-q", "-z", f"conv,{conv_type}"])


def get_endpoints(pcap_path: Path, ep_type: str) -> str:
    allowed = {"ip", "tcp", "udp", "eth"}
    if ep_type not in allowed:
        raise TsharkError(f"Unknown endpoint type. Use one of: {sorted(allowed)}")
    return run_tshark(pcap_path, ["-q", "-z", f"endpoints,{ep_type}"])


def get_protocol_hierarchy(pcap_path: Path) -> str:
    return run_tshark(pcap_path, ["-q", "-z", "io,phs"])


def get_packet_detail(pcap_path: Path, packet_number: int) -> DetailResult:
    if not isinstance(packet_number, int) or packet_number < 1:
        raise TsharkError("packet_number must be a positive integer.")
    text = run_tshark(
        pcap_path,
        ["-Y", f"frame.number == {packet_number}", "-V"],
    )
    tree = parse_dissection_tree(text)
    return DetailResult(text=text, packet_number=packet_number, tree=tree)


def follow_stream(pcap_path: Path, protocol: str, stream_index: int) -> str:
    allowed = {"tcp", "udp", "http", "tls"}
    if protocol not in allowed:
        raise TsharkError(f"Protocol must be one of: {sorted(allowed)}")
    if not isinstance(stream_index, int) or stream_index < 0:
        raise TsharkError("stream_index must be a non-negative integer.")
    return run_tshark(
        pcap_path,
        ["-q", "-z", f"follow,{protocol},ascii,{stream_index}"],
    )
