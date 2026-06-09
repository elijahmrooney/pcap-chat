"""
Upload validation and storage.

Uploaded files are accepted only if they begin with a recognized pcap or
pcapng magic number. The client-supplied filename is discarded; files are
stored under UPLOAD_DIR with a server-generated UUID name. Size is capped.

Magic numbers
-------------
pcapng:           0a 0d 0d 0a   (Section Header Block type)
classic pcap:     d4 c3 b2 a1   (LE, microsecond)
                  a1 b2 c3 d4   (BE, microsecond)
                  4d 3c b2 a1   (LE, nanosecond)
                  a1 b2 3c 4d   (BE, nanosecond)
"""
from __future__ import annotations

import logging
import uuid
from pathlib import Path

from config import MAX_UPLOAD_BYTES, UPLOAD_DIR

logger = logging.getLogger(__name__)


class UploadError(Exception):
    """Raised when an upload is rejected. Message is safe to show the user."""


# Recognized 4-byte magic numbers.
_PCAP_MAGICS = {
    bytes.fromhex("0a0d0d0a"),  # pcapng
    bytes.fromhex("d4c3b2a1"),  # classic LE microsecond
    bytes.fromhex("a1b2c3d4"),  # classic BE microsecond
    bytes.fromhex("4d3cb2a1"),  # classic LE nanosecond
    bytes.fromhex("a1b23c4d"),  # classic BE nanosecond
}


def _looks_like_pcap(head: bytes) -> bool:
    return len(head) >= 4 and head[:4] in _PCAP_MAGICS


def save_upload(data: bytes, original_filename: str) -> tuple[Path, str]:
    """Validate and store uploaded bytes.

    Returns (stored_path, original_filename). The original filename is kept
    only for display; it never influences the path on disk.

    Raises UploadError on size or magic-byte failure.
    """
    if not data:
        raise UploadError("Uploaded file is empty.")

    if len(data) > MAX_UPLOAD_BYTES:
        mb = MAX_UPLOAD_BYTES // (1024 * 1024)
        raise UploadError(f"File too large (max {mb} MB).")

    if not _looks_like_pcap(data):
        raise UploadError(
            "File does not look like a pcap/pcapng capture "
            "(unrecognized magic bytes)."
        )

    # Server-generated name; ignore whatever the client called it.
    stored_name = f"{uuid.uuid4().hex}.pcap"
    stored_path = (UPLOAD_DIR / stored_name).resolve()

    # Defense in depth: ensure we are writing inside UPLOAD_DIR.
    try:
        stored_path.relative_to(UPLOAD_DIR.resolve())
    except ValueError:
        raise UploadError("Refusing to write outside the upload directory.")

    stored_path.write_bytes(data)
    safe_display = Path(original_filename).name or "capture.pcap"
    logger.info("Stored upload %s as %s (%d bytes)", safe_display, stored_name, len(data))
    return stored_path, safe_display
