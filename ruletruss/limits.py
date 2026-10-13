"""Resource limits and safe file reading. Captures and configuration exports are untrusted input."""
import os

MAX_CONFIG_BYTES = 20 * 1024 * 1024          # a configuration export or log file
MAX_CAPTURE_BYTES = 512 * 1024 * 1024        # a packet capture file
MAX_CONFIG_LINES = 400_000
MAX_LINE_CHARS = 20_000
MAX_XML_DEPTH = 64
MAX_RULES = 100_000
MAX_OBJECT_DEPTH = 16                         # nesting of groups inside groups
MAX_EXPANSION = 50_000                        # addresses or services one group may expand to
MAX_PACKETS = 5_000_000
MAX_FLOWS = 200_000
MAX_NAME_CHARS = 120
PARSE_SECONDS = 600                           # wall-clock limit for a parser subprocess (about 18,000 packets per second)
PARSE_MEMORY_BYTES = 2 * 1024 ** 3


class LimitExceeded(ValueError):
    """An input was larger or more complex than the configured limits allow. Safe to show to the user."""


def read_text_bounded(path, max_bytes=MAX_CONFIG_BYTES):
    """Read a text file as UTF-8 (falling back to Latin-1 for vendor exports), refusing oversized files and NULs."""
    size = os.path.getsize(path)
    if size > max_bytes:
        raise LimitExceeded(f"file is {size:,} bytes; the limit is {max_bytes:,}")
    with open(path, "rb") as handle:
        raw = handle.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise LimitExceeded("file grew while it was being read")
    if b"\x00" in raw:
        raise ValueError("file contains NUL bytes; it does not look like a text configuration export")
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        raise ValueError("file is UTF-16; export it as UTF-8 or ASCII text")
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def clip(text, limit=MAX_NAME_CHARS):
    """Shorten text for display and storage. Never raises."""
    text = str(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"
