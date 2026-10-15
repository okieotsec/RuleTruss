"""Resource limits and safe file reading. Captures and configuration exports are untrusted input."""
import os

MAX_CONFIG_BYTES = 20 * 1024 * 1024          # a configuration export or log file
MAX_CAPTURE_BYTES = 512 * 1024 * 1024        # a packet capture file
MAX_CONFIG_LINES = 400_000
MAX_LINE_CHARS = 20_000
MAX_XML_DEPTH = 64
MAX_RULES = 100_000
MAX_OBJECT_DEPTH = 16                         # nesting of groups inside groups
MAX_VISITS = 200_000                           # group lookups while resolving one name (groups that list each other many times)
MAX_EXPANSION = 50_000                        # addresses or services one group may expand to
MAX_PACKETS = 5_000_000
MAX_FLOWS = 200_000
MAX_NAME_CHARS = 120
MAX_RESULT_BYTES = 512 * 1024 * 1024         # the analysis of one file, as the worker hands it back and as it is stored
MAX_DEVICE_ITEMS = 50_000                     # MAC bindings, layer-2 senders and identity observations per capture
PARSE_SECONDS = 600                           # wall-clock limit for a parser subprocess (about 18,000 packets per second)
PARSE_MEMORY_BYTES = 2 * 1024 ** 3


# The five limits below can be raised (or lowered) at start-up with --max-capture-mb, --max-packets, --parse-minutes, --max-flows and
# --parse-memory-gb. They are a protection against a hostile or broken file, so each has a ceiling that no setting can exceed.
CEILINGS = {"MAX_CAPTURE_BYTES": 256 * 1024 ** 3, "MAX_PACKETS": 2_000_000_000, "MAX_FLOWS": 500_000, "PARSE_SECONDS": 24 * 3600,
            "PARSE_MEMORY_BYTES": 128 * 1024 ** 3}
TUNABLE = tuple(CEILINGS)


def snapshot():
    """The current values of the adjustable limits, as a plain dict (sent to the parsing process)."""
    return {name: globals()[name] for name in TUNABLE}


def apply(values):
    """Set adjustable limits from a dict. Unknown names, non-integers and values outside 1..ceiling are refused."""
    for name, value in (values or {}).items():
        if name not in CEILINGS:
            raise ValueError(f"unknown limit {name!r}")
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= CEILINGS[name]:
            raise ValueError(f"{name} must be a whole number from 1 to {CEILINGS[name]:,}")
        globals()[name] = value


def configure(max_capture_mb=None, max_packets=None, parse_minutes=None, max_flows=None, parse_memory_gb=None):
    """Apply the command-line settings (None leaves a limit alone)."""
    scale = {"MAX_CAPTURE_BYTES": (max_capture_mb, 1024 ** 2), "MAX_PACKETS": (max_packets, 1), "PARSE_SECONDS": (parse_minutes, 60),
             "MAX_FLOWS": (max_flows, 1), "PARSE_MEMORY_BYTES": (parse_memory_gb, 1024 ** 3)}
    apply({name: int(value * unit) for name, (value, unit) in scale.items() if value is not None})


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
