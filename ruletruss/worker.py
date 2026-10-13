"""Parse one untrusted file in a separate, resource-limited process.

Usage (internal): python -I -m ruletruss.worker <input path> <output path> <options json>

The parent starts this with a wall-clock timeout, an empty environment and a throw-away working directory. Here the process
caps its own memory, CPU time, output size and open files before it opens the input. The result is written as JSON to the output
path; the parent reads it back with a size cap. Error text written here is limited to messages the parsers raise on purpose.
"""
import json
import sys

from . import limits


def apply_limits():
    """Set kernel resource limits where the platform supports them (Linux, macOS). Windows relies on the parent's timeout."""
    try:
        import resource
    except ImportError:
        return False
    cpu = limits.PARSE_SECONDS + 5
    for name, value in (("RLIMIT_CORE", 0), ("RLIMIT_CPU", cpu), ("RLIMIT_FSIZE", 512 * 1024 * 1024), ("RLIMIT_NOFILE", 64),
                        ("RLIMIT_AS", limits.PARSE_MEMORY_BYTES)):
        if hasattr(resource, name):
            try:
                resource.setrlimit(getattr(resource, name), (value, value))
            except (ValueError, OSError):
                pass
    return True


def run(kind, input_path, options):
    """Return a JSON-ready dict for the file. kind is 'auto'; the file's content decides how it is read."""
    from .model import to_plain
    with open(input_path, "rb") as handle:
        head = handle.read(4096)
    capture_id = options["source_id"]
    if head[:4] in (b"\x0a\x0d\x0d\x0a", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        from .capture.flows import analyze_capture
        info, flows = analyze_capture(input_path, capture_id, capture_id, options["filename"], options.get("observation_point", ""))
        return {"kind": "capture", "info": to_plain(info), "flows": to_plain(flows)}
    text_head = head.decode("utf-8", "replace")
    if text_head.lstrip().startswith("{") or "#fields" in text_head or "#separator" in text_head:
        from .capture.zeek import parse_conn_log
        info, flows = parse_conn_log(input_path, capture_id, capture_id, options["filename"], options.get("observation_point", ""))
        return {"kind": "flows", "info": to_plain(info), "flows": to_plain(flows)}
    from .adapters.registry import detect_format, parse_config
    text = limits.read_text_bounded(input_path)
    fmt = options.get("format") or detect_format(text)
    policy = parse_config(text, capture_id, fmt)
    return {"kind": "policy", "format": fmt, "policy": to_plain(policy)}


def main(argv):
    input_path, output_path, options_json = argv[1], argv[2], argv[3]
    apply_limits()
    options = json.loads(options_json)
    try:
        result = run("auto", input_path, options)
        payload = {"ok": True, "result": result}
    except (ValueError, OSError) as error:        # parser errors and limit errors carry user-safe messages
        payload = {"ok": False, "error": str(error)[:500], "known": True}
    except MemoryError:
        payload = {"ok": False, "error": "the file needs more memory than the parser is allowed to use", "known": True}
    except Exception:
        payload = {"ok": False, "error": "the file could not be processed", "known": False}
    with open(output_path, "w", encoding="ascii") as handle:
        json.dump(payload, handle, ensure_ascii=True, separators=(",", ":"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
