"""Import a Zeek conn.log (tab-separated with a #fields header, or JSON lines) as flow records.

A conn.log is a summary written by another tool. There are no packets or payloads to re-check, the originator is Zeek's
own inference, and the `service` column is Zeek's protocol label. All three are reported as such, with lower confidence
than direct packet evidence.
"""
import ipaddress
import json
import os

from .. import limits
from ..model import AppGuess, CaptureInfo, Evidence, Flow
from .flows import coverage_notes
from .reader import CaptureStats

REQUIRED = ("ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto")
MAX_LINE = 20_000


def sniff(first_line):
    return "json" if first_line.lstrip().startswith("{") else "tsv"


def _clean(value):
    return None if value in ("-", "(empty)", "") else value


def _record(raw_fields, mapping):
    out = {}
    for name in ("ts", "uid", "proto", "service", "duration", "conn_state", "history", "orig_pkts", "resp_pkts",
                 "orig_ip_bytes", "resp_ip_bytes", "orig_bytes", "resp_bytes"):
        out[name] = _clean(str(mapping.get(name, "-"))) if mapping.get(name) is not None else None
    out["orig_h"], out["orig_p"] = mapping.get("id.orig_h"), mapping.get("id.orig_p")
    out["resp_h"], out["resp_p"] = mapping.get("id.resp_h"), mapping.get("id.resp_p")
    return out


def _iter_records(path, stats):
    with open(path, "rb") as handle:
        header = handle.readline(MAX_LINE + 1)
    kind = sniff(header.decode("utf-8", "replace"))
    fields = []
    separator = "\t"
    with open(path, encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, start=1):
            if len(line) > MAX_LINE:
                stats.errors += 1
                continue
            line = line.rstrip("\n")
            if not line:
                continue
            if kind == "json":
                try:
                    obj = json.loads(line)
                except (ValueError, RecursionError):
                    stats.errors += 1
                    continue
                if not isinstance(obj, dict):
                    stats.errors += 1
                    continue
                if isinstance(obj.get("id"), dict):
                    for k, v in obj["id"].items():
                        obj[f"id.{k}"] = v
                yield number, _record(None, obj)
                continue
            if line.startswith("#"):
                if line.startswith("#separator"):
                    token = line.split(" ", 1)[1] if " " in line else "\\x09"
                    separator = bytes(token, "ascii", "ignore").decode("unicode_escape") or "\t"
                elif line.startswith("#fields"):
                    fields = line.split(separator)[1:]
                continue
            if not fields:
                raise ValueError("this tab-separated file has no #fields header, so it is not a Zeek log")
            parts = line.split(separator)
            if len(parts) != len(fields):
                stats.errors += 1
                continue
            yield number, _record(None, dict(zip(fields, parts, strict=True)))


def _int(value):
    try:
        return int(float(value)) if value not in (None, "-") else 0
    except (TypeError, ValueError):
        return 0


def parse_conn_log(path, capture_id, source_id, filename, observation_point=""):
    """Return (CaptureInfo, [Flow])."""
    size = os.path.getsize(path)
    if size > limits.MAX_CONFIG_BYTES * 10:
        raise limits.LimitExceeded(f"log is {size:,} bytes; the limit is {limits.MAX_CONFIG_BYTES * 10:,}")
    stats = CaptureStats()
    flows = []
    first = last = None
    saw_any = False
    for number, rec in _iter_records(path, stats):
        saw_any = True
        stats.read += 1
        try:
            ts = float(rec["ts"])
            src, dst = str(ipaddress.ip_address(rec["orig_h"])), str(ipaddress.ip_address(rec["resp_h"]))
            sport, dport = _int(rec["orig_p"]), _int(rec["resp_p"])
        except (TypeError, ValueError, KeyError):
            stats.errors += 1
            continue
        proto = (rec["proto"] or "").lower()
        if proto not in ("tcp", "udp", "icmp"):
            stats.errors += 1
            continue
        if len(flows) >= limits.MAX_FLOWS:
            stats.limits_hit.append(f"stopped after {limits.MAX_FLOWS:,} connections; the rest were not imported")
            break
        v6 = ":" in src
        flow_proto = "icmp6" if proto == "icmp" and v6 else proto
        history = rec["history"] or ""
        state = rec["conn_state"] or ""
        notes = ["Direction is Zeek's own inference (conn.log originator), not re-derived from packets."]
        if proto == "tcp":
            if "S" in history and "h" in history:
                conf, basis = "high", [f"Zeek history '{history}': originator SYN and responder SYN-ACK"]
            elif "S" in history:
                conf, basis = "high", [f"Zeek history '{history}': originator sent a SYN"]
            elif "h" in history:
                conf, basis = "medium", [f"Zeek history '{history}': responder SYN-ACK seen without the SYN"]
            else:
                conf = "low"
                basis = [(f"Zeek history '{history or '-'}' (state {state or '-'}) shows no handshake: "
                          "the originator was guessed by Zeek")]
                notes.append("No handshake in the log: the connection began before the log started or was one-sided.")
        elif proto == "udp":
            conf, basis = "low", ["Zeek treats the first datagram seen as the originator; UDP has no handshake"]
        else:
            conf, basis = ("high", ["ICMP echo request"]) if sport in (8, 128) else ("unknown", ["ICMP message"])
        apps = []
        for name in (rec["service"] or "").split(","):
            if name:
                apps.append(AppGuess(limits.clip(name, 40), "probable", "reported by Zeek's protocol analyzer "
                                     "(conn.log service column); not independently decoded here"))
        duration = float(rec["duration"]) if rec["duration"] and rec["duration"] != "-" else 0.0
        flows.append(Flow(
            flow_id=f"{capture_id}-f{len(flows) + 1}", source_id=source_id, ip_version=6 if v6 else 4, proto=flow_proto,
            initiator=src, responder=dst, initiator_port=None if proto == "icmp" else sport,
            responder_port=None if proto == "icmp" else dport, direction_confidence=conf, direction_basis=basis,
            pkts_fwd=_int(rec["orig_pkts"]), pkts_rev=_int(rec["resp_pkts"]), bytes_fwd=_int(rec["orig_bytes"]),
            bytes_rev=_int(rec["resp_bytes"]), first_ts=ts, last_ts=ts + duration,
            icmp_type=sport if proto == "icmp" else None, icmp_code=dport if proto == "icmp" else None, apps=apps,
            notes=notes,
            evidence=[Evidence(source_id, "flow", f"line {number} uid {limits.clip(rec['uid'] or '-', 30)}",
                               f"{proto} {src}:{sport} -> {dst}:{dport} state {state or '-'} history {history or '-'}")]))
        first = ts if first is None else min(first, ts)
        last = ts + duration if last is None else max(last, ts + duration)
    if not saw_any:
        raise ValueError("no connection records were found in this file")
    info = CaptureInfo(capture_id=capture_id, filename=limits.clip(filename), format="zeek-conn", size_bytes=size,
                       packets_read=stats.read, packets_decoded=len(flows), packets_skipped=stats.errors, first_ts=first,
                       last_ts=last, link_types=["flow records"], observation_point=limits.clip(observation_point, 200),
                       limits_hit=list(stats.limits_hit), flows=len(flows))
    info.coverage_notes = coverage_notes(info, stats, 0)
    info.coverage_notes.append("This is a Zeek connection summary: no packets or payloads are available to re-check it. "
                               "Counts in the 'packets' fields are connection records, not packets.")
    return info, flows
