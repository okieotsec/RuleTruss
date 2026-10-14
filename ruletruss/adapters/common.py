"""Pieces every adapter shares: line access with evidence, object resolution with depth and size limits."""
from .. import limits
from ..model import AddrSet, Evidence, ServiceSet
from ..redact import redact


class Lines:
    """The text of a configuration, line by line, so every statement can point back to a line number."""

    def __init__(self, text, source_id):
        self.source_id = source_id
        raw = text.splitlines()
        if len(raw) > limits.MAX_CONFIG_LINES:
            raise limits.LimitExceeded(f"configuration has {len(raw):,} lines; the limit is {limits.MAX_CONFIG_LINES:,}")
        for number, line in enumerate(raw, start=1):             # never parse the front of a line and drop the rest
            if len(line) > limits.MAX_LINE_CHARS:
                raise limits.LimitExceeded(f"line {number} is {len(line):,} characters long; the limit is {limits.MAX_LINE_CHARS:,}")
        self.raw = raw

    def evidence(self, first, last=None):
        """Evidence for line numbers (1-based). The stored text is redacted and clipped."""
        last = last or first
        text = " | ".join(redact(self.raw[n - 1].strip()) for n in range(first, min(last, first + 4) + 1))
        ref = f"line {first}" if first == last else f"lines {first}-{last}"
        return Evidence(self.source_id, "config", ref, limits.clip(text, 400))


class Resolver:
    """Resolve names that refer to other names (nested groups) without recursion limits being exceeded.

    `defs` maps name to a list of members; a member is ("leaf", value) or ("ref", name). `leaf_fn(value)` converts a
    leaf into a list of results. Cycles, missing names and runaway expansion are reported, never followed.
    """

    def __init__(self, defs, leaf_fn, on_problem):
        self.defs = defs
        self.leaf_fn = leaf_fn
        self.on_problem = on_problem

    def resolve(self, name, _depth=0, _seen=None):
        """Return (results, unresolved_names)."""
        seen = set(_seen or ())
        if name in seen:
            self.on_problem("warning", "group-cycle", f"group {name} contains itself; the loop was ignored")
            return [], []
        if _depth > limits.MAX_OBJECT_DEPTH:
            self.on_problem("warning", "group-too-deep", f"group {name} is nested more than {limits.MAX_OBJECT_DEPTH} "
                            "levels deep; deeper members were not resolved")
            return [], [name]
        if name not in self.defs:
            return [], [name]
        seen.add(name)
        out, unresolved = [], []
        for kind, value in self.defs[name]:
            if kind == "ref":
                sub, sub_un = self.resolve(value, _depth + 1, seen)
                out.extend(sub)
                unresolved.extend(sub_un)
            else:
                got = self.leaf_fn(value)
                if got is None:
                    unresolved.append(" ".join(value) if isinstance(value, tuple) else str(value))
                else:
                    out.extend(got)
            if len(out) > limits.MAX_EXPANSION:
                self.on_problem("warning", "group-too-large", f"group {name} expands to more than "
                                f"{limits.MAX_EXPANSION:,} entries; the rest were not resolved")
                unresolved.append(f"{name} (too large to resolve)")
                return out[: limits.MAX_EXPANSION], unresolved
        return out, unresolved


def cap_expansion(items, unresolved, name, issue):
    """Bound a group that expands as it is resolved. When cut, the group is also reported as unresolved, so no rule relies on part of it."""
    if len(items) <= limits.MAX_EXPANSION:
        return False
    issue("warning", "group-too-large", f"group {name} expands to more than {limits.MAX_EXPANSION:,} entries; the rest were not resolved")
    del items[limits.MAX_EXPANSION:]
    unresolved.append(f"{name} (too large to resolve)")
    return True


def dedupe(items):
    seen, out = set(), []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def addr_any():
    return AddrSet(any=True)


def svc_any():
    return ServiceSet(any=True)
