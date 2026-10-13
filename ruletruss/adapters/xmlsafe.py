"""Parse untrusted XML configuration exports (PAN-OS, pfSense, OPNsense) without entity expansion or deep nesting."""
import re

# The stdlib parser is used on purpose: input containing a DOCTYPE or any entity declaration is refused before parsing (tests:
# billion laughs, external entity), depth and element counts are bounded, and the parser runs in a memory-limited subprocess.
# This avoids a third-party runtime dependency. See SECURITY_TEST_PLAN.md and reports/cp0-baseline.
# nosemgrep: use-defused-xml
from xml.etree import ElementTree  # nosec B405

from .. import limits

_FORBIDDEN = re.compile(r"<!\s*(DOCTYPE|ENTITY|ELEMENT|ATTLIST)", re.IGNORECASE)


def parse_xml(text):
    """Return the root Element. Refuses DTDs and entity declarations (XXE, billion laughs) and runaway depth."""
    if _FORBIDDEN.search(text):
        raise ValueError("this XML contains a DOCTYPE or entity declaration; it is refused because such files can be "
                         "used to attack the parser. Export the configuration again without it.")
    try:
        root = ElementTree.fromstring(text)  # noqa: S314  # nosec B314 - DTDs and entities were refused above
    except ElementTree.ParseError as error:
        raise ValueError(f"the XML could not be read: {error}") from error
    stack = [(root, 1)]
    count = 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if depth > limits.MAX_XML_DEPTH:
            raise limits.LimitExceeded(f"XML is nested more than {limits.MAX_XML_DEPTH} levels deep")
        if count > 2_000_000:
            raise limits.LimitExceeded("XML has more than 2,000,000 elements")
        stack.extend((child, depth + 1) for child in node)
    return root


def members(node, path):
    """Texts of <member> children under `path` (a '/'-separated tag path) of `node`; [] when absent."""
    target = node.find(path) if path else node
    if target is None:
        return []
    return [(m.text or "").strip() for m in target.findall("member") if (m.text or "").strip()]


def text(node, path, default=""):
    found = node.find(path)
    return (found.text or "").strip() if found is not None and found.text else default


def snippet(node, limit=400):
    """A short, redacted XML rendering of an element, for evidence."""
    from ..redact import redact
    raw = ElementTree.tostring(node, encoding="unicode")
    return limits.clip(redact(re.sub(r"\s+", " ", raw)), limit)
