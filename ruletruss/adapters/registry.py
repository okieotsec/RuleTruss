"""Pick the adapter for an uploaded file and run it. Detection looks at content, never at the file name alone."""
from .. import limits
from ..redact import redact, single_line
from . import cisco, fortios, panos, pfsense, unifi

SOURCE_FORMATS = {
    "cisco-asa": "Cisco ASA running-config",
    "cisco-ios": "Cisco IOS / IOS-XE running-config (ACLs)",
    "panos": "Palo Alto PAN-OS XML configuration",
    "fortios": "Fortinet FortiOS CLI configuration",
    "pfsense": "pfSense config.xml",
    "opnsense": "OPNsense config.xml (legacy rules only)",
    "unifi": "UniFi Network firewall zones and policies (JSON from tools/unifi_export.py)",
}


def detect_format(text):
    """The format key for configuration text, or None when nothing matches."""
    head = text.lstrip()[:200_000]
    if unifi.detect(head):
        return "unifi"
    if head.startswith("<"):
        if pfsense.detect(head):
            return "opnsense" if "<opnsense>" in head[:2000] else "pfsense"
        if panos.detect(head):
            return "panos"
        return None
    if fortios.detect(head):
        return "fortios"
    flavour = cisco.detect(head)
    return {"asa": "cisco-asa", "ios": "cisco-ios"}.get(flavour)


def parse_config(text, source_id, fmt=None):
    """Parse configuration text to a PolicySet. `fmt` overrides detection when the user chose a format."""
    fmt = fmt or detect_format(text)
    if fmt is None:
        raise ValueError("the format of this configuration was not recognised. Supported: "
                         + "; ".join(SOURCE_FORMATS.values()))
    if fmt not in SOURCE_FORMATS:
        raise ValueError(f"unknown format {fmt!r}")
    policy = _parse(text, source_id, fmt)
    for rule in policy.rules:                        # administrators' comments: one plain line, and no credentials copied out of them
        if rule.comment:
            rule.comment = redact(single_line(rule.comment, limits.MAX_LINE_CHARS))
    return policy


def _parse(text, source_id, fmt):
    if fmt == "cisco-asa":
        return cisco.parse(text, source_id, "asa")
    if fmt == "cisco-ios":
        return cisco.parse(text, source_id, "ios")
    if fmt == "panos":
        return panos.parse(text, source_id)
    if fmt == "fortios":
        return fortios.parse(text, source_id)
    if fmt == "unifi":
        return unifi.parse(text, source_id)
    return pfsense.parse(text, source_id)
