"""A tiny, fictional vendor-name table for tests, the guide and screenshots. It is NOT the IEEE registry and names no real company.

The Riverbend example gives its devices MAC addresses from real IEEE-registered prefixes (so the real registry, once downloaded,
resolves them). This table maps the same prefixes to invented registrants, so the example can show the card-maker feature without
shipping any of the IEEE's data and without attributing invented devices to real companies.
"""
from .. import oui_build

SAMPLE = {
    "00000C": "Example Networks Corp.", "00090F": "Example Firewall Co.", "001B17": "Example Security Appliances Inc.",
    "000C29": "Example Virtualization Inc.", "00065B": "Example Computers Inc.", "0001E6": "Example Workstations Co.",
    "0001E3": "Example Automation AG", "0000BC": "Example Industrial Controls", "000054": "Example Electric",
    "00006C": "Example Electric", "0002A2": "Example Gateways GmbH", "008063": "Example Switch Works GmbH",
}


def install(path, extra=None):
    """Write the sample table to `path` in the format the application reads."""
    rows = {prefix: ("MA-L", name) for prefix, name in {**SAMPLE, **(extra or {})}.items()}
    oui_build.write(rows, path)
    return path
