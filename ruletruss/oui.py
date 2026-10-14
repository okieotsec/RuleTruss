"""MAC address helpers and the IEEE OUI (vendor prefix) lookup.

An OUI names the company that registered the block a network card's address came from. It is the maker of the network
interface, which is not always the maker of the device it sits in (and is meaningless for randomised or locally set addresses).

The vendor-name table is NOT part of this package. The user downloads it from the IEEE on request (see oui_build.py and the
"Vendor names" card on the Data & privacy tab) into the data folder, and its retrieval date is shown wherever a name is shown. With
no table loaded every function here still works; vendor names are simply absent. This module never touches the network.
"""
import gzip
import os
import re

_HEX = re.compile(r"[^0-9a-f]")
MAX_TABLE_LINES = 200_000
MAX_TABLE_BYTES = 32 * 1024 * 1024


def normalize_mac(value):
    """'AA-bb:cc:dd:ee:ff:00' or 'aabb.ccdd.eeff' or raw bytes -> 'aa:bb:cc:dd:ee:ff', or None if it is not a 48-bit address."""
    if isinstance(value, (bytes, bytearray)):
        digits = bytes(value).hex() if len(value) == 6 else ""
    else:
        digits = _HEX.sub("", str(value).lower())
    if len(digits) != 12:
        return None
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def mac_kind(mac):
    """'broadcast', 'multicast', 'local' (locally administered, often randomised or virtual) or 'universal'."""
    first = int(mac[:2], 16)
    if mac == "ff:ff:ff:ff:ff:ff":
        return "broadcast"
    if first & 1:
        return "multicast"
    return "local" if first & 2 else "universal"


class Registry:
    """The vendor-name table read from one file (or none). It re-reads the file when it changes on disk."""

    def __init__(self, path=None):
        self.path = path
        self._stamp, self._table, self._meta = None, {}, {}

    def _load(self):
        stamp = None
        try:
            stat = os.stat(self.path) if self.path else None
            stamp = (stat.st_mtime_ns, stat.st_size) if stat else None
        except OSError:
            stamp = None
        if stamp == self._stamp:
            return
        self._stamp, self._table, self._meta = stamp, {}, {}
        if stamp is None:
            return
        table, meta, size = {}, {}, 0
        try:
            with gzip.open(self.path, "rt", encoding="utf-8") as handle:
                for number, line in enumerate(handle):
                    size += len(line)
                    if number > MAX_TABLE_LINES or size > MAX_TABLE_BYTES:
                        raise ValueError("vendor-name file is larger than allowed")
                    line = line.rstrip("\n")
                    if line.startswith("#"):
                        key, _, value = line[1:].partition(" ")
                        meta[key] = value[:300]
                    else:
                        prefix, kind, name = line.split("\t", 2)
                        table[prefix] = (kind, name[:120])
        except (OSError, ValueError, EOFError):
            table, meta = {}, {}                     # an unreadable file is the same as no file: names are absent, nothing breaks
        self._table, self._meta = table, meta

    def available(self):
        self._load()
        return bool(self._table)

    def info(self):
        self._load()
        if not self._table:
            return {"available": False, "retrieved": "", "entries": 0, "source": ""}
        return {"available": True, "retrieved": self._meta.get("retrieved", "unknown"), "entries": len(self._table),
                "source": self._meta.get("source", "")}

    def lookup(self, mac):
        """Return {'vendor', 'registry', 'prefix', 'retrieved'} for a universally administered unicast MAC, else None.

        The longest registered prefix wins (36, then 28, then 24 bits), as the IEEE sub-assignments require.
        """
        mac = normalize_mac(mac)
        if mac is None or mac_kind(mac) != "universal":
            return None
        self._load()
        digits = mac.replace(":", "").upper()
        for length in (9, 7, 6):
            hit = self._table.get(digits[:length])
            if hit:
                return {"vendor": hit[1], "registry": hit[0], "prefix": digits[:length],
                        "retrieved": self._meta.get("retrieved", "unknown")}
        return None

    def describe(self, mac):
        """One plain statement about what a MAC address does and does not tell you."""
        mac = normalize_mac(mac)
        if mac is None:
            return ""
        kind = mac_kind(mac)
        if kind == "local":
            return "locally administered address (randomised, virtual or set by software): the prefix does not identify a maker"
        if kind in ("multicast", "broadcast"):
            return "group address, not a device"
        if not self.available():
            return "vendor names are not loaded"
        hit = self.lookup(mac)
        return f"network interface registered to {hit['vendor']}" if hit else "prefix not in the vendor-name table"


NO_NAMES = Registry(None)
