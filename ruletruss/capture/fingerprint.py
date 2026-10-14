"""Passive device identification: decoders for what devices say about themselves, and a tracker that collects it.

Nothing here sends anything. Every decoder works on bytes already captured, checks every length before it reads, and returns
plain text cut to a safe length. Text taken from a capture is only ever shown as text. What a device reports about itself can be
wrong or forged, so each observation records who said it and how sure we are; none of it says what the device is for.
"""
import ipaddress
import re
import struct

from .. import limits, oui
from ..model import DeviceFacts, Evidence, L2Sender, MacBinding, Observation

TEXT_LIMIT = 120
LLDP_CAPS = ((0x01, "other"), (0x02, "repeater"), (0x04, "bridge"), (0x08, "WLAN access point"), (0x10, "router"),
             (0x20, "telephone"), (0x40, "cable device"), (0x80, "station"))
CIP_VENDORS = {1: "Rockwell Automation/Allen-Bradley"}
CIP_DEVICE_TYPES = {0x02: "AC drive", 0x0C: "communications adapter", 0x0E: "PLC"}
MODBUS_OBJECTS = {0: "vendor", 1: "product code", 2: "revision", 3: "vendor URL", 4: "product", 5: "model", 6: "application"}
SNMP_SYSDESCR, SNMP_SYSOBJECTID, SNMP_SYSNAME = (bytes.fromhex(h) for h in ("2b06010201010100", "2b06010201010200", "2b06010201010500"))
UNSPECIFIED = ("0.0.0.0", "::")  # noqa: S104  # nosec B104 - compared against, never bound to
TTL_NOTES = {32: "older or embedded stacks", 64: "common for Linux, macOS and many embedded stacks", 128: "common for Windows",
             255: "common for network equipment and some embedded stacks"}
SSH_BANNER = re.compile(r"SSH-\d\.\d+-[\x21-\x7e][\x20-\x7e]{0,100}")
HTTP_REQUEST = re.compile(rb"[A-Z]{3,7} \S{1,500} HTTP/1\.[01]$")


def text(raw, limit=TEXT_LIMIT):
    """Printable ASCII only, whitespace collapsed, cut to `limit`. Control characters and non-ASCII are dropped."""
    out = " ".join("".join(chr(b) if 32 <= b < 127 else " " if b in (9, 10, 13) else "" for b in bytes(raw[: limit * 2])).split())
    return out if len(out) <= limit else out[: limit - 3] + "..."


def initial_ttl(ttl):
    return next((b for b in (32, 64, 128, 255) if ttl <= b), 255)


# ------------------------------------------------------------------ decoders (each returns a dict, or None if it does not match)

def parse_lldp(data):
    """LLDP frame body: chassis and port IDs, system name and description, enabled capabilities, management IPv4 address."""
    out, pos, seen = {}, 0, 0
    while pos + 2 <= len(data) and seen < 64:
        head = struct.unpack_from("!H", data, pos)[0]
        kind, length = head >> 9, head & 0x1FF
        value = data[pos + 2:pos + 2 + length]
        if len(value) < length:
            break
        pos += 2 + length
        if seen == 0 and kind != 1:
            return None
        seen += 1
        if kind == 0:
            break
        if kind == 1 and length >= 2:
            out["chassis"] = oui.normalize_mac(value[1:]) if value[0] == 4 and length == 7 else text(value[1:], 60)
        elif kind == 2 and length >= 2:
            out["port"] = oui.normalize_mac(value[1:]) if value[0] == 3 and length == 7 else text(value[1:], 60)
        elif kind == 4:
            out["port_description"] = text(value, 60)
        elif kind == 5:
            out["name"] = text(value)
        elif kind == 6:
            out["description"] = text(value)
        elif kind == 7 and length >= 4:
            enabled = struct.unpack_from("!H", value, 2)[0]
            out["capabilities"] = [name for bit, name in LLDP_CAPS if enabled & bit]
        elif kind == 8 and length >= 7 and value[0] == 5 and value[1] == 1:
            out["management_ip"] = str(ipaddress.ip_address(value[2:6]))
    return out if seen and (out.get("chassis") or out.get("name")) else None


def parse_dhcp(data):
    """DHCP/BOOTP message: client MAC, the address in play, message type, client hostname and vendor class."""
    if len(data) < 241 or data[236:240] != b"\x63\x82\x53\x63" or data[1] != 1 or data[2] != 6:
        return None
    out = {"op": data[0], "mac": oui.normalize_mac(data[28:34]), "ciaddr": data[12:16], "yiaddr": data[16:20]}
    pos = 240
    while pos < len(data):
        code = data[pos]
        if code == 255:
            break
        if code == 0:
            pos += 1
            continue
        if pos + 2 > len(data):
            break
        length = data[pos + 1]
        value = data[pos + 2:pos + 2 + length]
        if len(value) < length:
            break
        pos += 2 + length
        if code == 53 and length == 1:
            out["type"] = value[0]
        elif code == 12:
            out["hostname"] = text(value, 63)
        elif code == 60:
            out["vendor_class"] = text(value, 80)
        elif code == 50 and length == 4:
            out["requested"] = value
    return out if out["mac"] and out["mac"] != "00:00:00:00:00:00" else None


def parse_enip_identity(data):
    """EtherNet/IP ListIdentity reply: vendor ID, device type, product code, revision, serial number and product name."""
    if len(data) < 26 or struct.unpack_from("<H", data, 0)[0] != 0x0063 or struct.unpack_from("<H", data, 2)[0] < 2:
        return None
    pos = 26
    for _ in range(min(struct.unpack_from("<H", data, 24)[0], 4)):
        if pos + 4 > len(data):
            return None
        item, length = struct.unpack_from("<HH", data, pos)
        body = data[pos + 4:pos + 4 + length]
        pos += 4 + length
        if item == 0x000C and len(body) >= 33:
            vendor, device_type, product_code = struct.unpack_from("<HHH", body, 18)
            major, minor, _status, serial = struct.unpack_from("<BBHI", body, 24)
            name = text(body[33:33 + body[32]], 60)
            vendor_text = CIP_VENDORS.get(vendor, f"CIP vendor ID {vendor}")
            kind = CIP_DEVICE_TYPES.get(device_type, f"device type {device_type}")
            return {"value": f"{name or 'unnamed'} ({vendor_text} {kind}; revision {major}.{minor}; product code {product_code}; "
                             f"serial {serial:08X})"}
    return None


def parse_modbus_device_id(data):
    """Modbus 'Read Device Identification' response (function 0x2B, MEI type 0x0E): the objects the device returns."""
    if len(data) < 16 or data[2:4] != b"\x00\x00" or data[7] != 0x2B or data[8] != 0x0E or struct.unpack_from("!H", data, 4)[0] < 8:
        return None
    count, pos, found = data[13], 14, {}
    for _ in range(min(count, 16)):
        if pos + 2 > len(data):
            break
        object_id, length = data[pos], data[pos + 1]
        value = data[pos + 2:pos + 2 + length]
        if len(value) < length:
            break
        pos += 2 + length
        if object_id in MODBUS_OBJECTS and value:
            found[object_id] = text(value, 50)
    name = found.get(4) or found.get(5) or found.get(6) or ""
    details = [x for x in (found.get(0), found.get(1), f"revision {found[2]}" if 2 in found else "", found.get(3)) if x]
    value = f"{name} ({'; '.join(details)})" if name and details else name or "; ".join(details)
    return {"value": value} if value else None


def _tlv(data, pos, end):
    """One BER element: (tag, value_start, value_end), or None if it does not fit inside [pos, end)."""
    if pos + 2 > end:
        return None
    tag, length = data[pos], data[pos + 1]
    pos += 2
    if length & 0x80:
        size = length & 0x7F
        if size == 0 or size > 2 or pos + size > end:
            return None
        length = int.from_bytes(data[pos:pos + size], "big")
        pos += size
    return (tag, pos, pos + length) if pos + length <= end else None


def _oid_text(raw):
    if not raw:
        return ""
    parts, value = [str(min(raw[0] // 40, 2)), str(raw[0] - 40 * min(raw[0] // 40, 2))], 0
    for byte in raw[1:25]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def parse_snmp_response(data):
    """SNMP GetResponse: sysDescr, sysName and sysObjectID if present. The community string is read past and never kept."""
    outer = _tlv(data, 0, len(data))
    if not outer or outer[0] != 0x30:
        return None
    pos, end = outer[1], outer[2]
    for expected in (0x02, 0x04):                      # version, community
        item = _tlv(data, pos, end)
        if not item or item[0] != expected:
            return None
        pos = item[2]
    pdu = _tlv(data, pos, end)
    if not pdu or pdu[0] != 0xA2:
        return None
    pos, end = pdu[1], pdu[2]
    for _ in range(3):                                 # request id, error status, error index
        item = _tlv(data, pos, end)
        if not item or item[0] != 0x02:
            return None
        pos = item[2]
    varbinds = _tlv(data, pos, end)
    if not varbinds or varbinds[0] != 0x30:
        return None
    out, pos = {}, varbinds[1]
    for _ in range(32):
        entry = _tlv(data, pos, varbinds[2])
        if not entry:
            break
        pos = entry[2]
        oid = _tlv(data, entry[1], entry[2])
        if not oid or oid[0] != 0x06:
            continue
        value = _tlv(data, oid[2], entry[2])
        if not value:
            continue
        name, raw = bytes(data[oid[1]:oid[2]]), data[value[1]:value[2]]
        if name == SNMP_SYSDESCR and value[0] == 0x04:
            out["description"] = text(raw)
        elif name == SNMP_SYSNAME and value[0] == 0x04:
            out["name"] = text(raw, 60)
        elif name == SNMP_SYSOBJECTID and value[0] == 0x06:
            out["object_id"] = _oid_text(raw)
    return out or None


def http_headers(payload):
    """('response', Server header) or ('request', User-Agent header) from the start of an HTTP/1.x message, else None."""
    head = bytes(payload[:4096]).split(b"\r\n\r\n", 1)[0].split(b"\r\n")[:60]
    if not head:
        return None
    if head[0].startswith(b"HTTP/1.") and len(head[0]) >= 12:
        wanted, role = b"server:", "response"
    elif HTTP_REQUEST.fullmatch(head[0]):
        wanted, role = b"user-agent:", "request"
    else:
        return None
    for line in head[1:]:
        if line[:len(wanted)].lower() == wanted:
            value = text(line[len(wanted):], 100)
            return (role, value) if value else None
    return None


def ssh_banner(payload):
    line = bytes(payload[:120]).split(b"\n", 1)[0].rstrip(b"\r").decode("latin-1")
    return line if SSH_BANNER.fullmatch(line) else None


# ------------------------------------------------------------------ collection

class DeviceTracker:
    """Collects MAC bindings, layer-2 senders and identity observations while a capture is read. Bounded in every dimension."""

    def __init__(self, source_id, max_items=limits.MAX_DEVICE_ITEMS):
        self.source_id, self.max_items = source_id, max_items
        self.bindings, self.senders, self.observations = {}, {}, {}
        self.ttl = {}
        self.full = False

    def _evidence(self, numbers, note):
        return [Evidence(self.source_id, "packet", ",".join(str(n) for n in numbers), note)]

    def _bind(self, number, mac, ip, basis):
        if not mac or oui.mac_kind(mac) in ("multicast", "broadcast"):
            return
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return
        if address.is_unspecified or address.is_multicast:
            return
        key = (mac, ip, basis)
        entry = self.bindings.get(key)
        if entry is None:
            if len(self.bindings) >= self.max_items:
                self.full = True
                return
            entry = self.bindings[key] = MacBinding(mac, ip, basis, 0, [])
        entry.packets += 1
        if len(entry.evidence) < 1:
            entry.evidence = self._evidence([number], {"arp": "ARP message", "dhcp": "DHCP acknowledgement",
                                                       "frame": "frame carrying this IP's packets"}[basis])
        elif entry.packets <= 4:
            entry.evidence[0].ref += f",{number}"

    def _observe(self, number, kind, value, confidence, basis, ip="", mac="", source_type="self-reported"):
        if not value or not (ip or mac):
            return
        key = (ip, mac, kind, value)
        if key in self.observations:
            return
        if len(self.observations) >= self.max_items:
            self.full = True
            return
        self.observations[key] = Observation(kind, value, confidence, source_type, basis, ip, mac, self._evidence([number], basis))

    # ---- layer 2
    def add_l2(self, frame):
        entry = self.senders.get(frame.src_mac)
        if entry is None:
            if len(self.senders) >= self.max_items:
                self.full = True
                return
            entry = self.senders[frame.src_mac] = L2Sender(frame.src_mac, 0, [], self._evidence([frame.number], "non-IP frame"))
        entry.frames += 1
        if frame.kind not in entry.kinds:
            entry.kinds.append(frame.kind)
        if frame.kind == "arp" and frame.arp:
            op, sender, spa = frame.arp
            if op in (1, 2) and sender == frame.src_mac:
                self._bind(frame.number, sender, spa, "arp")
        elif frame.kind == "lldp":
            self._lldp(frame)

    def _lldp(self, frame):
        info = parse_lldp(frame.lldp)
        if not info:
            return
        mac, basis = frame.src_mac, "LLDP advertisement"
        if info.get("name"):
            self._observe(frame.number, "lldp-name", info["name"], "confirmed", basis, mac=mac)
        if info.get("description"):
            self._observe(frame.number, "lldp-description", info["description"], "confirmed", basis, mac=mac)
        if info.get("capabilities"):
            self._observe(frame.number, "lldp-capabilities", ", ".join(info["capabilities"]), "confirmed", basis, mac=mac)
        if info.get("management_ip"):
            self._bind(frame.number, mac, info["management_ip"], "arp")        # the device advertises this as its own address

    # ---- IP packets
    def add_packet(self, packet):
        if packet.src_mac and packet.src_mac != packet.dst_mac:
            self._bind(packet.number, packet.src_mac, packet.src, "frame")
        if packet.ttl and packet.proto in ("tcp", "udp", "icmp", "icmp6") and packet.src not in UNSPECIFIED \
                and (packet.src in self.ttl or len(self.ttl) < self.max_items) \
                and packet.ttl > self.ttl.get(packet.src, (0, 0))[0]:
            self.ttl[packet.src] = (packet.ttl, packet.number)
        payload = packet.payload
        if not payload:
            return
        if packet.proto == "udp":
            self._udp(packet, payload)
        elif packet.proto == "tcp":
            self._tcp(packet, payload)

    def _udp(self, packet, payload):
        ports = {packet.sport, packet.dport}
        if ports & {67, 68}:
            self._dhcp(packet, parse_dhcp(payload))
        elif packet.sport == 161:
            info = parse_snmp_response(payload)
            if info:
                for key, kind in (("description", "snmp-sysdescr"), ("name", "snmp-sysname"), ("object_id", "snmp-sysobjectid")):
                    self._observe(packet.number, kind, info.get(key), "confirmed", "SNMP response from the device", ip=packet.src)
        elif packet.sport == 44818:
            self._enip(packet, payload)

    def _tcp(self, packet, payload):
        if packet.sport == 502:
            info = parse_modbus_device_id(payload)
            if info:
                self._observe(packet.number, "modbus-identity", info["value"], "confirmed", "Modbus device identification reply",
                              ip=packet.src)
        elif packet.sport == 44818:
            self._enip(packet, payload)
        banner = ssh_banner(payload)
        if banner:
            self._observe(packet.number, "ssh-banner", banner, "confirmed", "SSH version banner", ip=packet.src)
            return
        http = http_headers(payload)
        if http:
            role, value = http
            self._observe(packet.number, "http-server" if role == "response" else "http-user-agent", value, "confirmed",
                          "HTTP Server header" if role == "response" else "HTTP User-Agent header", ip=packet.src)

    def _enip(self, packet, payload):
        info = parse_enip_identity(payload)
        if info:
            self._observe(packet.number, "enip-identity", info["value"], "confirmed", "EtherNet/IP ListIdentity reply", ip=packet.src)

    def _dhcp(self, packet, info):
        if not info:
            return
        mac, source_ip = info["mac"], ""
        if info["op"] == 2 and info.get("type") == 5 and info["yiaddr"] != b"\x00" * 4:
            source_ip = str(ipaddress.ip_address(info["yiaddr"]))
            self._bind(packet.number, mac, source_ip, "dhcp")
        elif info["op"] == 1 and info["ciaddr"] != b"\x00" * 4:
            source_ip = str(ipaddress.ip_address(info["ciaddr"]))
        if info["op"] == 1:                                      # hostname and vendor class are the client's own words
            self._observe(packet.number, "dhcp-hostname", info.get("hostname"), "confirmed", "DHCP client request", ip=source_ip, mac=mac)
            self._observe(packet.number, "dhcp-vendor-class", info.get("vendor_class"), "confirmed", "DHCP client request",
                          ip=source_ip, mac=mac)

    # ---- result
    def facts(self):
        for ip, (ttl, number) in self.ttl.items():
            bucket = initial_ttl(ttl)
            self._observe(number, "ttl-hint", f"initial TTL probably {bucket} ({TTL_NOTES[bucket]})", "possible",
                          f"highest TTL seen from this address was {ttl}", ip=ip, source_type="weak-hint")
        facts = DeviceFacts(list(self.bindings.values()), list(self.senders.values()), list(self.observations.values()))
        if self.full:
            facts.limits_hit.append(f"more than {self.max_items:,} device records in this capture; the rest were not recorded")
        return facts
