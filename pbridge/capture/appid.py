"""Application identification from payload evidence.

Confidence levels:
  confirmed  the payload has a structure that an unrelated protocol would almost never produce (magic values plus
             length and enumeration checks, or a successful decode).
  probable   the payload has a weak but real signature (for example a banner or a one-byte marker).
  possible   only the port number suggests it. A port is never treated as proof.

Text taken from packets (host names, banners) is untrusted: it is reduced to printable ASCII and clipped before use.
"""
import re
import struct
from dataclasses import dataclass

import dpkt

from ..model import AppGuess

CONFIRMED, PROBABLE, POSSIBLE = "confirmed", "probable", "possible"
MODBUS_FUNCS = {1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers", 4: "Read Input Registers",
                5: "Write Single Coil", 6: "Write Single Register", 7: "Read Exception Status", 8: "Diagnostics",
                11: "Get Comm Event Counter", 12: "Get Comm Event Log", 15: "Write Multiple Coils",
                16: "Write Multiple Registers", 17: "Report Server ID", 20: "Read File Record", 21: "Write File Record",
                22: "Mask Write Register", 23: "Read/Write Multiple Registers", 24: "Read FIFO Queue",
                43: "Encapsulated Interface Transport"}
ENIP_COMMANDS = {0x0004: "ListServices", 0x0063: "ListIdentity", 0x0064: "ListInterfaces", 0x0065: "RegisterSession",
                 0x0066: "UnRegisterSession", 0x006F: "SendRRData", 0x0070: "SendUnitData"}
IEC104_U = {0x07: "STARTDT act", 0x0B: "STARTDT con", 0x13: "STOPDT act", 0x23: "STOPDT con", 0x43: "TESTFR act",
            0x83: "TESTFR con"}
PORT_HINTS = {
    ("tcp", 502): "Modbus/TCP", ("tcp", 44818): "EtherNet/IP", ("udp", 44818): "EtherNet/IP",
    ("udp", 2222): "EtherNet/IP implicit I/O", ("tcp", 20000): "DNP3", ("udp", 20000): "DNP3",
    ("tcp", 102): "S7comm / ISO-on-TCP (or IEC 61850 MMS)", ("udp", 47808): "BACnet/IP", ("tcp", 4840): "OPC UA",
    ("tcp", 2404): "IEC 60870-5-104", ("tcp", 22): "SSH", ("tcp", 23): "Telnet", ("tcp", 80): "HTTP",
    ("tcp", 443): "TLS (HTTPS)", ("tcp", 53): "DNS", ("udp", 53): "DNS", ("udp", 123): "NTP", ("udp", 161): "SNMP",
    ("udp", 162): "SNMP trap", ("tcp", 445): "SMB", ("tcp", 3389): "RDP", ("udp", 67): "DHCP", ("udp", 68): "DHCP",
    ("udp", 514): "Syslog", ("tcp", 21): "FTP", ("tcp", 25): "SMTP", ("udp", 5353): "mDNS", ("udp", 1900): "SSDP",
    ("tcp", 1433): "Microsoft SQL Server", ("tcp", 3306): "MySQL", ("tcp", 5432): "PostgreSQL",
    ("tcp", 135): "MS RPC", ("tcp", 139): "NetBIOS session", ("udp", 137): "NetBIOS name", ("tcp", 1911): "Niagara Fox",
    ("tcp", 789): "Red Lion Crimson", ("tcp", 9600): "OMRON FINS", ("udp", 9600): "OMRON FINS",
    ("tcp", 1962): "PCWorx", ("tcp", 18245): "GE SRTP", ("tcp", 34980): "EtherCAT (UDP/TCP)",
}


@dataclass
class Hit:
    name: str
    confidence: str
    detail: str
    role: str = None           # "client" or "server": which role the sender of this payload played


def safe_text(raw, limit=80):
    """Printable ASCII only, clipped. Anything else becomes '?'."""
    text = "".join(chr(b) if 32 <= b < 127 else "?" for b in raw[:limit])
    return text + ("..." if len(raw) > limit else "")


def _crc_dnp(data):
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return (~crc) & 0xFFFF


def decode_modbus(p, proto, sport, dport):
    if proto != "tcp" or len(p) < 8:
        return None
    tid, pid, length, unit, func = struct.unpack("!HHHBB", p[:8])
    if pid != 0 or length < 2 or length > 254 or length != len(p) - 6 or (func & 0x7F) not in MODBUS_FUNCS:
        return None
    exception = bool(func & 0x80)
    role = None
    if exception:
        role = "server"
    elif func in (3, 4) and length == 6:
        role = "client"
    elif func in (3, 4) and len(p) > 8 and length == 3 + p[8] and p[8] % 2 == 0:
        role = "server"
    name = MODBUS_FUNCS[func & 0x7F]
    detail = (f"decoded Modbus/TCP header (protocol id 0, length {length} matches the data, function {func & 0x7F} "
              f"{name}{' exception response' if exception else ''}, unit {unit}, transaction {tid})")
    return Hit("Modbus/TCP", CONFIRMED, detail, role)


def decode_enip(p, proto, sport, dport):
    if len(p) < 24:
        return None
    cmd, length, session, _status = struct.unpack("<HHII", p[:12])
    options = struct.unpack("<I", p[20:24])[0]
    if cmd not in ENIP_COMMANDS or length != len(p) - 24 or options != 0:
        return None
    role = "client" if cmd == 0x0063 and length == 0 else None
    return Hit("EtherNet/IP", CONFIRMED, f"decoded EtherNet/IP encapsulation header (command {ENIP_COMMANDS[cmd]}, length "
               f"{length} matches the data, session {session:#x})", role)


def decode_dnp3(p, proto, sport, dport):
    if len(p) < 10 or p[0] != 0x05 or p[1] != 0x64 or p[2] < 5:
        return None
    if struct.unpack("<H", p[8:10])[0] != _crc_dnp(p[:8]):
        return None
    ctrl = p[3]
    role = "client" if ctrl & 0x80 and ctrl & 0x40 else "server" if not ctrl & 0x80 else None
    return Hit("DNP3", CONFIRMED, f"decoded DNP3 link-layer header (start bytes 0x0564, header CRC valid, control byte "
               f"{ctrl:#04x}, length {p[2]})", role)


def decode_tpkt(p, proto, sport, dport):
    if proto != "tcp" or len(p) < 7 or p[0] != 3 or p[1] != 0 or struct.unpack("!H", p[2:4])[0] != len(p):
        return None
    cotp_len, cotp_type = p[4], p[5]
    if cotp_type == 0xF0 and len(p) >= 17 and p[7] == 0x32 and p[8] in (1, 2, 3, 7):
        roles = {1: "client", 2: "server", 3: "server", 7: None}
        names = {1: "Job", 2: "Ack", 3: "Ack_Data", 7: "Userdata"}
        return Hit("S7comm", CONFIRMED, f"decoded TPKT + COTP data + S7 header (protocol id 0x32, message type "
                   f"{names[p[8]]})", roles[p[8]])
    if cotp_type in (0xE0, 0xD0) and cotp_len + 5 <= len(p):
        body = p[4 + cotp_len + 1:] if cotp_len + 5 <= len(p) else b""
        role = "client" if cotp_type == 0xE0 else "server"
        if b"Cookie: mstshash=" in p or (cotp_type == 0xE0 and len(body) >= 8 and body[0] == 0x01 and body[2:4] == b"\x08\x00"):
            return Hit("RDP", CONFIRMED if b"mstshash" in p else PROBABLE,
                       "decoded TPKT + X.224 connection request carrying an RDP negotiation or cookie", role)
        return Hit("ISO-on-TCP (TPKT/COTP)", PROBABLE, "TPKT and COTP connection setup with a valid length; the "
                   "upper protocol (S7comm, MMS, RDP) is not yet visible", role)
    return None


def decode_bacnet(p, proto, sport, dport):
    if proto != "udp" or len(p) < 6 or p[0] != 0x81 or p[1] not in (0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x09, 0x0A,
                                                                    0x0B, 0x0C, 0x0D):
        return None
    if struct.unpack("!H", p[2:4])[0] != len(p):
        return None
    return Hit("BACnet/IP", CONFIRMED, f"decoded BACnet virtual link header (type 0x81, function {p[1]:#04x}, length "
               f"{len(p)} matches)", None)


def decode_opcua(p, proto, sport, dport):
    if proto != "tcp" or len(p) < 8 or p[:3] not in (b"HEL", b"ACK", b"OPN", b"MSG", b"CLO", b"ERR") or p[3:4] not in (
            b"F", b"C", b"A"):
        return None
    size = struct.unpack("<I", p[4:8])[0]
    if size != len(p) and size > len(p):
        return None
    role = "client" if p[:3] in (b"HEL", b"OPN", b"CLO") else "server" if p[:3] == b"ACK" else None
    return Hit("OPC UA", CONFIRMED, f"decoded OPC UA binary message header ({p[:3].decode()}, size {size})", role)


def decode_iec104(p, proto, sport, dport):
    if proto != "tcp" or len(p) < 6 or p[0] != 0x68 or not 4 <= p[1] <= 253 or p[1] + 2 > len(p):
        return None
    control = p[2]
    if control & 3 == 3 and (p[1] != 4 or control not in IEC104_U):
        return None
    return Hit("IEC 60870-5-104", PROBABLE, "start byte 0x68 and a consistent APDU length"
               + (f" ({IEC104_U[control]})" if control in IEC104_U and p[1] == 4 else ""), None)


def decode_dns(p, proto, sport, dport):
    data = p[2:] if proto == "tcp" and len(p) > 2 and struct.unpack("!H", p[:2])[0] == len(p) - 2 else p
    if len(data) < 12 or len(data) > 4096:
        return None
    try:
        msg = dpkt.dns.DNS(data)
    except (dpkt.Error, struct.error, ValueError, IndexError, UnicodeError):
        return None
    if not 1 <= len(msg.qd) <= 8 or len(msg.an) > 64 or msg.opcode > 5 or msg.rcode > 11:
        return None
    name = msg.qd[0].name
    if not name or len(name) > 253 or not re.fullmatch(r"[A-Za-z0-9_.\-*]+", name):
        return None
    label = "mDNS" if 5353 in (sport, dport) else "DNS"
    role = "server" if msg.qr else "client"
    kind = "response" if msg.qr else "query"
    return Hit(label, CONFIRMED, f"decoded DNS message ({kind} for {safe_text(name.encode())})", role)


HTTP_REQUEST = re.compile(rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT) \S{1,2000} HTTP/1\.[01]\r\n")
HTTP_RESPONSE = re.compile(rb"^HTTP/1\.[01] \d{3} ")


def decode_http(p, proto, sport, dport):
    if proto != "tcp":
        return None
    if HTTP_REQUEST.match(p):
        line = p.split(b"\r\n", 1)[0]
        return Hit("HTTP", CONFIRMED, f"decoded HTTP request line ({safe_text(line, 60)})", "client")
    if HTTP_RESPONSE.match(p):
        status_line = p.split(b"\r\n", 1)[0]
        return Hit("HTTP", CONFIRMED, f"decoded HTTP response status line ({safe_text(status_line, 40)})", "server")
    return None


def _sni(body):
    """Server name from a ClientHello body, or None. Bounds-checked."""
    try:
        pos = 2 + 32
        pos += 1 + body[pos]
        pos += 2 + struct.unpack("!H", body[pos:pos + 2])[0]
        pos += 1 + body[pos]
        ext_total = struct.unpack("!H", body[pos:pos + 2])[0]
        pos += 2
        end = min(len(body), pos + ext_total)
        while pos + 4 <= end:
            etype, elen = struct.unpack("!HH", body[pos:pos + 4])
            pos += 4
            if etype == 0 and elen >= 5:
                nlen = struct.unpack("!H", body[pos + 3:pos + 5])[0]
                return safe_text(body[pos + 5:pos + 5 + nlen], 100)
            pos += elen
    except (IndexError, struct.error):
        return None
    return None


def decode_tls(p, proto, sport, dport):
    if proto != "tcp" or len(p) < 6 or p[0] not in (20, 21, 22, 23) or p[1] != 3 or p[2] > 4:
        return None
    length = struct.unpack("!H", p[3:5])[0]
    if length == 0 or length > 18432:
        return None
    if p[0] == 22 and len(p) >= 11:
        htype = p[5]
        if htype == 1 and p[6] == 0 and len(p) >= 43:
            sni = _sni(p[9:5 + length])
            return Hit("TLS", CONFIRMED, "decoded TLS ClientHello" + (f" with server name {sni}" if sni else ""), "client")
        if htype == 2 and p[6] == 0:
            return Hit("TLS", CONFIRMED, "decoded TLS ServerHello", "server")
    return Hit("TLS", PROBABLE, f"valid TLS record header (type {p[0]}, length {length})", None)


def decode_ssh(p, proto, sport, dport):
    if proto == "tcp" and re.match(rb"^SSH-(1\.99|2\.0)-[\x21-\x7e]{1,60}", p):
        return Hit("SSH", CONFIRMED, f"decoded SSH identification string ({safe_text(p.split(b'\r', 1)[0], 40)})", None)
    return None


def decode_ntp(p, proto, sport, dport):
    if proto != "udp" or len(p) not in (48, 68, 72, 76):
        return None
    version, mode = (p[0] >> 3) & 7, p[0] & 7
    if not 1 <= version <= 4 or not 1 <= mode <= 5:
        return None
    role = "client" if mode == 3 else "server" if mode in (4, 5) else None
    return Hit("NTP", PROBABLE, f"48-byte NTP-shaped packet (version {version}, mode {mode})", role)


def _ber_len(data, pos):
    first = data[pos]
    if first < 0x80:
        return first, pos + 1
    count = first & 0x7F
    if count == 0 or count > 2:
        raise ValueError
    return int.from_bytes(data[pos + 1:pos + 1 + count], "big"), pos + 1 + count


def decode_snmp(p, proto, sport, dport):
    if proto != "udp" or len(p) < 10 or p[0] != 0x30:
        return None
    try:
        total, pos = _ber_len(p, 1)
        if total != len(p) - pos or p[pos] != 0x02 or p[pos + 1] != 1 or p[pos + 2] not in (0, 1, 3):
            return None
        version = p[pos + 2]
        pos += 3
        if version == 3:
            return Hit("SNMP", PROBABLE, "BER sequence with SNMP version 3 and a consistent length", None)
        if p[pos] != 0x04:
            return None
        clen, pos2 = _ber_len(p, pos + 1)
        pos = pos2 + clen
        pdu = p[pos]
    except (IndexError, ValueError):
        return None
    if pdu not in range(0xA0, 0xA9):
        return None
    role = "client" if pdu in (0xA0, 0xA1, 0xA3, 0xA5, 0xA6) else "server" if pdu == 0xA2 else None
    return Hit("SNMP", CONFIRMED, f"decoded SNMP v{'1' if version == 0 else '2c'} message (PDU type {pdu:#04x}, length "
               "matches)", role)


def decode_dhcp(p, proto, sport, dport):
    if proto != "udp" or len(p) < 240 or p[0] not in (1, 2) or p[1] != 1 or p[2] != 6 or p[236:240] != b"\x63\x82\x53\x63":
        return None
    return Hit("DHCP", CONFIRMED, "decoded BOOTP/DHCP message (magic cookie present)", "client" if p[0] == 1 else "server")


def decode_smb(p, proto, sport, dport):
    if proto != "tcp" or len(p) < 8 or p[0] != 0 or p[4:8] not in (b"\xffSMB", b"\xfeSMB"):
        return None
    if int.from_bytes(p[1:4], "big") > len(p) - 4 + 65536:
        return None
    role = None
    if p[4:8] == b"\xfeSMB" and len(p) >= 24 and struct.unpack("<H", p[8:10])[0] == 64:
        role = "server" if p[20] & 1 else "client"
    return Hit("SMB", CONFIRMED, f"decoded SMB{'2/3' if p[4] == 0xFE else '1'} header", role)


def decode_banners(p, proto, sport, dport):
    if proto == "tcp" and re.match(rb"^220[ -][\x20-\x7e]{0,100}(FTP|ftp)", p):
        return Hit("FTP", PROBABLE, "server greeting 220 containing FTP", "server")
    if proto == "tcp" and re.match(rb"^220[ -][\x20-\x7e]{0,100}(SMTP|ESMTP)", p):
        return Hit("SMTP", PROBABLE, "server greeting 220 containing SMTP", "server")
    if proto == "tcp" and len(p) >= 3 and p[0] == 0xFF and p[1] in (0xFB, 0xFC, 0xFD, 0xFE) and p[2] < 50:
        return Hit("Telnet", PROBABLE, "Telnet IAC option negotiation bytes", None)
    if proto == "udp" and re.match(rb"^(M-SEARCH|NOTIFY) \* HTTP/1\.1\r\n", p):
        return Hit("SSDP", CONFIRMED, "decoded SSDP request line", "client")
    if proto == "udp" and re.match(rb"^<\d{1,3}>", p):
        return Hit("Syslog", PROBABLE, "syslog priority prefix <NN>", None)
    return None


DECODERS = (decode_modbus, decode_enip, decode_dnp3, decode_tpkt, decode_bacnet, decode_opcua, decode_iec104, decode_dns,
            decode_http, decode_tls, decode_ssh, decode_ntp, decode_snmp, decode_dhcp, decode_smb, decode_banners)


def decode_payload(proto, payload, sport, dport):
    """Run every decoder on one payload; returns the list of Hit objects (usually zero or one)."""
    hits = []
    if not payload:
        return hits
    for decoder in DECODERS:
        try:
            hit = decoder(payload, proto, sport, dport)
        except (struct.error, IndexError, ValueError, KeyError, UnicodeError, AttributeError):
            hit = None
        if hit is not None:
            hits.append(hit)
    return hits


def identify(proto, hit_samples, ports, payload_seen):
    """Combine payload evidence for one flow.

    hit_samples: list of (direction_index, packet_number, [Hit, ...]) from decode_payload on the first payload packets.
    ports: the two port numbers, used only for the port-hint fallback. Returns (list of AppGuess, notes).
    """
    best = {}
    roles = {}
    for _direction, number, hits in hit_samples:
        for hit in hits:
            current = best.get(hit.name)
            if current is None or _rank(hit.confidence) > _rank(current[0].confidence):
                best[hit.name] = (hit, number)
            if hit.role:
                roles.setdefault(hit.name, set()).add(hit.role)
    guesses, notes = [], []
    for name, (hit, number) in best.items():
        confidence = hit.confidence
        basis = f"{hit.detail} in packet {number}"
        if confidence == PROBABLE and roles.get(name) == {"client", "server"}:
            confidence = CONFIRMED
            basis += "; a request and a response in this flow both match"
        guesses.append(AppGuess(name, confidence, basis))
    guesses.sort(key=lambda g: -_rank(g.confidence))
    hinted = [PORT_HINTS[(proto, p)] for p in dict.fromkeys(ports) if p is not None and (proto, p) in PORT_HINTS]
    identified = {g.name for g in guesses}
    for hint in hinted:
        base = hint.split(" ")[0].lower()
        if not any(base in name.lower() or name.lower() in hint.lower() for name in identified):
            if identified:
                notes.append(f"The port usually carries {hint}, but the payload decoded as "
                             f"{', '.join(sorted(identified))}. The port number alone was not used.")
            else:
                guesses.append(AppGuess(hint, POSSIBLE, "only the port number suggests this" + (
                    "; the captured payload did not decode as it" if payload_seen else "; no payload was captured to check")))
    return guesses, notes


def _rank(confidence):
    return {CONFIRMED: 3, PROBABLE: 2, POSSIBLE: 1}[confidence]
