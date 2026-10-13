"""Synthetic captures for tests and the demonstration. Every address, name and payload here is made up.

The scenario is a small fictional plant: an engineering network (10.20.0.0/16), a controller network (10.30.0.0/16), a
corporate network (10.10.0.0/16) and a few services. It deliberately includes the awkward cases the analysis must handle:
a capture that starts mid-connection, a connection attempt with no reply, one-way UDP, a reverse-direction connection
between the same two hosts, IPv6, VLAN tags, port reuse, and traffic on a well-known port that is not that protocol.
"""
import ipaddress
import struct

import dpkt

ETH_A, ETH_B = b"\x02\x00\x00\x00\x00\x01", b"\x02\x00\x00\x00\x00\x02"
SYN, ACK, FIN, RST, PSH = dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK, dpkt.tcp.TH_FIN, dpkt.tcp.TH_RST, dpkt.tcp.TH_PUSH


def modbus_request(tid, unit=1, func=3, start=0, qty=10):
    return struct.pack("!HHHBBHH", tid, 0, 6, unit, func, start, qty)


def modbus_response(tid, unit=1, func=3, registers=10):
    data = bytes(range(registers * 2))
    return struct.pack("!HHHBBB", tid, 0, 3 + len(data), unit, func, len(data)) + data


def enip_register_session(response=False):
    body = struct.pack("<HH", 1, 0)
    header = struct.pack("<HHII8sI", 0x0065, len(body), 0x1234 if response else 0, 0, b"\x00" * 8, 0)
    return header + body


def opcua_hello():
    body = struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + struct.pack("<I", 4) + b"opc."
    return b"HELF" + struct.pack("<I", 8 + len(body)) + body


def dns_message(name, response=False, txid=0x1234):
    msg = dpkt.dns.DNS(id=txid, qr=1 if response else 0, opcode=0, rcode=0, qd=[dpkt.dns.DNS.Q(name=name, type=1, cls=1)])
    if response:
        msg.an = [dpkt.dns.DNS.RR(name=name, type=1, cls=1, ttl=60, ip=bytes([10, 20, 1, 20]))]
    return bytes(msg)


def ntp_packet(mode):
    return bytes([0x18 | mode]) + b"\x00" * 47


def snmp_get(response=False):
    pdu_tag = b"\xa2" if response else b"\xa0"
    varbind = b"\x30\x0b\x06\x07\x2b\x06\x01\x02\x01\x01\x01\x05\x00"
    pdu_body = b"\x02\x01\x01\x02\x01\x00\x02\x01\x00" + b"\x30" + bytes([len(varbind)]) + varbind
    pdu = pdu_tag + bytes([len(pdu_body)]) + pdu_body
    inner = b"\x02\x01\x01\x04\x06public" + pdu
    return b"\x30" + bytes([len(inner)]) + inner


def tls_client_hello(sni):
    name = sni.encode()
    ext_sni = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
            + struct.pack("!H", len(ext_sni)) + ext_sni)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


class CaptureBuilder:
    """Collects frames and writes them as PCAP or PCAPNG."""

    def __init__(self, start=1_700_000_000.0):
        self.start = start
        self.frames = []

    def _ip(self, src, dst, l4, proto, ts):
        a, b = ipaddress.ip_address(src), ipaddress.ip_address(dst)
        if a.version == 4:
            ip = dpkt.ip.IP(src=a.packed, dst=b.packed, p=proto, data=l4, ttl=64)
            ip.len = len(bytes(ip))
            ethertype = dpkt.ethernet.ETH_TYPE_IP
        else:
            ip = dpkt.ip6.IP6(src=a.packed, dst=b.packed, nxt=proto, hlim=64, data=l4)
            ethertype = dpkt.ethernet.ETH_TYPE_IP6
        return ip, ethertype

    def _emit(self, ts, ip, ethertype, vlan=None):
        eth = dpkt.ethernet.Ethernet(dst=ETH_B, src=ETH_A, type=ethertype, data=ip)
        raw = bytes(eth)
        if vlan is not None:
            raw = raw[:12] + b"\x81\x00" + struct.pack("!H", vlan) + raw[12:]
        self.frames.append((self.start + ts, raw))

    def tcp(self, ts, src, sport, dst, dport, flags, payload=b"", seq=1000, ack=0, vlan=None):
        l4 = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, data=payload)
        ip, ethertype = self._ip(src, dst, l4, dpkt.ip.IP_PROTO_TCP, ts)
        self._emit(ts, ip, ethertype, vlan)

    def udp(self, ts, src, sport, dst, dport, payload):
        l4 = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
        l4.ulen = len(bytes(l4))
        ip, ethertype = self._ip(src, dst, l4, dpkt.ip.IP_PROTO_UDP, ts)
        self._emit(ts, ip, ethertype)

    def icmp(self, ts, src, dst, icmp_type, ident=7, seq=1):
        echo = dpkt.icmp.ICMP.Echo(id=ident, seq=seq, data=b"abcdefgh")
        l4 = dpkt.icmp.ICMP(type=icmp_type, code=0, data=echo)
        ip, ethertype = self._ip(src, dst, l4, dpkt.ip.IP_PROTO_ICMP, ts)
        self._emit(ts, ip, ethertype)

    def arp(self, ts):
        arp = dpkt.arp.ARP(sha=ETH_A, spa=bytes([10, 20, 1, 15]), tha=b"\x00" * 6, tpa=bytes([10, 20, 1, 1]))
        eth = dpkt.ethernet.Ethernet(dst=b"\xff" * 6, src=ETH_A, type=dpkt.ethernet.ETH_TYPE_ARP, data=arp)
        self.frames.append((self.start + ts, bytes(eth)))

    def session(self, ts, client, cport, server, sport, request=b"", response=b"", close=True, vlan=None):
        """A full TCP session: handshake, one request and response, then FIN."""
        self.tcp(ts, client, cport, server, sport, SYN, seq=100, vlan=vlan)
        self.tcp(ts + 0.001, server, sport, client, cport, SYN | ACK, seq=500, ack=101, vlan=vlan)
        self.tcp(ts + 0.002, client, cport, server, sport, ACK, seq=101, ack=501, vlan=vlan)
        seq_c, seq_s = 101, 501
        if request:
            self.tcp(ts + 0.01, client, cport, server, sport, PSH | ACK, request, seq=seq_c, ack=seq_s, vlan=vlan)
            seq_c += len(request)
        if response:
            self.tcp(ts + 0.02, server, sport, client, cport, PSH | ACK, response, seq=seq_s, ack=seq_c, vlan=vlan)
            seq_s += len(response)
        if close:
            self.tcp(ts + 0.03, client, cport, server, sport, FIN | ACK, seq=seq_c, ack=seq_s, vlan=vlan)
            self.tcp(ts + 0.031, server, sport, client, cport, FIN | ACK, seq=seq_s, ack=seq_c + 1, vlan=vlan)

    def write(self, path, fmt="pcap"):
        frames = sorted(self.frames, key=lambda f: f[0])
        with open(path, "wb") as handle:
            writer = dpkt.pcapng.Writer(handle) if fmt == "pcapng" else dpkt.pcap.Writer(handle)
            for ts, raw in frames:
                writer.writepkt(raw, ts=ts)
            writer.close()


def plant_capture():
    """The demonstration scenario. Returns a CaptureBuilder."""
    c = CaptureBuilder()
    ews, plc, hist, hmi = "10.20.1.15", "10.30.2.40", "10.30.5.10", "10.10.4.4"
    # Engineering workstation polls the controller with Modbus/TCP (initiator: workstation)
    for i in range(3):
        c.session(1 + i * 10, ews, 50000 + i, plc, 502, modbus_request(i + 1), modbus_response(i + 1))
    # Engineering workstation to controller on EtherNet/IP
    c.session(40, ews, 51000, plc, 44818, enip_register_session(), enip_register_session(response=True))
    # Historian polls the controller too, and the controller connects back to the historian on OPC UA: two directions
    c.session(45, hist, 52000, plc, 502, modbus_request(9), modbus_response(9))
    c.session(50, plc, 49500, hist, 4840, opcua_hello(), b"")
    # Corporate HMI to the historian over TLS with a server name
    c.session(55, hmi, 53000, hist, 443, tls_client_hello("historian.plant.example"), b"")
    # DNS and NTP and SNMP over UDP
    c.udp(60, ews, 40001, "10.20.1.2", 53, dns_message("ntp.plant.example"))
    c.udp(60.01, "10.20.1.2", 53, ews, 40001, dns_message("ntp.plant.example", response=True))
    c.udp(65, plc, 123, "10.30.5.1", 123, ntp_packet(3))
    c.udp(65.01, "10.30.5.1", 123, plc, 123, ntp_packet(4))
    c.udp(70, "10.20.1.50", 41000, plc, 161, snmp_get())
    c.udp(70.01, plc, 161, "10.20.1.50", 41000, snmp_get(response=True))
    # One-way syslog
    c.udp(75, plc, 514, "10.20.1.60", 514, b"<134>plc1 status ok")
    # A connection attempt with no reply: SYN only, retransmitted
    for t in (80, 81, 83):
        c.tcp(t, hmi, 54000, plc, 502, SYN, seq=900)
    # A capture that starts mid-connection: data only, no handshake
    c.tcp(2, ews, 51500, plc, 502, PSH | ACK, modbus_request(21), seq=5000, ack=7000)
    c.tcp(2.01, plc, 502, ews, 51500, PSH | ACK, modbus_response(21), seq=7000, ack=5000 + 12)
    # Port 502 carrying something that is not Modbus
    c.session(85, "10.20.1.99", 55000, "10.30.2.41", 502, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\n")
    # A service on an unknown port with an opaque payload
    c.session(90, ews, 55100, "10.30.2.99", 8888, b"\x01\x02\x03\x04\x05\x06", b"\x06\x05")
    # ICMP echo
    c.icmp(95, ews, plc, 8)
    c.icmp(95.01, plc, ews, 0)
    # IPv6 Modbus
    c.session(100, "2001:db8:20::15", 56000, "2001:db8:30::40", 502, modbus_request(5), modbus_response(5))
    # VLAN-tagged session
    c.session(105, "10.20.1.16", 57000, plc, 502, modbus_request(6), modbus_response(6), vlan=120)
    # Port reuse: the same 5-tuple twice
    c.session(110, ews, 58000, plc, 502, modbus_request(7), modbus_response(7))
    c.session(130, ews, 58000, plc, 502, modbus_request(8), modbus_response(8))
    c.arp(1)
    return c
