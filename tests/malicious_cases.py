"""Hostile and malformed inputs for security testing. Everything is generated; nothing here is real data."""
import os
import struct

from ruletruss.synthetic import CaptureBuilder, dns_message, modbus_request, modbus_response

ASA_HEAD = "interface Gi0/0\n nameif a\n security-level 1\n"


def _ace_lines(n):
    return "".join(f"access-list A extended permit tcp host 10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255} any eq 80\n" for i in range(n))


def configs():
    """name -> bytes"""
    cases = {
        "empty": b"",
        "whitespace": b" \n\t\n" * 100,
        "nul_bytes": b"hostname x\x00\naccess-list A extended permit ip any any\n",
        "utf16": "hostname x\naccess-list A extended permit ip any any\n".encode("utf-16"),
        "latin1": b"hostname caf\xe9\naccess-list A extended permit ip any any\naccess-group A in interface a\n",
        "binary_junk": os.urandom(5000),
        "one_huge_line": b"access-list A extended permit tcp " + b"A" * (5 * 1024 * 1024) + b"\n",
        "unterminated_quote_forti": b"config firewall policy\n edit 1\n set name 'never closed\n set srcintf \"a\n next\nend\n",
        "unbalanced_forti": b"end\nend\nnext\nnext\nconfig firewall policy\n edit 1\n edit 2\n config x\n",
        "forti_nested_config": b"config firewall policy\n" + b"config x\n" * 2000 + b"end\n" * 2000,
        "xml_billion_laughs": (b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
                               b'<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><pfsense>&lol3;</pfsense>'),
        "xml_external_entity": b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><pfsense>&xxe;</pfsense>',
        "xml_deep_nesting": b"<pfsense>" + b"<a>" * 10000 + b"</a>" * 10000 + b"</pfsense>",
        "xml_unclosed": b"<pfsense><filter><rule>",
        "xml_huge_attribute": b'<config version="' + b"A" * 3_000_000 + b'"><devices/></config>',
        "xml_wrong_root": b"<html><body>hi</body></html>",
        "asa_group_cycle": (ASA_HEAD + "object-group network A\n group-object B\nobject-group network B\n group-object A\n"
                            "access-list X extended permit ip object-group A any\naccess-group X in interface a\n").encode(),
        "asa_group_chain_5000": (ASA_HEAD + "".join(f"object-group network G{i}\n group-object G{i + 1}\n" for i in range(5000))
                                 + "object-group network G5000\n network-object host 10.0.0.1\n"
                                 "access-list X extended permit ip object-group G0 any\naccess-group X in interface a\n").encode(),
        "asa_group_exponential": (ASA_HEAD + "object-group network L0\n network-object host 10.0.0.1\n"
                                  + "".join(f"object-group network L{i + 1}\n group-object L{i}\n group-object L{i}\n" for i in range(40))
                                  + "access-list X extended permit ip object-group L40 any\naccess-group X in interface a\n").encode(),
        "asa_100k_rules": (ASA_HEAD + _ace_lines(100_000) + "access-group A in interface a\n").encode(),
        "asa_over_line_limit": (ASA_HEAD + _ace_lines(410_000)).encode(),
        "asa_weird_tokens": (ASA_HEAD + "access-list A extended permit tcp any any eq \naccess-list A extended permit\n"
                             "access-list A extended permit tcp 999.1.1.1 255.255.255.0 any\naccess-list A extended permit object\n"
                             "access-list A extended permit ip any any range 100 1\naccess-list A extended permit ip any any eq 99999\n"
                             "access-group A in interface\naccess-group in\n").encode(),
        "ios_weird_wildcards": b"ip access-list extended X\n permit ip 10.0.0.0 0.255.0.255 any\n permit ip 1.2.3.4 255.0.0.0 any\n"
                               b" permit tcp any any range 0 70000\n permit udp host any any\n",
        "pan_cycle": (b'<config version="10"><devices><entry name="l"><vsys><entry name="vsys1"><address-group>'
                      b'<entry name="a"><static><member>b</member></static></entry><entry name="b"><static><member>a</member></static></entry>'
                      b'</address-group><rulebase><security><rules><entry name="r"><from><member>any</member></from><to><member>any</member></to>'
                      b'<source><member>a</member></source><destination><member>any</member></destination><service><member>any</member></service>'
                      b'<action>allow</action></entry></rules></security></rulebase></entry></vsys></entry></devices></config>'),
        "pan_many_rules": (b'<config version="10"><devices><entry name="l"><vsys><entry name="vsys1"><rulebase><security><rules>'
                           + b"".join(b'<entry name="r%d"><action>allow</action></entry>' % i for i in range(60000))
                           + b"</rules></security></rulebase></entry></vsys></entry></devices></config>"),
        "pfsense_many_aliases": (b"<pfsense><aliases>" + b"".join(b"<alias><name>a%d</name><type>host</type><address>a%d</address></alias>" % (i, i + 1)
                                                              for i in range(5000)) + b"</aliases><filter><rule><type>pass</type>"
                                 b"<source><address>a0</address></source><destination><any/></destination></rule></filter></pfsense>"),
        "csv_formula_labels": b"hostname =cmd|' /C calc'!A0\naccess-list A extended permit ip any any\n",
        "credential_dump": (b"hostname r\nenable secret 9 $9$AAAA\nusername x password 7 0822455D0A16\nsnmp-server community secretstring RO\n"
                            b"crypto isakmp key MYPSK address 1.2.3.4\ninterface Gi0/0\n ip access-group A in\nip access-list extended A\n permit ip any any\n"),
    }
    return cases


def captures(directory):
    """name -> path of a hostile capture file."""
    out = {}

    def write(name, data):
        path = os.path.join(directory, name)
        with open(path, "wb") as handle:
            handle.write(data)
        out[name] = path

    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    def record(frame, ts=1):
        return struct.pack("<IIII", ts, 0, len(frame), len(frame)) + frame

    eth = b"\x02" * 6 + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    write("random_after_magic.pcap", header + os.urandom(20000))
    write("truncated_header.pcap", header[:10])
    write("zero_length_packets.pcap", header + b"".join(record(b"") for _ in range(1000)))
    write("giant_claimed_length.pcap", header + struct.pack("<IIII", 1, 0, 0x7FFFFFFF, 0x7FFFFFFF) + b"\x00" * 64)
    write("ihl_zero.pcap", header + record(eth + b"\x40" + b"\x00" * 40))
    write("ip_length_lies.pcap", header + record(eth + b"\x45\x00\xff\xff" + b"\x00" * 4 + b"\x40\x06" + b"\x00" * 2 + bytes([10, 0, 0, 1]) + bytes([10, 0, 0, 2])
                                                 + b"\x00\x50\x01\xbb" + b"\x00" * 30))
    write("tcp_offset_garbage.pcap", header + record(eth + b"\x45\x00\x00\x30" + b"\x00" * 4 + b"\x40\x06" + b"\x00" * 2 + bytes([10, 0, 0, 1])
                                                      + bytes([10, 0, 0, 2]) + b"\x00\x50\x01\xbb" + b"\x00" * 8 + b"\xf0\x02" + b"\x00" * 20))
    write("ipv6_ext_header_chain.pcap", header + record(b"\x02" * 6 + b"\x02\x00\x00\x00\x00\x01" + b"\x86\xdd" + b"\x60\x00\x00\x00\x00\xff\x00\x40"
                                                         + b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x01" + b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x02"
                                                         + b"\x00\x00" + b"\x00" * 6 + (b"\x00\x00" + b"\x00" * 6) * 30))
    write("pcapng_bogus_block.pcapng", b"\x0a\x0d\x0d\x0a" + struct.pack("<I", 0x7FFFFFF0) + b"\x4d\x3c\x2b\x1a" + os.urandom(200))
    write("pcapng_truncated.pcapng", b"\x0a\x0d\x0d\x0a" + struct.pack("<I", 28) + b"\x4d\x3c\x2b\x1a\x01\x00\x00\x00")
    # crafted payloads inside valid TCP/UDP packets
    b = CaptureBuilder()
    b.session(0, "10.0.0.1", 40000, "10.0.0.2", 53, b"\x00\x14" + b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\xc0\x0c" * 4, b"")
    b.udp(1, "10.0.0.1", 5000, "10.0.0.2", 53, b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x0c\x00\x01\x00\x01")        # pointer loop
    b.udp(2, "10.0.0.1", 5001, "10.0.0.2", 53, b"\x12\x34\x81\x80" + b"\xff" * 200)
    b.session(3, "10.0.0.1", 41000, "10.0.0.2", 443, b"\x16\x03\x01\x40\x00\x01\x00\x3f\xff\x03\x03" + b"\x00" * 40 + b"\xff\xff" * 30, b"")
    b.session(4, "10.0.0.1", 42000, "10.0.0.2", 502, struct.pack("!HHHBB", 1, 0, 6, 1, 3) + b"\x00" * 3, b"")
    b.session(5, "10.0.0.1", 43000, "10.0.0.2", 80, b"GET " + b"/" * 3000 + b" HTTP/1.1\r\nHost: " + b"a" * 400 + b"\r\n\r\n", b"")
    b.udp(6, "10.0.0.1", 6000, "10.0.0.2", 161, b"\x30\x84\xff\xff\xff\xff\x02\x01\x01")
    b.udp(7, "10.0.0.1", 6001, "10.0.0.2", 123, b"\x1b" + b"\x00" * 47)
    b.icmp(8, "10.0.0.1", "10.0.0.2", 8)
    b.session(9, "10.0.0.1", 44000, "10.0.0.2", 22, b"SSH-2.0-" + b"\x00\xff" * 100, b"")
    path = os.path.join(directory, "crafted_payloads.pcap")
    b.write(path)
    out["crafted_payloads.pcap"] = path
    # a legitimate-looking capture with many distinct flows, to check bounded work
    many = CaptureBuilder()
    for i in range(3000):
        many.udp(i * 0.0001, f"10.{(i >> 8) & 255}.{i & 255}.1", 1024 + i % 60000, "10.9.9.9", 9000, b"x")
    p2 = os.path.join(directory, "many_flows.pcap")
    many.write(p2)
    out["many_flows.pcap"] = p2
    return out


def flow_logs():
    return {
        "zeek_binary": os.urandom(4000),
        "zeek_giant_line": b"#separator \\x09\n#fields\tts\tid.orig_h\n" + b"1\t" + b"A" * 3_000_000 + b"\n",
        "zeek_nan_and_huge": (b"#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
                              b"nan\tC1\t10.0.0.1\t1\t10.0.0.2\t2\ttcp\n1e999\tC2\t10.0.0.1\t99999999999999999999\t10.0.0.2\t2\ttcp\n"
                              b"1\tC3\tnot-an-ip\t1\t10.0.0.2\t2\ttcp\n1\tC4\t10.0.0.1\t1\t10.0.0.2\t2\tgre\n"),
        "zeek_json_deep": b'{"a":' * 5000 + b"1" + b"}" * 5000 + b"\n",
        "zeek_json_not_object": b"[1,2,3]\n\"x\"\n42\n",
        "zeek_no_header": b"a\tb\tc\n1\t2\t3\n",
    }


__all__ = ["captures", "configs", "dns_message", "flow_logs", "modbus_request", "modbus_response"]
