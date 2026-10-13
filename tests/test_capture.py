import os
import struct
import tempfile
import unittest
import warnings

from ruletruss import limits
from ruletruss.capture import appid, zeek
from ruletruss.capture.flows import analyze_capture
from ruletruss.capture.reader import UnsupportedCapture, sniff
from ruletruss.synthetic import CaptureBuilder, dns_message, modbus_request, modbus_response, plant_capture

OBS = "SPAN port on the distribution switch (test)"


class CaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        cls.results = {}
        for fmt in ("pcap", "pcapng"):
            path = os.path.join(cls.dir.name, f"plant.{fmt}")
            plant_capture().write(path, fmt)
            with warnings.catch_warnings():
                warnings.simplefilter("error")
                cls.results[fmt] = analyze_capture(path, "c1", "s1", f"plant.{fmt}", OBS)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def flow(self, fmt="pcap", **match):
        flows = [f for f in self.results[fmt][1] if all(getattr(f, k) == v for k, v in match.items())]
        self.assertEqual(len(flows), 1, f"{match} matched {len(flows)} flows")
        return flows[0]

    def test_pcap_and_pcapng_give_the_same_flows(self):
        def shape(fmt):
            return sorted((f.proto, f.initiator, f.initiator_port, f.responder, f.responder_port, f.direction_confidence,
                           f.pkts_fwd, f.pkts_rev, tuple(a.name for a in f.apps)) for f in self.results[fmt][1])
        self.assertEqual(shape("pcap"), shape("pcapng"))
        self.assertEqual(self.results["pcapng"][0].format, "pcapng")
        self.assertEqual(self.results["pcap"][0].format, "pcap")

    def test_capture_metadata_and_coverage(self):
        info = self.results["pcap"][0]
        self.assertEqual((info.packets_read, info.packets_decoded, info.packets_skipped), (110, 109, 1))
        self.assertEqual(info.observation_point, OBS)
        self.assertGreater(info.last_ts, info.first_ts)
        text = " ".join(info.coverage_notes)
        self.assertIn("not evidence of absence", text)
        self.assertIn(OBS, text)
        self.assertIn("non-IP", text)

    def test_missing_observation_point_is_stated_not_guessed(self):
        path = os.path.join(self.dir.name, "plant.pcap")
        info, _ = analyze_capture(path, "c9", "s9", "x.pcap")
        self.assertEqual(info.observation_point, "")
        self.assertIn("unknown which network segment", " ".join(info.coverage_notes))

    def test_tcp_handshake_gives_high_confidence_initiator_and_evidence(self):
        f = self.flow(initiator="10.20.1.15", initiator_port=50000, responder_port=502)
        self.assertEqual(f.direction_confidence, "high")
        self.assertIn("SYN", f.direction_basis[0])
        self.assertIn("handshake answered", " ".join(f.direction_basis))
        self.assertEqual((f.evidence[0].kind, f.evidence[0].ref.split(",")[0].isdigit()), ("packet", True))
        self.assertGreater(f.pkts_fwd, 0)
        self.assertGreater(f.pkts_rev, 0)

    def test_responses_are_not_reverse_initiation(self):
        ews_to_plc = [f for f in self.results["pcap"][1] if f.initiator == "10.20.1.15" and f.responder == "10.30.2.40"]
        self.assertTrue(ews_to_plc)
        self.assertFalse([f for f in self.results["pcap"][1]
                          if f.initiator == "10.30.2.40" and f.initiator_port == 502])

    def test_reverse_initiation_between_the_same_hosts_is_a_separate_flow(self):
        f = self.flow(initiator="10.30.2.40", responder="10.30.5.10", responder_port=4840)
        self.assertEqual(f.direction_confidence, "high")
        self.assertEqual([a.name for a in f.apps], ["OPC UA"])
        self.assertTrue(self.flow(initiator="10.30.5.10", responder="10.30.2.40", responder_port=502))

    def test_modbus_is_confirmed_from_decoding_and_the_basis_says_so(self):
        f = self.flow(initiator="10.20.1.15", initiator_port=50000, responder_port=502)
        self.assertEqual(f.apps[0].name, "Modbus/TCP")
        self.assertEqual(f.apps[0].confidence, "confirmed")
        self.assertIn("decoded Modbus/TCP header", f.apps[0].basis)
        self.assertIn("packet", f.apps[0].basis)

    def test_port_alone_is_only_possible(self):
        f = self.flow(initiator="10.10.4.4", initiator_port=54000)
        self.assertEqual([(a.name, a.confidence) for a in f.apps], [("Modbus/TCP", "possible")])
        self.assertIn("no payload was captured", f.apps[0].basis)

    def test_syn_without_reply_is_flagged(self):
        f = self.flow(initiator="10.10.4.4", initiator_port=54000)
        self.assertEqual(f.direction_confidence, "high")
        self.assertIn("no SYN-ACK", " ".join(f.notes))
        self.assertEqual(f.pkts_rev, 0)

    def test_midstream_tcp_is_not_claimed_as_proven(self):
        f = self.flow(initiator_port=51500)
        self.assertIn(f.direction_confidence, ("medium", "low"))
        self.assertIn("not proven", " ".join(f.notes))

    def test_port_502_that_is_not_modbus_is_called_out(self):
        f = self.flow(initiator="10.20.1.99")
        self.assertEqual(f.apps[0].name, "HTTP")
        self.assertNotIn("Modbus", [a.name for a in f.apps])
        self.assertIn("port number alone was not used", " ".join(f.notes))

    def test_unknown_payload_gets_no_application_guess(self):
        f = self.flow(responder_port=8888)
        self.assertEqual(f.apps, [])

    def test_udp_direction_is_never_better_than_the_evidence(self):
        syslog = self.flow(responder_port=514)
        self.assertEqual(syslog.direction_confidence, "low")
        self.assertIn("one direction", " ".join(syslog.notes))
        dns = self.flow(responder_port=53)
        self.assertEqual(dns.direction_confidence, "medium")
        self.assertEqual(dns.apps[0].name, "DNS")
        self.assertIn("ntp.plant.example", dns.apps[0].basis)

    def test_tls_server_name_is_extracted_and_sanitised(self):
        f = self.flow(responder_port=443, responder="10.30.5.10")
        self.assertIn("historian.plant.example", f.apps[0].basis)

    def test_icmp_echo(self):
        f = self.flow(proto="icmp")
        self.assertEqual((f.direction_confidence, f.initiator, f.responder), ("high", "10.20.1.15", "10.30.2.40"))

    def test_ipv6_and_vlan(self):
        f = self.flow(ip_version=6)
        self.assertEqual((f.initiator, f.responder_port), ("2001:db8:20::15", 502))
        self.assertEqual(self.flow(initiator="10.20.1.16").vlan, 120)

    def test_port_reuse_is_split_into_two_flows(self):
        flows = [f for f in self.results["pcap"][1] if f.initiator_port == 58000]
        self.assertEqual(len(flows), 2)

    def test_snmp_ntp_roles(self):
        self.assertEqual(self.flow(responder_port=161).apps[0].name, "SNMP")
        ntp = self.flow(responder_port=123)
        self.assertEqual((ntp.initiator, ntp.apps[0].confidence), ("10.30.2.40", "confirmed"))   # request and response both match


class HostileCaptureTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def write(self, name, data):
        path = os.path.join(self.dir.name, name)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def test_wrong_file_types_are_rejected_by_content_not_name(self):
        for name, data in (("a.pcap", b"not a capture at all"), ("b.pcapng", b""), ("c.pcap", b"MZ\x90\x00" * 100),
                           ("d.pcap", b"PK\x03\x04" + b"\x00" * 100)):
            with self.subTest(name=name), self.assertRaises(UnsupportedCapture):
                sniff(self.write(name, data))

    def test_pcap_renamed_is_still_read(self):
        builder = CaptureBuilder()
        builder.session(0, "10.0.0.1", 40000, "10.0.0.2", 502, modbus_request(1), modbus_response(1))
        path = os.path.join(self.dir.name, "capture.txt")
        builder.write(path)
        info, flows = analyze_capture(path, "c", "s", "capture.txt")
        self.assertEqual(len(flows), 1)
        self.assertEqual(info.format, "pcap")

    def test_truncated_capture_reports_and_keeps_earlier_packets(self):
        builder = CaptureBuilder()
        for i in range(5):
            builder.session(i, "10.0.0.1", 40000 + i, "10.0.0.2", 502, modbus_request(i), modbus_response(i))
        path = os.path.join(self.dir.name, "full.pcap")
        builder.write(path)
        with open(path, "rb") as handle:
            data = handle.read()
        short = self.write("short.pcap", data[: len(data) - 37])
        info, flows = analyze_capture(short, "c", "s", "short.pcap")
        self.assertTrue(flows)
        self.assertTrue(info.limits_hit or info.packets_read > 0)

    def test_header_only_and_garbage_body(self):
        header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        path = self.write("empty.pcap", header)
        info, flows = analyze_capture(path, "c", "s", "empty.pcap")
        self.assertEqual((info.packets_read, flows), (0, []))
        garbage = header + struct.pack("<IIII", 1, 0, 60, 60) + os.urandom(60)
        info, flows = analyze_capture(self.write("garbage.pcap", garbage), "c", "s", "garbage.pcap")
        self.assertEqual(flows, [])

    def test_absurd_packet_length_does_not_allocate_or_hang(self):
        header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        bomb = header + struct.pack("<IIII", 1, 0, 0x7FFFFFFF, 0x7FFFFFFF) + b"\x00" * 100
        _, flows = analyze_capture(self.write("bomb.pcap", bomb), "c", "s", "bomb.pcap")
        self.assertEqual(flows, [])

    def test_packet_limit_is_reported(self):
        from ruletruss.capture import reader
        builder = CaptureBuilder()
        for i in range(50):
            builder.udp(i * 0.01, "10.0.0.1", 1000 + i, "10.0.0.2", 53, dns_message("a.example"))
        path = os.path.join(self.dir.name, "many.pcap")
        builder.write(path)
        stats = reader.CaptureStats()
        packets = list(reader.iter_packets(path, stats, max_packets=10))
        self.assertEqual(len(packets), 10)
        self.assertIn("stopped after 10", " ".join(stats.limits_hit))

    def test_flow_limit_is_reported(self):
        from ruletruss.capture.flows import FlowTracker
        from ruletruss.capture.reader import CaptureStats, iter_packets
        builder = CaptureBuilder()
        for i in range(20):
            builder.udp(i * 0.01, "10.0.0.1", 1000 + i, "10.0.0.2", 9000, b"x")
        path = os.path.join(self.dir.name, "flows.pcap")
        builder.write(path)
        tracker = FlowTracker("c", "s", max_flows=5)
        for packet in iter_packets(path, CaptureStats()):
            tracker.add(packet)
        self.assertEqual(len(tracker.finish()), 5)
        self.assertEqual(tracker.dropped_flows, 15)

    def test_oversized_file_is_refused(self):
        original = limits.MAX_CAPTURE_BYTES
        limits.MAX_CAPTURE_BYTES = 10
        self.addCleanup(setattr, limits, "MAX_CAPTURE_BYTES", original)
        builder = CaptureBuilder()
        builder.udp(0, "10.0.0.1", 1, "10.0.0.2", 2, b"x")
        path = os.path.join(self.dir.name, "x.pcap")
        builder.write(path)
        with self.assertRaises(limits.LimitExceeded):
            analyze_capture(path, "c", "s", "x.pcap")


class DecoderTests(unittest.TestCase):
    def test_modbus_requires_consistent_length(self):
        good = modbus_request(1)
        self.assertTrue(appid.decode_payload("tcp", good, 40000, 502))
        self.assertFalse(appid.decode_payload("tcp", good + b"\x00", 40000, 502))   # length field no longer matches
        self.assertFalse(appid.decode_payload("tcp", b"\x00" * 12, 40000, 502))

    def test_hostile_text_is_reduced_to_printable_ascii(self):
        text = appid.safe_text(b"evil\x1b[31m\xe2\x80\xaename\x00\n<script>")
        self.assertTrue(all(32 <= ord(c) < 127 for c in text.replace("...", "")))

    def test_decoders_never_raise_on_random_bytes(self):
        import random
        rng = random.Random(7)  # noqa: S311 - a fixed seed for reproducible test data, not security
        for _ in range(3000):
            blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 200)))
            for proto in ("tcp", "udp"):
                appid.decode_payload(proto, blob, rng.randrange(65536), rng.randrange(65536))

    def test_dnp3_crc_must_be_valid(self):
        header = b"\x05\x64\x05\xc0\x01\x00\x00\x04"
        crc = appid._crc_dnp(header)
        good = header + struct.pack("<H", crc)
        self.assertEqual(appid.decode_payload("tcp", good, 1, 20000)[0].name, "DNP3")
        bad = header + struct.pack("<H", crc ^ 1)
        self.assertEqual(appid.decode_payload("tcp", bad, 1, 20000), [])


class ZeekTests(unittest.TestCase):
    TSV = ("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n"
           "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\t"
           "conn_state\thistory\torig_pkts\tresp_pkts\n"
           "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tstring\tcount\tcount\n"
           "1700000000.0\tCabc\t10.20.1.15\t50000\t10.30.2.40\t502\ttcp\tmodbus\t1.5\t12\t23\tSF\tShADadFf\t6\t5\n"
           "1700000001.0\tCdef\t10.20.1.2\t40000\t10.20.1.3\t53\tudp\tdns\t0.1\t30\t60\tSF\tDd\t1\t1\n"
           "1700000002.0\tCmid\t10.20.1.15\t51000\t10.30.2.40\t502\ttcp\t-\t3.0\t10\t10\tOTH\tDd\t2\t2\n"
           "garbage line\n")

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def write(self, text):
        path = os.path.join(self.dir.name, "conn.log")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return path

    def test_tsv_conn_log(self):
        info, flows = zeek.parse_conn_log(self.write(self.TSV), "z1", "s2", "conn.log", "tap A")
        self.assertEqual((info.format, len(flows)), ("zeek-conn", 3))
        self.assertEqual(flows[0].direction_confidence, "high")
        self.assertEqual(flows[0].apps[0].confidence, "probable")
        self.assertIn("not independently decoded", flows[0].apps[0].basis)
        self.assertEqual(flows[1].direction_confidence, "low")
        self.assertEqual(flows[2].direction_confidence, "low")
        self.assertEqual(flows[0].evidence[0].kind, "flow")
        self.assertIn("no packets or payloads", " ".join(info.coverage_notes))
        self.assertEqual(info.packets_skipped, 1)

    def test_json_conn_log_and_garbage(self):
        lines = ('{"ts":1700000000.0,"uid":"C1","id.orig_h":"10.0.0.1","id.orig_p":1234,"id.resp_h":"10.0.0.2",'
                 '"id.resp_p":80,"proto":"tcp","history":"ShAdDaFf","service":"http"}\nnot json\n[1,2]\n')
        _, flows = zeek.parse_conn_log(self.write(lines), "z2", "s3", "conn.log")
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].responder_port, 80)

    def test_tsv_without_header_and_empty_file_are_rejected(self):
        with self.assertRaises(ValueError):
            zeek.parse_conn_log(self.write("a\tb\tc\n"), "z", "s", "conn.log")
        with self.assertRaises(ValueError):
            zeek.parse_conn_log(self.write(""), "z", "s", "conn.log")


if __name__ == "__main__":
    unittest.main()


class LinkTypeTests(unittest.TestCase):
    def test_every_supported_link_type_decodes_to_the_same_connection(self):
        import dpkt

        from ruletruss.capture.reader import decode_frame
        tcp = dpkt.tcp.TCP(sport=40000, dport=502, flags=dpkt.tcp.TH_SYN, seq=1)
        ip = dpkt.ip.IP(src=bytes([10, 0, 0, 1]), dst=bytes([10, 0, 0, 2]), p=6, data=tcp)
        ip.len = len(bytes(ip))
        raw = bytes(ip)
        frames = {101: raw, 113: struct.pack("!HHH8sH", 0, 1, 6, b"\x02" * 6 + b"\0\0", 0x0800) + raw,
                  276: struct.pack("!HHIHBB8s", 0x0800, 0, 1, 1, 0, 6, b"\x02" * 6 + b"\0\0") + raw,
                  0: struct.pack("<I", 2) + raw, 108: struct.pack(">I", 2) + raw}
        for linktype, frame in frames.items():
            packet = decode_frame(1, 0.0, frame, linktype)
            self.assertEqual((packet.proto, packet.src, packet.dst, packet.dport), ("tcp", "10.0.0.1", "10.0.0.2", 502), linktype)
        with self.assertRaises(UnsupportedCapture):
            decode_frame(1, 0.0, raw, 105)       # 802.11 is not supported and says so
