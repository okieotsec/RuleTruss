"""MAC addresses, the OUI registry snapshot and passive device identification."""
import os
import tempfile
import unittest

from ruletruss import devices, oui
from ruletruss import synthetic as s
from ruletruss.capture import fingerprint as fp
from ruletruss.capture.flows import analyze_capture_full
from ruletruss.model import to_plain
from ruletruss.samples import vendor_names
from ruletruss.service import Service
from ruletruss.store import Store

SWITCH, PLC_A, PLC_B, ROUTER = "00:00:0c:00:00:02", "00:00:0c:00:00:21", "00:00:0c:00:00:22", "00:00:0c:00:00:fe"
RANDOMISED = "02:11:22:33:44:55"
REMOTE = ("10.20.0.10", "10.20.0.11", "10.20.0.12")


def scenario():
    """One cell switch: two PLCs and a switch with real-looking MACs, three remote hosts that arrive via the router."""
    c = s.CaptureBuilder()
    c.segment(["10.30.2.0/24"], {"10.30.2.21": PLC_A, "10.30.2.22": PLC_B, "10.30.2.2": SWITCH}, ROUTER)
    c.arp_message(1, 2, "10.30.2.21", "10.30.2.2")
    c.lldp(2, SWITCH, "cell2-sw1", "Acme managed switch, firmware 1.2", management_ip="10.30.2.2")
    c.session(10, REMOTE[0], 50001, "10.30.2.22", 80, s.http_get("/", "10.30.2.22"), s.http_ok_server("PlcWeb/2.1"))
    c.session(20, REMOTE[1], 50002, "10.30.2.22", 502, b"", s.modbus_device_identification({0: "Acme", 4: "Pump controller", 2: "V3.1"}))
    c.session(30, REMOTE[2], 50003, "10.30.2.21", 22, s.ssh_banner("OpenSSH_9.2"), s.ssh_banner("dropbear_2022.83"))
    c.udp(40, REMOTE[0], 41000, "10.30.2.22", 161, s.snmp_get())
    c.udp(40.01, "10.30.2.22", 161, REMOTE[0], 41000, s.snmp_description_response("Acme PLC fw 3.1", "plc-b"))
    c.udp(50, "10.30.2.21", 44818, "10.30.2.255", 44818, s.enip_list_identity_reply("1756-L83E/B", vendor=1))
    c.udp(60, "0.0.0.0", 68, "255.255.255.255", 67, s.dhcp_discover(RANDOMISED, "laptop-7", "MSFT 5.0"))  # noqa: S104 - a packet source address in generated data, not a bind
    return c


class OuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        cls.path = vendor_names.install(os.path.join(cls.dir.name, "names.tsv.gz"), {"70B3D5100": "Example Small Maker", "70B3D5": "Example Block Owner"})
        cls.registry = oui.Registry(cls.path)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def test_longest_prefix_wins_and_names_the_registry(self):
        # the sample builder files every row as MA-L; give the longer prefixes their own registry through the builder's row format
        from ruletruss import oui_build
        path = os.path.join(self.dir.name, "long.tsv.gz")
        oui_build.write({"70B3D5": ("MA-L", "Example Block Owner"), "70B3D5100": ("MA-S", "Example Small Maker")}, path)
        registry = oui.Registry(path)
        hit = registry.lookup("70:b3:d5:10:0a:bc")
        self.assertEqual((hit["registry"], hit["prefix"], hit["vendor"]), ("MA-S", "70B3D5100", "Example Small Maker"))
        self.assertEqual(registry.lookup("70:b3:d5:20:00:01")["vendor"], "Example Block Owner")
        self.assertIsNone(registry.lookup("70:b3:d6:20:00:01"))

    def test_formats_and_non_devices(self):
        self.assertEqual(oui.normalize_mac("00-00-0C-12-34-56"), "00:00:0c:12:34:56")
        self.assertEqual(oui.normalize_mac("0000.0c12.3456"), "00:00:0c:12:34:56")
        self.assertIsNone(oui.normalize_mac("00:00:0c"))
        self.assertIsNone(oui.normalize_mac(b"\x00" * 5))
        self.assertEqual(oui.mac_kind("ff:ff:ff:ff:ff:ff"), "broadcast")
        self.assertEqual(oui.mac_kind("01:00:5e:00:00:01"), "multicast")
        self.assertEqual(oui.mac_kind(RANDOMISED), "local")

    def test_randomised_and_group_addresses_get_no_vendor(self):
        self.assertIsNone(self.registry.lookup(RANDOMISED))
        self.assertIsNone(self.registry.lookup("01:00:5e:00:00:01"))
        self.assertIn("randomised", self.registry.describe(RANDOMISED))
        self.assertIn("not a device", self.registry.describe("ff:ff:ff:ff:ff:ff"))

    def test_without_names_everything_still_works(self):
        self.assertFalse(oui.NO_NAMES.available())
        self.assertIsNone(oui.NO_NAMES.lookup("00:00:0c:00:00:01"))
        self.assertEqual(oui.NO_NAMES.describe("00:00:0c:00:00:01"), "vendor names are not loaded")
        self.assertFalse(oui.NO_NAMES.info()["available"])

    def test_the_snapshot_states_its_date(self):
        info = self.registry.info()
        self.assertTrue(info["available"])
        self.assertRegex(info["retrieved"], r"^\d{4}-\d\d-\d\d$")


class DecoderTests(unittest.TestCase):
    def test_every_prefix_of_every_message_is_handled(self):
        """A message cut anywhere must give a result or None, never an exception."""
        c = scenario()
        lldp = next(raw for _, raw in c.frames if raw[12:14] == b"\x88\xcc")[14:]
        messages = {
            fp.parse_lldp: lldp, fp.parse_dhcp: s.dhcp_discover(RANDOMISED, "host", "vendor"),
            fp.parse_enip_identity: s.enip_list_identity_reply("name"), fp.parse_snmp_response: s.snmp_description_response("d", "n"),
            fp.parse_modbus_device_id: s.modbus_device_identification({0: "a", 4: "b"}), fp.http_headers: s.http_ok_server("x"),
            fp.ssh_banner: s.ssh_banner(),
        }
        for decoder, data in messages.items():
            self.assertTrue(decoder(data), decoder.__name__)
            for n in range(len(data)):
                decoder(data[:n])

    def test_random_bytes_do_not_raise(self):
        value = 12345
        for _ in range(400):
            blob = bytearray()
            for _ in range(80):
                value = (value * 1103515245 + 12345) & 0x7FFFFFFF
                blob.append(value >> 16 & 0xFF)
            for decoder in (fp.parse_lldp, fp.parse_dhcp, fp.parse_enip_identity, fp.parse_snmp_response, fp.parse_modbus_device_id,
                            fp.http_headers, fp.ssh_banner):
                decoder(bytes(blob))

    def test_text_is_plain_bounded_ascii(self):
        raw = b"\x1b[31mred\x00\x07 name\xe2\x82\xac\r\n" + b"A" * 500
        out = fp.text(raw)
        self.assertTrue(out.isascii() and out.isprintable())
        self.assertLessEqual(len(out), fp.TEXT_LIMIT)
        self.assertNotIn("\x1b", out)

    def test_the_snmp_community_is_never_kept(self):
        info = fp.parse_snmp_response(s.snmp_description_response("Acme PLC", "plc-b", community="s3cret-community"))
        self.assertEqual(info["description"], "Acme PLC")
        self.assertNotIn("s3cret", repr(info))

    def test_enip_identity_fields(self):
        info = fp.parse_enip_identity(s.enip_list_identity_reply("1756-L83E/B", vendor=1, device_type=0x0E, product_code=166,
                                                                 revision=(32, 11), serial=0xABCD))
        self.assertIn("1756-L83E/B", info["value"])
        self.assertIn("Rockwell Automation", info["value"])
        self.assertIn("PLC", info["value"])
        self.assertIn("revision 32.11", info["value"])
        self.assertIsNone(fp.parse_enip_identity(s.enip_list_identity()))          # a request carries no identity
        self.assertIsNone(fp.parse_enip_identity(s.enip_list_identity_reply()))    # the all-zero legacy item is not an identity

    def test_initial_ttl_buckets(self):
        self.assertEqual([fp.initial_ttl(t) for t in (1, 32, 33, 60, 64, 65, 120, 128, 129, 250)], [32, 32, 64, 64, 64, 128, 128, 128, 255, 255])

    def test_http_server_versus_user_agent(self):
        self.assertEqual(fp.http_headers(s.http_ok_server("PlcWeb/2.1")), ("response", "PlcWeb/2.1"))
        self.assertEqual(fp.http_headers(s.http_get("/", "h")), ("request", "Windows-Update-Agent"))
        self.assertIsNone(fp.http_headers(b"POST /x HTTP/1.1\r\nHost: h\r\n\r\n"))
        self.assertIsNone(fp.http_headers(b"hello"))


class TrackerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        path = os.path.join(cls.dir.name, "cell.pcap")
        scenario().write(path)
        cls.info, cls.flows, cls.facts = analyze_capture_full(path, "c", "s", "cell.pcap")
        ips = sorted({ip for f in cls.flows for ip in (f.initiator, f.responder)})
        cls.registry = oui.Registry(vendor_names.install(os.path.join(cls.dir.name, "names.tsv.gz")))
        cls.built = devices.build(to_plain(cls.facts), ips, cls.registry)
        cls.devs = cls.built["devices"]

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def test_arp_confirms_a_mac(self):
        row = self.devs["10.30.2.21"]
        self.assertEqual((row["mac"], row["mac_confidence"]), (PLC_A, "confirmed"))
        self.assertIn("arp", row["mac_basis"])
        self.assertEqual(row["nic_vendor"], "Example Networks Corp.")

    def test_frames_alone_are_only_probable_and_say_why(self):
        row = self.devs["10.30.2.22"]
        self.assertEqual((row["mac"], row["mac_confidence"], row["mac_basis"]), (PLC_B, "probable", "frame"))
        self.assertIn("router", row["mac_note"])

    def test_a_router_mac_is_shared_and_not_attributed(self):
        shared = {m["mac"]: m for m in self.built["shared_macs"]}
        self.assertEqual(set(shared[ROUTER]["ips"]), set(REMOTE))
        for ip in REMOTE:
            self.assertEqual(self.devs[ip]["mac"], "", ip)
        self.assertEqual(shared[ROUTER]["nic_vendor"], "Example Networks Corp.")        # the card's maker is still shown for the shared MAC

    def test_lldp_names_the_switch_and_binds_its_management_address(self):
        row = self.devs["10.30.2.2"]
        self.assertEqual(row["mac"], SWITCH)
        kinds = {i["kind"]: i for i in row["identity"]}
        self.assertEqual(kinds["lldp-name"]["value"], "cell2-sw1")
        self.assertEqual(kinds["lldp-name"]["type"], "self-reported")
        self.assertEqual(row["identity_short"], "Acme managed switch, firmware 1.2")

    def test_self_reported_identity_from_protocols(self):
        by_kind = {i["kind"]: i["value"] for ip in ("10.30.2.21", "10.30.2.22") for i in self.devs[ip]["identity"]}
        self.assertIn("1756-L83E/B", by_kind["enip-identity"])
        self.assertEqual(by_kind["snmp-sysdescr"], "Acme PLC fw 3.1")
        self.assertEqual(by_kind["snmp-sysname"], "plc-b")
        self.assertEqual(by_kind["modbus-identity"], "Pump controller (Acme; revision V3.1)")
        self.assertEqual(by_kind["http-server"], "PlcWeb/2.1")
        self.assertTrue(by_kind["ssh-banner"].startswith("SSH-2.0-"))

    def test_identity_is_ordered_with_the_strongest_first_and_hints_apart(self):
        row = self.devs["10.30.2.22"]
        self.assertEqual(row["identity"][0]["kind"], "modbus-identity")
        self.assertTrue(row["hint"].startswith("initial TTL probably 64"))
        self.assertNotIn("TTL", row["identity_short"])
        self.assertEqual(next(i for i in row["identity"] if i["kind"] == "ttl-hint")["type"], "weak-hint")

    def test_a_randomised_mac_with_no_ip_is_listed_apart_with_its_hostname(self):
        entry = next(d for d in self.built["l2_only"] if d["mac"] == RANDOMISED)
        self.assertEqual(entry["mac_kind"], "local")
        self.assertEqual(entry["nic_vendor"], "")
        self.assertEqual({i["kind"]: i["value"] for i in entry["identity"]}, {"dhcp-hostname": "laptop-7", "dhcp-vendor-class": "MSFT 5.0"})

    def test_every_observation_points_at_packets(self):
        for o in self.facts.observations:
            self.assertTrue(o.evidence and o.evidence[0].ref, o.kind)


class HostileFrameTests(unittest.TestCase):
    """A capture full of broken layer-2 frames is read to the end, and nothing from it can inject anything."""

    def test_malformed_arp_lldp_and_forged_text_do_not_stop_the_reader(self):
        import struct

        import dpkt
        c = s.CaptureBuilder()
        c.segment(["10.0.0.0/24"], {"10.0.0.5": "00:00:0c:00:00:05"})
        good = bytes(dpkt.ethernet.Ethernet(dst=b"\xff" * 6, src=bytes.fromhex("00000c000009"), type=0x0806,
                                            data=dpkt.arp.ARP(sha=bytes.fromhex("00000c000009"), spa=bytes([10, 0, 0, 9]),
                                                              tha=b"\x00" * 6, tpa=bytes([10, 0, 0, 1]))))
        c.frames += [(c.start + 1, good[:30]), (c.start + 2, good[:14] + b"\x00\x01\x08\x00\x06\x04"),
                     (c.start + 3, bytes.fromhex("0180c200000e00000c000007") + b"\x88\xcc" + b"\x02\x07\x04" + b"\xff" * 5),
                     (c.start + 4, bytes.fromhex("0180c200000e00000c000007") + b"\x88\xcc" + struct.pack("!H", 5 << 9 | 4) + b"\x1b[2J" + b"\x00\x00"),
                     (c.start + 5, bytes.fromhex("ffffffffffff") + b"\xff" * 6 + b"\x08\x06" + b"\x00" * 28)]   # a broadcast source MAC
        c.lldp(6, "00:00:0c:00:00:07", "sw\x1b[31m\u202e;=cmd|' /C calc'!A0", "d" * 600)
        c.session(7, "10.0.0.5", 1000, "10.0.0.6", 80, b"GET / HTTP/1.1\r\nUser-Agent: " + b"A" * 9000 + b"\r\n\r\n", b"")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bad.pcap")
            c.write(path)
            info, flows, facts = analyze_capture_full(path, "c", "s", "bad.pcap")
        self.assertEqual(info.packets_read, len(c.frames))
        self.assertNotIn("ff:ff:ff:ff:ff:ff", [x.mac for x in facts.l2_senders] + [b.mac for b in facts.bindings])
        for o in facts.observations:
            self.assertTrue(o.value.isascii() and o.value.isprintable() and len(o.value) <= fp.TEXT_LIMIT, o.value)
        self.assertTrue(any("cmd" in o.value for o in facts.observations))        # kept as harmless text; the export neutralises it


class AttributionTests(unittest.TestCase):
    def build(self, bindings, observations=()):
        facts = {"bindings": [{"mac": m, "ip": ip, "basis": b, "packets": n, "evidence": []} for m, ip, b, n in bindings],
                 "l2_senders": [], "observations": list(observations), "limits_hit": []}
        return devices.build(facts, sorted({b[1] for b in bindings}))

    def test_one_ip_with_two_macs_keeps_the_stronger_and_lists_the_other(self):
        built = self.build([("00:00:0c:00:00:01", "10.0.0.5", "frame", 50), ("00:00:0c:00:00:02", "10.0.0.5", "arp", 2)])
        row = built["devices"]["10.0.0.5"]
        self.assertEqual((row["mac"], row["mac_confidence"]), ("00:00:0c:00:00:02", "confirmed"))
        self.assertEqual(row["other_macs"], ["00:00:0c:00:00:01"])

    def test_one_mac_with_two_ips_is_shared_unless_arp_confirmed(self):
        built = self.build([("00:00:0c:00:00:01", "10.0.0.5", "arp", 3), ("00:00:0c:00:00:01", "10.0.0.6", "frame", 9)])
        self.assertEqual(built["devices"]["10.0.0.5"]["mac"], "00:00:0c:00:00:01")
        self.assertEqual(built["devices"]["10.0.0.6"]["mac"], "")
        self.assertEqual(built["shared_macs"][0]["confirmed_ips"], ["10.0.0.5"])

    def test_merging_captures_adds_counts_and_keeps_one_observation(self):
        one = {"bindings": [{"mac": "00:00:0c:00:00:01", "ip": "10.0.0.5", "basis": "frame", "packets": 3, "evidence": []}],
               "l2_senders": [{"mac": "00:00:0c:00:00:09", "frames": 2, "kinds": ["lldp"], "evidence": []}],
               "observations": [{"kind": "ssh-banner", "value": "SSH-2.0-x", "confidence": "confirmed", "ip": "10.0.0.5", "mac": ""}],
               "limits_hit": ["a"]}
        merged = devices.merge([one, one])
        self.assertEqual(merged["bindings"][0]["packets"], 6)
        self.assertEqual(merged["l2_senders"][0]["frames"], 4)
        self.assertEqual(len(merged["observations"]), 1)
        self.assertEqual(merged["limits_hit"], ["a"])


class LimitTests(unittest.TestCase):
    def test_the_tracker_stops_recording_at_its_limit_and_says_so(self):
        tracker = fp.DeviceTracker("s", max_items=3)
        for i in range(10):
            tracker._bind(i, f"00:00:0c:00:00:{i:02x}", f"10.0.0.{i + 1}", "frame")
        facts = tracker.facts()
        self.assertEqual(len(facts.bindings), 3)
        self.assertTrue(facts.limits_hit)


class ServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        cls.service = Service(Store(os.path.join(cls.dir.name, "data")))
        cls.pid = cls.service.store.create_project("devices")["id"]
        path = os.path.join(cls.dir.name, "cell.pcap")
        scenario().write(path)
        upload = cls.service.store.new_upload_path(cls.pid)
        with open(path, "rb") as src, open(upload, "wb") as dst:
            dst.write(src.read())
        cls.service.import_upload(cls.pid, upload, "cell.pcap")
        vendor_names.install(cls.service.vendor_path)
        cls.overview = cls.service.overview(cls.pid)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def test_the_inventory_carries_mac_vendor_and_identity(self):
        rows = {d["ip"]: d for d in self.overview["inventory"]["devices"]}
        self.assertEqual(rows["10.30.2.21"]["mac"], PLC_A)
        self.assertEqual(rows["10.30.2.21"]["mac_confidence"], "confirmed")
        self.assertTrue(rows["10.30.2.21"]["nic_vendor"])
        self.assertEqual(rows["10.30.2.22"]["mac_confidence"], "probable")

    def test_a_device_seen_only_in_lldp_still_gets_a_row(self):
        rows = {d["ip"]: d for d in self.overview["inventory"]["devices"]}
        self.assertTrue(rows["10.30.2.2"]["seen_without_flows"])
        self.assertEqual(rows["10.30.2.2"]["initiated_flows"], 0)

    def test_the_extras_report_shared_macs_and_the_registry_date(self):
        extras = self.overview["device_extras"]
        self.assertEqual([m["mac"] for m in extras["shared_macs"]], [ROUTER])
        self.assertTrue(extras["snapshot"]["retrieved"])
        self.assertTrue(extras["caution"])

    def test_exports_are_safe_and_labelled(self):
        _, name, data = self.service.export(self.pid, {"kind": "devices-csv"})
        self.assertEqual(name, "devices.csv")
        self.assertIn(PLC_A, data.decode())
        _, _, md_data = self.service.export(self.pid, {"kind": "devices-markdown"})
        self.assertIn("OBSERVED", md_data.decode())
        self.assertIn("can be wrong or forged", md_data.decode())

    def test_spreadsheet_formulas_in_identity_text_are_neutralised(self):
        rows = [{"ip": "10.0.0.1", "label": "=HYPERLINK(\"http://x\")", "mac_note": "@SUM(1)", "hint": "-2+3", "identity": []}]
        from ruletruss import exports
        text = exports.devices_csv(rows, {})
        for cell in ("'=HYPERLINK", "'@SUM(1)", "'-2+3"):
            self.assertIn(cell, text)
        self.assertNotIn(",=HYPERLINK", text)


if __name__ == "__main__":
    unittest.main()
