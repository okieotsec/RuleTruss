"""A file analysed by an older version must never be read as if it were current (found on the owner's own project: an old parse of a UniFi export made
the translation say 1 policy translated and 157 not applicable; a fresh parse says 68 and 76)."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import unifi_zones

from ruletruss import store
from ruletruss.service import Service
from ruletruss.store import Store
from ruletruss.synthetic import plant_capture

MAP = {"Default": "Gi0/0", "IP_CAMERAS": "Gi0/1", "WIRELESS_DEVICES": "Gi0/2", "SOC_SERVICES": "Gi0/3", "OT_LAB_DEVICES": "Gi0/4",
       "ISOLATION": "Gi0/5", "SANDBOX": "Gi0/6", "zone-External": "Gi0/7"}


class StaleParseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.service = Service(Store(self.tmp.name))
        self.pid = self.service.store.create_project("stale")["id"]

    def add(self, data, name):
        path = self.service.store.new_upload_path(self.pid)
        Path(path).write_bytes(data)
        return self.service.import_upload(self.pid, path, name)

    def age(self, sid, edit_parsed=None):
        """Make a stored file look like one analysed by an older version: no stamp in the project file, and the parsed data edited."""
        folder = self.service.store.source_dir(self.pid, sid)
        if edit_parsed:
            parsed_path = os.path.join(folder, "parsed.json")
            parsed = json.loads(Path(parsed_path).read_text(encoding="utf-8"))
            edit_parsed(parsed)
            Path(parsed_path).write_text(json.dumps(parsed), encoding="utf-8")
        project_path = os.path.join(self.service.store.project_dir(self.pid), "project.json")
        project = json.loads(Path(project_path).read_text(encoding="utf-8"))
        for source in project["sources"]:
            if source["id"] == sid:
                source.pop("parse_format", None)
        Path(project_path).write_text(json.dumps(project), encoding="utf-8")
        self.service.store._cache.clear()

    def translate(self, sid):
        return self.service.translation_json(self.pid, {"workflow": "preserve", "policy": sid, "target": "cisco-asa", "zone_map": MAP,
                                                        "confirm": ["gateway", "vpn"]})

    def test_a_new_import_is_stamped_and_not_stale(self):
        entry = self.add(unifi_zones.text(False).encode(), "export.json")
        self.assertEqual(entry["parse_format"], store.PARSE_FORMAT)
        self.assertFalse(self.service.project(self.pid)["sources"][0]["stale"])

    def test_an_old_parse_of_a_configuration_is_read_again_before_it_is_used(self):
        sid = self.add(unifi_zones.text(False).encode(), "export.json")["id"]
        good = self.translate(sid)["dispositions"]
        self.assertGreater(good["translated"], 10)

        def strip(parsed):                                   # what a parse from before zones kept their networks looked like
            for zone in parsed["policy"]["interfaces"].values():
                zone.pop("network_nets", None)
                zone.pop("missing_networks", None)
        self.age(sid, strip)
        self.assertTrue(self.service.project(self.pid)["sources"][0]["stale"])
        again = self.translate(sid)["dispositions"]
        self.assertEqual(again, good, "the old parse must have been replaced by a fresh one, not used")
        self.assertFalse(self.service.project(self.pid)["sources"][0]["stale"])
        parsed = json.loads(Path(os.path.join(self.service.store.source_dir(self.pid, sid), "parsed.json")).read_text(encoding="utf-8"))
        self.assertTrue(any("network_nets" in z for z in parsed["policy"]["interfaces"].values()))

    def test_a_stale_capture_is_flagged_not_silently_re_read(self):
        with tempfile.TemporaryDirectory() as work:
            path = os.path.join(work, "p.pcap")
            plant_capture().write(path, "pcap")
            sid = self.add(Path(path).read_bytes(), "p.pcap")["id"]
        self.age(sid)
        self.assertTrue(self.service.project(self.pid)["sources"][0]["stale"])

    def test_a_configuration_that_cannot_be_read_again_keeps_its_old_analysis_and_stays_marked(self):
        sid = self.add(unifi_zones.text(False).encode(), "export.json")["id"]
        self.age(sid)
        Path(self.service.store.original_path(self.pid, sid)).write_bytes(b"this is not a configuration")
        entry, policy = self.service.policy(self.service.project(self.pid), sid)
        self.assertTrue(entry["stale"])
        self.assertTrue(policy.rules)


if __name__ == "__main__":
    unittest.main()
