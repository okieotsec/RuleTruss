"""Regenerate the synthetic sample inputs in samples/. Everything is fictional and reproducible.

    .venv/bin/python tools/make_samples.py
"""
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from pbridge.synthetic import plant_capture  # noqa: E402

ZEEK = ("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes"
        "\tconn_state\thistory\torig_pkts\tresp_pkts\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tstring\tcount\tcount\n"
        "1700000000.0\tCa1\t10.20.1.15\t50000\t10.30.2.40\t502\ttcp\tmodbus\t1.5\t12\t23\tSF\tShADadFf\t6\t5\n"
        "1700000010.0\tCa2\t10.20.1.15\t50001\t10.30.2.40\t502\ttcp\tmodbus\t1.2\t12\t23\tSF\tShADadFf\t6\t5\n"
        "1700000020.0\tCa3\t10.30.2.40\t49500\t10.30.5.10\t4840\ttcp\t-\t0.4\t36\t0\tSF\tShADadFf\t5\t4\n"
        "1700000030.0\tCa4\t10.20.1.50\t41000\t10.30.2.40\t161\tudp\tsnmp\t0.1\t60\t70\tSF\tDd\t1\t1\n"
        "1700000040.0\tCa5\t10.20.1.15\t51500\t10.30.2.40\t502\ttcp\t-\t3.0\t10\t10\tOTH\tDd\t2\t2\n")


def main():
    builder = plant_capture()
    builder.write(str(ROOT / "samples" / "plant-span.pcap"), "pcap")
    builder.write(str(ROOT / "samples" / "plant-span.pcapng"), "pcapng")
    (ROOT / "samples" / "plant-conn.log").write_text(ZEEK, encoding="utf-8")
    shutil.copy(ROOT / "pbridge" / "samples" / "demo_asa.cfg", ROOT / "samples" / "configs" / "demo-plant-asa.cfg")
    for src, dst in (("asa_plant.cfg", "asa-firewall.cfg"), ("ios_ot_switch.cfg", "ios-switch-acls.cfg"), ("panos_plant.xml", "panos-firewall.xml"),
                     ("fortios_plant.conf", "fortios-firewall.conf"), ("pfsense_plant.xml", "pfsense-config.xml")):
        shutil.copy(ROOT / "tests" / "fixtures" / src, ROOT / "samples" / "configs" / dst)
    print("wrote samples/")


if __name__ == "__main__":
    main()
