"""A synthetic demonstration project: a fictional plant, one capture and one firewall export. Nothing here is real."""
import os
import tempfile

from ..synthetic import plant_capture

HERE = os.path.dirname(os.path.abspath(__file__))
SUBNETS = [
    {"cidr": "10.20.0.0/16", "label": "Engineering", "zone": "eng"},
    {"cidr": "10.30.2.0/24", "label": "Controllers", "zone": "plc"},
    {"cidr": "10.30.5.0/24", "label": "Historian and services", "zone": "hist"},
    {"cidr": "10.10.0.0/16", "label": "Corporate", "zone": "corp"},
]
LABELS = {"10.20.1.15": "Engineering workstation", "10.30.2.40": "PLC-1", "10.30.5.10": "Historian", "10.10.4.4": "Corporate HMI",
          "10.30.5.1": "Time server", "10.20.1.50": "Network monitor"}
GROUPS = [
    {"name": "Engineering", "members": ["10.20.0.0/16"]},
    {"name": "Controllers", "members": ["10.30.2.0/24"], "gateway_isolated": True},
    {"name": "Historian", "members": ["10.30.5.10"]},
    {"name": "Services", "members": ["10.30.5.1"]},
    {"name": "Corporate", "members": ["10.10.0.0/16"]},
]


def create_demo(service):
    """Create the demo project through the same import path a real upload takes."""
    project = service.store.create_project("Sample plant (synthetic)")
    pid = project["id"]
    with tempfile.TemporaryDirectory() as work:
        capture = os.path.join(work, "plant.pcapng")
        plant_capture().write(capture, "pcapng")
        for path, name, point in ((capture, "plant-span.pcapng", "SPAN of the controller-facing switch ports (fictional)"),
                                  (os.path.join(HERE, "demo_asa.cfg"), "demo-asa.cfg", "")):
            upload = service.store.new_upload_path(pid)
            with open(path, "rb") as src, open(upload, "wb") as dst:
                dst.write(src.read())
            service.import_upload(pid, upload, name, point)
    service.store.update_context(pid, subnets=SUBNETS, labels=LABELS, groups=GROUPS)
    return service.store.get_project(pid)


def riverbend_files():
    """name -> bytes for every Riverbend file (generated, nothing is stored in the package)."""
    from .. import riverbend
    from ..riverbend_configs import configs
    with tempfile.TemporaryDirectory() as work:
        out = {}
        captures = (("ops-field-span.pcapng", riverbend.ops_field_capture, "pcapng"), ("dmz-tap.pcap", riverbend.dmz_tap_capture, "pcap"),
                    ("cell-switch-late-start.pcapng", riverbend.midstream_capture, "pcapng"))
        for name, builder, fmt in captures:
            path = os.path.join(work, name)
            builder().write(path, fmt)
            with open(path, "rb") as handle:
                out[name] = handle.read()
        out["corp-edge-conn.log"] = riverbend.corp_edge_zeek_log().encode("utf-8")
        for name, text in configs().items():
            out[name] = text.encode("utf-8")
    return out


RIVERBEND_POINTS = {
    "ops-field-span.pcapng": "SPAN of the trunk between operations and the field cells (fictional)",
    "dmz-tap.pcap": "Tap on the DMZ firewall links (fictional)",
    "cell-switch-late-start.pcapng": "Laptop on a cell switch port, started late (fictional)",
    "corp-edge-conn.log": "Zeek at the corporate edge (fictional)",
}


def create_riverbend(service):
    """The larger Riverbend example, imported through the same path as a real upload."""
    from .. import riverbend
    project = service.store.create_project("Riverbend Water Treatment (synthetic example)")
    pid = project["id"]
    for name, data in riverbend_files().items():
        upload = service.store.new_upload_path(pid)
        with open(upload, "wb") as handle:
            handle.write(data)
        service.import_upload(pid, upload, name, RIVERBEND_POINTS.get(name, ""))
    ctx = riverbend.context()
    service.store.update_context(pid, subnets=ctx["subnets"], labels=ctx["labels"], groups=ctx["groups"],
                                 notes="Fictional. See samples/riverbend/GUIDE.md for what each file is meant to show.")
    return service.store.get_project(pid)
