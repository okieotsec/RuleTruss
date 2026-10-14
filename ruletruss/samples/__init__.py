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


def create_unifi(service):
    """A synthetic UniFi gateway export (zones, predefined and custom policies), imported through the normal path, with the demo capture
    so Compare has traffic to judge. Nothing in it is a real network."""
    project = service.store.create_project("UniFi gateway (synthetic example)")
    pid = project["id"]
    with tempfile.TemporaryDirectory() as work:
        capture = os.path.join(work, "home-lab.pcapng")
        unifi_capture().write(capture, "pcapng")
        for path, name, point in ((capture, "home-lab-span.pcapng", "SPAN of the gateway's LAN port (fictional)"),
                                  (os.path.join(HERE, "unifi_export.json"), "unifi-export.json", "")):
            upload = service.store.new_upload_path(pid)
            with open(path, "rb") as src, open(upload, "wb") as dst:
                dst.write(src.read())
            service.import_upload(pid, upload, name, point)
    service.store.update_context(pid, subnets=UNIFI_SUBNETS, labels=UNIFI_LABELS, groups=[],
                                 notes="Fictional. Both the capture and the export are invented; the export follows the published UniFi API schema.")
    return service.store.get_project(pid)


UNIFI_SUBNETS = [{"cidr": "192.168.1.0/24", "label": "Default LAN", "zone": "Internal"},
                 {"cidr": "10.10.10.0/24", "label": "Servers", "zone": "Internal"},
                 {"cidr": "192.168.20.0/24", "label": "IoT", "zone": "IoT"}, {"cidr": "172.16.50.0/24", "label": "DMZ", "zone": "DMZ"}]
UNIFI_LABELS = {"192.168.1.10": "Admin PC", "192.168.1.50": "Laptop", "10.10.10.5": "NAS", "10.10.10.9": "File server", "192.168.20.31": "Camera",
                "192.168.20.32": "Smart TV", "172.16.50.10": "Public web server"}


def unifi_capture():
    """Traffic inside the networks of the synthetic UniFi export, so Compare has something to judge. Invented, like everything here."""
    from .. import synthetic as s
    c, port = s.CaptureBuilder(), iter(range(41000, 42000))
    c.session(1, "192.168.1.50", next(port), "172.16.50.10", 443, s.tls_client_hello("www.example.test"), b"")            # allowed: Web to DMZ
    c.session(5, "192.168.1.50", next(port), "172.16.50.10", 22, s.ssh_banner("OpenSSH_9.2"), s.ssh_banner())            # no policy names this
    c.session(9, "192.168.1.10", next(port), "192.168.20.31", 80, s.http_get("/", "camera"), s.http_ok_server("CamWeb/1.0"))   # Admins to IoT
    c.session(14, "192.168.20.31", next(port), "10.10.10.5", 443, s.tls_client_hello("nas.example.test"), b"")             # IoT to NAS web
    for k in range(3):                                                                                                      # the camera is blocked from the file server
        c.tcp(20 + k, "192.168.20.31", 52000, "10.10.10.9", 445, s.SYN, seq=5)
    c.udp(30, "192.168.20.32", next(port), "8.8.8.8", 53, s.dns_message("time.example.test"))                              # IoT DNS only
    c.udp(30.02, "8.8.8.8", 53, "192.168.20.32", 41999, s.dns_message("time.example.test", response=True))
    c.session(35, "192.168.20.32", next(port), "198.51.100.7", 443, s.tls_client_hello("cloud.camera-vendor.example"), b"")   # a domain policy
    for k in range(2):
        c.tcp(40 + k, "192.168.20.32", 53000, "198.51.100.7", 8883, s.SYN, seq=6)                                           # blocked: the rest
    for k in range(2):
        c.tcp(45 + k, "203.0.113.9", 54000, "192.168.1.50", 22, s.SYN, seq=7)                                               # from outside
    c.session(50, "192.168.1.50", next(port), "198.51.100.7", 443, s.tls_client_hello("updates.example.test"), b"")        # ordinary browsing
    c.session(55, "192.168.1.50", next(port), "10.10.10.5", 443, s.tls_client_hello("nas.example.test"), b"")             # the all-states block drops its replies
    return c


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
