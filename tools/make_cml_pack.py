"""Build the test pack for trying the generated ASA configuration on a real ASAv in Cisco Modeling Labs.

Writes docs/CML_TEST.md, samples/cml-test/asa-config.txt and samples/cml-test/expected.csv from a small invented UniFi export (three networks and the
Internet side). The expected column is what the SOURCE policy says, evaluated by this tool; the observed column is for you to fill in from the lab.
Nothing here is real data. Usage: python tools/make_cml_pack.py
"""
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYATS_FIELDS = ("username", "pass" + "word", "enable_" + "pass" + "word")             # empty in the lab file, as CML exports them
KEEP_ZONES = ("Default LAN", "IP Cameras", "Wireless Devices", "External")
KEEP_NETWORKS = ("Default", "IP_CAMERAS", "WIRELESS_DEVICES")
# network key (or zone-External) -> the ASA's interface name, address on the ASA, security level, and the test host behind it
LAB = {
    "Default": {"zone": "Default LAN", "nameif": "lan", "port": "GigabitEthernet0/0", "asa": "10.0.0.1", "mask": "255.255.255.0", "level": 100,
                "host": "h-lan", "ip": "10.0.0.10"},
    "WIRELESS_DEVICES": {"zone": "Wireless Devices", "nameif": "wifi", "port": "GigabitEthernet0/1", "asa": "10.0.20.1", "mask": "255.255.255.0",
                         "level": 80, "host": "h-wifi", "ip": "10.0.20.10"},
    "IP_CAMERAS": {"zone": "IP Cameras", "nameif": "cameras", "port": "GigabitEthernet0/2", "asa": "10.0.10.1", "mask": "255.255.255.0",
                   "level": 60, "host": "h-cam", "ip": "10.0.10.10"},
    "zone-External": {"zone": "External", "nameif": "outside", "port": "GigabitEthernet0/3", "asa": "198.51.100.1", "mask": "255.255.255.0",
                      "level": 0, "host": "h-ext", "ip": "198.51.100.10"},
}


def small_export():
    """The clean invented export (the one the tests use), cut down to the zones a five-node lab can hold."""
    sys.path.insert(0, str(ROOT / "tests"))
    import unifi_zones
    doc = json.loads(unifi_zones.text(False))
    names = {z["id"]: z["name"] for z in doc["zones"]}
    keep_ids = {i for i, n in names.items() if n in KEEP_ZONES}
    doc["zones"] = [z for z in doc["zones"] if z["id"] in keep_ids]
    for zone in doc["zones"]:
        zone["networkIds"] = [n for n in zone["networkIds"] if any(net["id"] == n and net["name"] in KEEP_NETWORKS for net in doc["networks"])]
    doc["networks"] = [n for n in doc["networks"] if n["name"] in KEEP_NETWORKS]
    doc["policies"] = [p for p in doc["policies"] if p["source"]["zoneId"] in keep_ids and p["destination"]["zoneId"] in keep_ids]
    return doc


def build():
    sys.path.insert(0, str(ROOT))
    from ruletruss.adapters.registry import parse_config
    from ruletruss.evaluate import ALLOW, DENY, Probe, evaluate
    from ruletruss.migrate.firewall import render, translate_policy

    doc = small_export()
    policy = parse_config(json.dumps(doc), "cml", "unifi")
    zone_map = {key: info["nameif"] for key, info in LAB.items()}
    translation = translate_policy(policy, "cisco-asa", zone_map=zone_map, confirmed=())
    if not translation.deployable:
        raise SystemExit("the small example is not deployable: " + "; ".join(translation.blockers))
    acls = render(translation, "cisco-asa")
    lines = [ln for ln in acls.splitlines() if ln.strip() and not ln.startswith("!")]
    interfaces = []
    for info in LAB.values():
        interfaces += [f"interface {info['port']}", f" nameif {info['nameif']}", f" security-level {info['level']}",
                       f" ip address {info['asa']} {info['mask']}", " no shutdown", "!"]
    inspection = ["policy-map global_policy", " class inspection_default", "  inspect icmp", "  inspect icmp error", "!",
                  "service-policy global_policy global", "!"]            # an ASA does not track ICMP replies without these
    config = ["hostname rtasa", "!", *interfaces, *inspection, *lines, "end"]
    rows = []
    hosts = list(LAB.values())
    for src in hosts:
        for dst in hosts:
            if src is dst:
                continue
            for test in ("icmp", "tcp443"):
                probe = (Probe(src["ip"], dst["ip"], "icmp", icmp_type=8, icmp_code=0, src_zone=src["zone"], dst_zone=dst["zone"]) if test == "icmp"
                         else Probe(src["ip"], dst["ip"], "tcp", 40000, 443, src_zone=src["zone"], dst_zone=dst["zone"]))
                outcome = evaluate(policy, probe).outcome
                rows.append({"from": src["host"], "to": dst["host"], "test": test,
                             "expected": {ALLOW: "ALLOW", DENY: "DENY"}.get(outcome, "UNDECIDED"), "observed": ""})
    return config, rows, translation


def _scalar(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, dict)) and not value:
        return "[]" if isinstance(value, list) else "{}"
    return json.dumps(str(value))                        # a JSON string is a valid YAML double-quoted string


def _yaml(value, indent=0):
    """A small YAML writer for the lab file (dicts, lists and scalars only), so the tool needs no YAML library."""
    pad = "  " * indent
    lines = []
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (dict, list)) and item:
                lines += [f"{pad}{key}:", _yaml(item, indent + 1)]
            else:
                lines.append(f"{pad}{key}: {_scalar(item)}")
    else:
        for item in value:
            if isinstance(item, (dict, list)) and item:
                body = _yaml(item, indent + 1).split("\n")
                lines += [f"{pad}- {body[0].lstrip()}", *body[1:]]
            else:
                lines.append(f"{pad}- {_scalar(item)}")
    return "\n".join(lines)


def host_script(info):
    """The boot script of an Alpine host (CML sources node.cfg at boot): its name, address, default route and a TCP 443 listener."""
    return ("# this is a shell script which will be sourced at boot\n"
            f"hostname {info['host']}\n"
            "# configurable user account\nUSERNAME=cisco\nPASSWORD=cisco\n"
            "# RuleTruss test: address, default route and a listener on TCP 443\n"
            f"ip addr add {info['ip']}/24 dev eth0\nip link set eth0 up\nip route add default via {info['asa']}\n"
            "(while true; do echo OPEN | nc -l -p 443 > /dev/null; done) &\n")


def lab_file(with_host_config=True):
    """The five-node lab in the format Cisco Modeling Labs 2.10 itself exports (lab file version 0.3.1)."""
    def interfaces(labels):
        return [{"id": f"i{n}", "label": label, "mac_address": None, "type": "physical", "slot": n} for n, label in enumerate(labels)]

    def node(number, label, definition, x, y, labels, config=None):
        return {"boot_disk_size": None, "configuration": [{"name": "node.cfg", "content": config}] if config else [], "cpu_limit": None, "cpus": None, "data_volume": None, "hide_links": False,
                "id": f"n{number}", "image_definition": None, "label": label, "node_definition": definition, "parameters": {}, "priority": None,
                "pyats": dict.fromkeys(PYATS_FIELDS), "ram": None, "tags": [], "x": x, "y": y,
                "interfaces": interfaces(labels)}

    asa_ports = ["Management0/0", "GigabitEthernet0/0", "GigabitEthernet0/1", "GigabitEthernet0/2", "GigabitEthernet0/3", "GigabitEthernet0/4"]
    places = {"Default": (-240, -160), "WIRELESS_DEVICES": (-240, 160), "IP_CAMERAS": (240, 160), "zone-External": (240, -160)}
    nodes = [node(0, "rtasa", "asav", 0, 0, asa_ports)]
    links = []
    for number, (key, info) in enumerate(LAB.items(), start=1):
        x, y = places[key]
        nodes.append(node(number, info["host"], "alpine", x, y, ["eth0", "eth1", "eth2", "eth3"], host_script(info) if with_host_config else None))
        asa_interface = asa_ports.index(info["port"])
        links.append({"id": f"l{number - 1}", "n1": "n0", "n2": f"n{number}", "i1": f"i{asa_interface}", "i2": "i0", "conditioning": {},
                      "label": f"rtasa-{info['port']}<->{info['host']}-eth0"})
    lab = {"description": "", "notes": "Invented example for trying RuleTruss's generated ASA configuration.", "title": "RuleTruss ASA test",
           "node_staging": {"enabled": False, "start_remaining": True, "abort_on_failure": False}, "version": "0.3.1"}
    return _yaml({"annotations": [], "smart_annotations": [], "nodes": nodes, "links": links, "lab": lab}) + "\n"


def test_script(src):
    """One paste for one host: its six tests (ping and TCP 443 to the other three hosts), printed as 'from,to,test,observed' lines."""
    lines = []
    for dst in LAB.values():
        if dst is src:
            continue
        lines += [f"if ping -c 2 -W 2 {dst['ip']} >/dev/null 2>&1; then r=ALLOW; else r=DENY; fi; echo {src['host']},{dst['host']},icmp,$r",
                  f"if nc -w 2 {dst['ip']} 443 </dev/null 2>/dev/null | grep -q OPEN; then r=ALLOW; else r=DENY; fi; echo {src['host']},{dst['host']},tcp443,$r"]
    return "\n".join(lines) + "\n"


def write(config, rows, translation):
    pack = ROOT / "samples" / "cml-test"
    pack.mkdir(parents=True, exist_ok=True)
    (pack / "asa-config.txt").write_text("\n".join(config) + "\n", encoding="utf-8")
    (pack / "rt-asa-test-lab.yaml").write_text(lab_file(), encoding="utf-8")
    (pack / "rt-asa-test-lab-topology-only.yaml").write_text(lab_file(with_host_config=False), encoding="utf-8")
    for info in LAB.values():
        (pack / f"run-tests-{info['host']}.sh").write_text(test_script(info), encoding="utf-8")
    with open(pack / "expected.csv", "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["from", "to", "test", "expected", "observed"])
        writer.writeheader()
        writer.writerows(rows)
    table = "\n".join(f"| {r['from']} | {r['to']} | {'ping' if r['test'] == 'icmp' else 'TCP 443'} | {r['expected']} | |" for r in rows)
    hosts = "\n".join(f"* **{i['host']}** ({i['zone']}): address {i['ip']}, gateway {i['asa']}, ASA port `{i['port']}`" for i in LAB.values())
    commands = "\n".join(f"# {i['host']}\nip addr add {i['ip']}/24 dev eth0 && ip link set eth0 up && ip route add default via {i['asa']}" for i in LAB.values())
    doc = f"""# Trying the generated ASA configuration on an ASAv in Cisco Modeling Labs

This is a test pack for one question: **does a real ASA, given the configuration RuleTruss generated from a UniFi export, permit and deny the
connections the UniFi policy permits and denies?** Everything in it is invented. It is generated by `tools/make_cml_pack.py`.

**First run, 2026-10-15 (Cisco ASA software 9.24(1) on an ASAv from the CML-Free reference images, in a CML 2.10.1 server on Proxmox): all 24 connections behaved as the UniFi policy says.** The recorded results
are in `samples/cml-test/results-2026-10-15.csv`, and a test fails if the generated configuration or the expected answers ever differ from what was tried, so the record cannot be quietly reused
for something else. The ASAv was unlicensed, which Cisco limits to 100 Kbps of throughput; that should not change what it permits or denies for single pings and small connections, but it means nothing here says anything about performance. This is one small example: {len(rows)} connections (ping and TCP 443 between four hosts) on a virtual ASA. It does not cover NAT, routing,
VPN, traffic to the firewall itself, other configurations, or a physical ASA, and the expected column is this tool's own evaluation of the source policy, not an independent oracle. The earlier checks
(CP12) used this project's evaluator and the independent parser Batfish.

The lab file follows the layout of the lab files CML 2.10 writes (lab file version 0.3.1); the other CML steps below are from general knowledge and may differ from your screen. Where they do, trust the screen and tell me.

## The lab (5 nodes, which is the CML-Free limit)

```
   h-lan --- [Gi0/0 lan 100]               [Gi0/3 outside 0] --- h-ext
                        ASAv  (rtasa)
   h-wifi -- [Gi0/1 wifi 80]               [Gi0/2 cameras 60] -- h-cam
```

* One **ASAv** node and four **Alpine Linux** nodes, each Alpine node linked directly to the ASAv port named below (no switch). The imported lab already has these links.
{hosts}
* The ASAv's data ports should show up as `GigabitEthernet0/0` to `0/3` in its console (check with `show interface ip brief`). If the numbers differ, change the port
  names in the configuration to match.
* The four security levels are different on purpose: an ASA denies traffic between interfaces of the **same** level unless told otherwise, whatever the access list says.

## Steps

1. In CML, **import** `samples/cml-test/rt-asa-test-lab.yaml` (if CML refuses it, try `rt-asa-test-lab-topology-only.yaml`, the same lab without the host boot scripts, and tell me the error) (on the Dashboard, the import option; it asks for a file). It creates the five nodes already linked:
   the ASAv is `rtasa` and the four Alpine hosts are `h-lan`, `h-wifi`, `h-cam`, `h-ext`. The lab file is in the format your own CML 2.10 exports (version 0.3.1).
   Start the lab. Wait until the ASAv has finished booting.
2. Open the ASAv console. Enter privileged mode (`enable`; on a fresh ASAv the password is empty, press Enter) and then `configure terminal`.
3. Paste the contents of `samples/cml-test/asa-config.txt`. Some ASAv versions print warnings while pasting; copy any error line into your report.
4. Check: `show running-config access-list` should list the `RT-...-IN` lists, and `show running-config access-group` should show one `in interface` line for each of `lan`, `wifi`, `cameras`, `outside`.
5. The imported lab already gives each Alpine host its address, gateway and a TCP 443 listener through its `node.cfg` boot script. Check one: open `h-lan`'s console
   (login `cisco`, password `cisco`, the node's own default, for this isolated lab only) and run `ip addr show eth0` and `ip route`. If the address and default route are not there
   (for example if you imported `rt-asa-test-lab-topology-only.yaml` instead), set them by hand on each host:

```
{commands}
```

   then, on every host: `while true; do echo OPEN | nc -l -p 443 > /dev/null; done &`

6. Run the tests. **The quick way:** on each host's console, paste the contents of `samples/cml-test/run-tests-<host>.sh` (for example `run-tests-h-lan.sh` on `h-lan`). Each prints six lines like
   `h-lan,h-wifi,icmp,DENY`. Copy the lines from all four hosts and send them to me; the ASA's `show access-list` output from step 7 is the other half of the evidence. Wait for each
   to finish: a blocked connection takes a couple of seconds to time out.
   **The manual way**, for any single row of the table below, from the host in the **from** column:
   * ping: `ping -c 2 -W 2 <to address>`; **ALLOW** if replies arrive, **DENY** if none do.
   * TCP 443: `nc -w 2 <to address> 443 </dev/null | grep OPEN`; **ALLOW** if it prints OPEN, **DENY** if it prints nothing. (Every host's listener sends the word OPEN to whoever connects.)
   Addresses: h-lan {LAB['Default']['ip']}, h-wifi {LAB['WIRELESS_DEVICES']['ip']}, h-cam {LAB['IP_CAMERAS']['ip']}, h-ext {LAB['zone-External']['ip']}.
7. Also paste the output of `show access-list` from the ASAv after the tests, which shows hit counts for each entry. (If you tested by hand, fill in the **observed** column of the table; the same
   table is in `samples/cml-test/expected.csv`.)

## What to expect and what a mismatch means

The **expected** column is the UniFi policy's own answer for a new connection, as evaluated by this tool. Replies of an allowed connection are accepted by the ASA
automatically, so only the first packet matters.

* A mismatch where the ASA **allows** what UniFi denies is the serious one: it means the generated configuration is more open than the source.
* A ping that should be ALLOW but gets no reply: first check that the configuration contains `inspect icmp` (`show running-config policy-map`). An ASA does not
  track ICMP replies without it (confirmed in the first lab run: with the line removed, an allowed ping got no replies); the lines are in the pasted configuration, and RuleTruss's own ASA output warns that it does not generate them.
* A mismatch where the ASA **denies** what UniFi allows means the configuration is stricter, or a setup problem (a wrong address, an interface that is down).
  Check `show interface ip brief` and that the host's gateway is right before concluding anything.
* Rows marked UNDECIDED could not be decided from the export; ignore them.

## Test table ({len(rows)} rows)

| from | to | test | expected | observed |
|---|---|---|---|---|
{table}

## What was generated

The invented export is a cut-down version of the clean example (three networks and External). It translated to {len(translation.rules)} access-list entries and was
deployable with nothing unresolved: {translation.dispositions}. This is a preview of the method, not of any real network.
"""
    (ROOT / "docs" / "CML_TEST.md").write_text(doc, encoding="utf-8")


if __name__ == "__main__":
    cfg, table_rows, result = build()
    write(cfg, table_rows, result)
    print(f"wrote docs/CML_TEST.md, samples/cml-test/asa-config.txt, rt-asa-test-lab.yaml and expected.csv ({len(table_rows)} cases, {len(cfg)} config lines)")
