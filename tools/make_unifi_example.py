"""Build ruletruss/samples/unifi_export.json (the "Load the UniFi example" project) from the schema-based test fixture.

    .venv/bin/python tools/make_unifi_example.py

The test fixture is deliberately full of awkward cases. The example keeps the instructive ones and makes the rest of the gateway behave like a
sensible one: custom zones end in a predefined default, replies are let in where a zone pair blocks by default, and one all-states block is
left as a teaching example of how a policy can drop replies. Everything is invented.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "unifi-export.json"
OUT = ROOT / "ruletruss" / "samples" / "unifi_export.json"
DROP = {"Not the lab range", "Strange protocol", "Echo reply too", "Allow Router Advertisements", "Allow Neighbor Solicitations"}


def main():
    doc = json.loads(FIXTURE.read_text(encoding="utf-8"))
    zones = {z["name"]: z["id"] for z in doc["zones"]}
    policies = [p for p in doc["policies"] if p["name"] not in DROP]
    for p in policies:
        if p["name"] == "Block IoT to LAN":
            p["connectionStateFilter"] = ["NEW"]                    # new connections only, so the replies of allowed traffic pass
        if p["name"] == "Block Servers to LAN":
            p["description"] = "All states on purpose: this one also drops the replies of connections started from the LAN (see Compare)."
    # drop policies whose pair we define more fully below
    redo = {("IoT", "Internal"), ("Internal", "IoT"), ("Internal", "DMZ"), ("DMZ", "Internal")}
    names = {v: k for k, v in zones.items()}
    kept = [p for p in policies if p["metadata"]["origin"] == "USER_DEFINED" or (names[p["source"]["zoneId"]], names[p["destination"]["zoneId"]]) not in redo]
    count = [5000]

    def system(src, dst, name, action, index, states=None, origin="SYSTEM_DEFINED"):
        count[0] += 1
        p = {"id": f"00000000-0000-4000-8000-{count[0]:012d}", "name": name, "description": "", "enabled": True, "index": index, "loggingEnabled": False,
             "action": {"type": action, **({"allowReturnTraffic": False} if action == "ALLOW" else {})}, "source": {"zoneId": zones[src]},
             "destination": {"zoneId": zones[dst]}, "ipProtocolScope": {"ipVersion": "IPV4_AND_IPV6"}, "metadata": {"origin": origin}}
        if states:
            p["connectionStateFilter"] = states
        kept.append(p)
    last = 2147483647
    system("IoT", "Internal", "Allow Return Traffic", "ALLOW", 30000, ["RELATED", "ESTABLISHED"])
    system("IoT", "Internal", "Block All Traffic", "BLOCK", last)
    system("Internal", "IoT", "Allow All Traffic", "ALLOW", last)
    system("Internal", "DMZ", "Block All Traffic", "BLOCK", last)
    system("External", "IoT", "Allow Return Traffic", "ALLOW", 30000, ["RELATED", "ESTABLISHED"])
    system("External", "IoT", "Block All Traffic", "BLOCK", last)
    system("DMZ", "Internal", "Allow Return Traffic", "ALLOW", 30000, ["RELATED", "ESTABLISHED"])
    system("DMZ", "Internal", "Block All Traffic", "BLOCK", last)
    # every zone pair ends in a predefined policy, as in a real export; replies are let back in wherever a pair blocks
    allow_pairs = {("Internal", d) for d in zones if d not in ("DMZ", "Internal")} | {("Gateway", d) for d in zones if d != "Gateway"} \
        | {("Vpn", d) for d in zones} | {("IoT", "External"), ("IoT", "Gateway"), ("Hotspot", "External"), ("DMZ", "External")}
    have_final = {(names[p["source"]["zoneId"]], names[p["destination"]["zoneId"]]) for p in kept if p["index"] == last}
    have_return = {(names[p["source"]["zoneId"]], names[p["destination"]["zoneId"]]) for p in kept if p["name"] == "Allow Return Traffic"}
    for src in zones:
        for dst in zones:
            if (src, dst) in have_final or (src == dst == "Gateway"):
                continue
            if (src, dst) in allow_pairs:
                system(src, dst, "Allow All Traffic", "ALLOW", last)
            else:
                if (src, dst) not in have_return and src != dst:
                    system(src, dst, "Allow Return Traffic", "ALLOW", 30000, ["RELATED", "ESTABLISHED"])
                system(src, dst, "Block All Traffic", "BLOCK", last)
    doc["policies"] = kept
    doc["exported_at"] = "2026-10-14T12:00:00Z"
    OUT.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(kept)} policies")


if __name__ == "__main__":
    main()
