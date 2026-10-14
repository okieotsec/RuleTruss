"""A synthetic UniFi export shaped like a gateway with one zone per VLAN, built to reproduce the translation problems a reviewer found:
zone-scoped policies, per-pair defaults that must not become 'any', zones with no networks, a zone whose networks are missing from
the export, MAC allowlists, stale zone assignments, predefined ICMPv6 policies with no message type, and policies for the firewall
itself and for VPN. Everything is invented; the names and addresses follow the table in the review."""
import json


def U(n):
    return f"00000000-0000-4000-8000-{n:012d}"


NETWORKS = {"Default": "10.0.0.0/24", "IP_CAMERAS": "10.0.10.0/24", "WIRELESS_DEVICES": "10.0.20.0/24", "SOC_SERVICES": "10.0.100.0/24",
            "OT_LAB_DEVICES": "10.0.101.0/24", "ISOLATION": "10.0.250.0/24", "SANDBOX": "10.0.251.0/24"}
ZONE_NETWORKS = {"Default LAN": ["Default"], "IP Cameras": ["IP_CAMERAS"], "Wireless Devices": ["WIRELESS_DEVICES"], "SOC Services": ["SOC_SERVICES"],
                 "OT Lab": ["OT_LAB_DEVICES"], "Isolation": ["ISOLATION"], "Sandbox": ["SANDBOX"]}
EMPTY_ZONES = ["Internal", "Dmz", "Hotspot", "Vpn", "Gateway"]
LAST = 2147483647
LOCAL = list(ZONE_NETWORKS)
nid = {name: U(100 + i) for i, name in enumerate(NETWORKS)}
zid = {name: U(200 + i) for i, name in enumerate([*ZONE_NETWORKS, "External", *EMPTY_ZONES])}


def build(with_problems=True):
    """The export. With `with_problems=False` the MAC, ICMPv6, stale and VPN policies are left out (a clean, translatable gateway)."""
    count = [1000]
    policies = []

    def add(src, dst, name, action="ALLOW", index=10000, origin="USER_DEFINED", src_filter=None, dst_filter=None, states=None, scope=None):
        count[0] += 1
        p = {"id": U(count[0]), "name": name, "description": "", "enabled": True, "index": index, "loggingEnabled": False,
             "action": {"type": action, **({"allowReturnTraffic": False} if action == "ALLOW" else {})},
             "source": {"zoneId": zid[src], **({"trafficFilter": src_filter} if src_filter else {})},
             "destination": {"zoneId": zid[dst], **({"trafficFilter": dst_filter} if dst_filter else {})},
             "ipProtocolScope": scope or {"ipVersion": "IPV4_AND_IPV6"}, "metadata": {"origin": origin}}
        if states:
            p["connectionStateFilter"] = states
        policies.append(p)

    def net(name):
        return {"type": "NETWORK", "networkFilter": {"networkIds": [nid[name]], "matchOpposite": False}}

    def ip(*values):
        return {"type": "IP_ADDRESS", "ipAddressFilter": {"type": "IP_ADDRESSES", "matchOpposite": False,
                                                           "items": [{"type": "SUBNET" if "/" in x else "IP_ADDRESS", "value": x} for x in values]}}

    def mac(*macs):
        return {"type": "MAC_ADDRESS", "macAddressFilter": {"macAddresses": list(macs)}}

    # predefined: every local zone ends in Allow All to External and Gateway, Block All to the others, with return traffic where it blocks
    for src in LOCAL:
        for dst in [*LOCAL, "External", "Gateway"]:
            if src == dst:
                continue
            if dst in ("External", "Gateway"):
                add(src, dst, "Allow All Traffic", "ALLOW", LAST, "SYSTEM_DEFINED")
            else:
                add(src, dst, "Allow Return Traffic", "ALLOW", 30000, "SYSTEM_DEFINED", states=["RELATED", "ESTABLISHED"])
                add(src, dst, "Block All Traffic", "BLOCK", LAST, "SYSTEM_DEFINED")
        add(src, "External", "Block Invalid Traffic", "BLOCK", 30000, "SYSTEM_DEFINED", states=["INVALID"])
    for dst in LOCAL:
        add("External", dst, "Allow Return Traffic", "ALLOW", 30000, "SYSTEM_DEFINED", states=["RELATED", "ESTABLISHED"])
        add("External", dst, "Block All Traffic", "BLOCK", LAST, "SYSTEM_DEFINED")
    # yours
    add("OT Lab", "SOC Services", "ALLOW OT Lab -> SOC", "ALLOW", 10000)
    add("SOC Services", "OT Lab", "ALLOW OT Lab -> SOC (Return)", "ALLOW", 30000, "DERIVED", states=["RELATED", "ESTABLISHED"])
    add("SOC Services", "Default LAN", "ALLOW SOC -> Default LAN", "ALLOW", 10000)
    add("Isolation", "External", "Isolated internet", "ALLOW", 10000, dst_filter={"type": "PORT", "portFilter": {"type": "PORTS", "matchOpposite": False,
                                                                                                                 "items": [{"type": "PORT_NUMBER", "value": 443}]}})
    add("Wireless Devices", "IP Cameras", "Cameras for phones", "ALLOW", 10000, src_filter=net("WIRELESS_DEVICES"), dst_filter=net("IP_CAMERAS"))
    if with_problems:
        add("Wireless Devices", "SOC Services", "ALLOW Wireless -> SOC (two devices)", "ALLOW", 10000, src_filter=mac("60:45:2e:77:05:2e", "72:e9:41:e8:b1:16"))
        add("Internal", "Internal", "BLOCK tablet", "BLOCK", 10000, src_filter=mac("bc:24:11:81:fa:29"))
        add("Internal", "External", "Block Traffic from 10.0.20.197 to 104.26.15.72", "BLOCK", 10000, src_filter=ip("10.0.20.197"), dst_filter=ip("104.26.15.72"))
        icmp6 = {"ipVersion": "IPV6", "protocolFilter": {"type": "NAMED_PROTOCOL", "matchOpposite": False, "protocol": {"name": "ICMPV6"}}}
        add("External", "Gateway", "Allow Neighbor Solicitations", "ALLOW", 30002, "SYSTEM_DEFINED", scope=icmp6)
        add("Vpn", "Default LAN", "Allow VPN to LAN", "ALLOW", 10000)
    zones = [{"id": zid[z], "name": z, "networkIds": [nid[n] for n in nets], "metadata": {"origin": "USER_DEFINED"}} for z, nets in ZONE_NETWORKS.items()]
    zones.append({"id": zid["External"], "name": "External", "networkIds": [U(901), U(902)], "metadata": {"origin": "SYSTEM_DEFINED"}})
    zones += [{"id": zid[z], "name": z, "networkIds": [], "metadata": {"origin": "SYSTEM_DEFINED"}} for z in EMPTY_ZONES]
    networks = [{"id": nid[name], "name": name, "enabled": True, "management": "GATEWAY", "vlanId": 10 + i, "default": name == "Default",
                 "ipv4Configuration": {"autoScaleEnabled": False, "hostIpAddress": cidr.replace("0/24", "1"), "prefixLength": 24},
                 "metadata": {"origin": "USER_DEFINED"}} for i, (name, cidr) in enumerate(NETWORKS.items())]
    return {"ruletruss_unifi_export": 1, "exported_at": "2026-10-14T12:00:00Z", "application_version": "10.6.106",
            "site": {"id": U(1), "name": "Default", "internalReference": "default"}, "zones": zones, "policies": policies, "networks": networks,
            "traffic_matching_lists": [], "acl_rules": []}


def text(with_problems=True):
    return json.dumps(build(with_problems))
