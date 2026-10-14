"""Turn device facts from captures into one reviewable list: which MAC belongs to which IP, who made the network card, and
what each device said about itself.

Attributing a MAC to an IP is a judgement, and this module states how it made it:
  confirmed  the device announced the pairing itself (ARP, or a DHCP acknowledgement to that MAC)
  probable   the only evidence is frames carrying that IP's packets, and the MAC carried no other IP. If the IP is on another
             network, that MAC is the router's, so this is never shown as confirmed
  (none)     a MAC that carried several IPs is a router, a firewall or a device with aliases; it is listed under shared_macs and
             not attributed to any one of those IPs unless that IP was confirmed by ARP or DHCP
The OUI names the maker of the network interface only. It is not shown as the device's maker, and not shown at all for a
randomised or locally administered MAC.
"""
from . import limits, netutil, oui

STRENGTH = {"arp": 2, "dhcp": 2, "frame": 1}
IDENTITY_ORDER = ("enip-identity", "modbus-identity", "snmp-sysdescr", "lldp-description", "lldp-name", "dhcp-hostname", "snmp-sysname",
                  "http-server", "ssh-banner", "dhcp-vendor-class", "http-user-agent", "snmp-sysobjectid", "lldp-capabilities",
                  "ttl-hint")
KIND_LABELS = {"enip-identity": "EtherNet/IP identity", "modbus-identity": "Modbus identity", "snmp-sysdescr": "SNMP description",
               "snmp-sysname": "SNMP name", "snmp-sysobjectid": "SNMP object ID", "lldp-name": "LLDP name",
               "lldp-description": "LLDP description", "lldp-capabilities": "LLDP capabilities", "dhcp-hostname": "DHCP hostname",
               "dhcp-vendor-class": "DHCP vendor class", "http-server": "HTTP server", "http-user-agent": "HTTP user agent",
               "ssh-banner": "SSH banner", "ttl-hint": "TTL hint"}
NOT_A_FACT = "Strings are what the device said about itself in the capture; they can be wrong or forged."


def _ref(evidence):
    return "; ".join(f"packets {e['ref']}" for e in evidence[:1] if e.get("ref")) if evidence else ""


def merge(facts_list):
    """Combine the `devices` dicts of several captures. Counts add; observations keep their first evidence."""
    bindings, senders, observations, notes = {}, {}, {}, []
    for facts in facts_list:
        for b in facts.get("bindings", []):
            key = (b["mac"], b["ip"], b["basis"])
            have = bindings.get(key)
            if have:
                have["packets"] += b.get("packets", 1)
            elif len(bindings) < limits.MAX_DEVICE_ITEMS:
                bindings[key] = dict(b)
        for s in facts.get("l2_senders", []):
            have = senders.get(s["mac"])
            if have:
                have["frames"] += s.get("frames", 1)
                have["kinds"] = sorted(set(have["kinds"]) | set(s.get("kinds", [])))
            elif len(senders) < limits.MAX_DEVICE_ITEMS:
                senders[s["mac"]] = dict(s)
        for o in facts.get("observations", []):
            key = (o.get("ip", ""), o.get("mac", ""), o["kind"], o["value"])
            if key not in observations and len(observations) < limits.MAX_DEVICE_ITEMS:
                observations[key] = o
        notes.extend(facts.get("limits_hit", []))
    return {"bindings": list(bindings.values()), "l2_senders": list(senders.values()), "observations": list(observations.values()),
            "limits_hit": list(dict.fromkeys(notes))}


def _nic(mac, registry):
    """What the MAC does and does not say, as plain data."""
    hit = registry.lookup(mac)
    return {"mac": mac, "mac_kind": oui.mac_kind(mac), "nic_vendor": hit["vendor"] if hit else "",
            "registry": hit["registry"] if hit else "", "mac_note": registry.describe(mac)}


def build(facts, ips=(), registry=oui.NO_NAMES):
    """Per-IP device records, the shared-MAC list and layer-2-only devices.

    `ips` are the addresses the flows mention, so every observed device gets a row even with no MAC or identity information.
    `registry` supplies card-maker names; without one (the default) the names are simply absent.
    """
    by_mac, by_ip = {}, {}
    for b in facts["bindings"]:
        by_mac.setdefault(b["mac"], {}).setdefault(b["ip"], []).append(b)
        by_ip.setdefault(b["ip"], {}).setdefault(b["mac"], []).append(b)
    shared = []
    for mac, ip_map in by_mac.items():
        if len(ip_map) >= 2:
            confirmed = sorted((ip for ip, bs in ip_map.items() if any(STRENGTH[b["basis"]] == 2 for b in bs)), key=netutil.ip_sort_key)
            shared.append({**_nic(mac, registry), "ips": sorted(ip_map, key=netutil.ip_sort_key), "confirmed_ips": confirmed,
                           "packets": sum(b["packets"] for bs in ip_map.values() for b in bs),
                           "note": "One MAC carried several IP addresses: a router, firewall or gateway for traffic from other "
                                   "networks, or a device with several addresses. Its address is not attributed to any of them "
                                   "unless ARP or DHCP confirmed it."})
    shared.sort(key=lambda s: (-len(s["ips"]), s["mac"]))
    shared_macs = {s["mac"] for s in shared}

    obs_by_ip, obs_by_mac = {}, {}
    for o in facts["observations"]:
        (obs_by_ip if o.get("ip") else obs_by_mac).setdefault(o.get("ip") or o["mac"], []).append(o)

    devices, attributed_macs = {}, set()
    for ip in sorted(set(ips) | set(by_ip) | set(obs_by_ip), key=netutil.ip_sort_key):
        row = {"ip": ip, "mac": "", "mac_confidence": "", "mac_basis": "", "other_macs": [], "identity": [], "identity_short": "",
               "hint": "", "mac_note": "", "nic_vendor": "", "mac_kind": ""}
        candidates = []                                          # (strength, packets, mac, basis list)
        for mac, bs in by_ip.get(ip, {}).items():
            best = max(STRENGTH[b["basis"]] for b in bs)
            if best == 2 or mac not in shared_macs:
                candidates.append((best, sum(b["packets"] for b in bs), mac, sorted({b["basis"] for b in bs}), bs))
        candidates.sort(key=lambda c: (-c[0], -c[1], c[2]))
        if candidates:
            strength, _packets, mac, basis, bs = candidates[0]
            row.update(_nic(mac, registry))
            row.update(mac_confidence="confirmed" if strength == 2 else "probable", mac_basis="+".join(basis),
                       mac_evidence=_ref(bs[0].get("evidence", [])))
            if strength == 1:
                row["mac_note"] = (row["mac_note"] + "; " if row["mac_note"] else "") + (
                    "seen only as the sender of this address's frames: if this address is on another network, this is the "
                    "router's MAC")
            row["other_macs"] = [c[2] for c in candidates[1:]]
            attributed_macs.add(mac)
        items = list(obs_by_ip.get(ip, []))
        if row["mac"]:
            items += obs_by_mac.get(row["mac"], [])
        items.sort(key=lambda o: IDENTITY_ORDER.index(o["kind"]) if o["kind"] in IDENTITY_ORDER else 99)
        for o in items:
            row["identity"].append({"kind": o["kind"], "label": KIND_LABELS.get(o["kind"], o["kind"]), "value": o["value"],
                                    "type": o.get("source_type", "self-reported"), "confidence": o["confidence"],
                                    "basis": o.get("basis", ""), "evidence": _ref(o.get("evidence", []))})
        facts_only = [i for i in row["identity"] if i["type"] != "weak-hint"]
        hints = [i for i in row["identity"] if i["type"] == "weak-hint"]
        if facts_only:
            row["identity_short"] = limits.clip(facts_only[0]["value"], 70)
        if hints:
            row["hint"] = hints[0]["value"]
        devices[ip] = row

    senders = {s["mac"]: s for s in facts["l2_senders"]}
    l2_only = []
    for mac in sorted(set(senders) | set(obs_by_mac)):
        if mac in attributed_macs or mac in by_mac:
            continue
        items = obs_by_mac.get(mac, [])
        sender = senders.get(mac, {"frames": 0, "kinds": []})
        l2_only.append({**_nic(mac, registry), "frames": sender["frames"], "kinds": sender["kinds"],
                        "identity": [{"kind": o["kind"], "label": KIND_LABELS.get(o["kind"], o["kind"]), "value": o["value"],
                                      "type": o.get("source_type", "self-reported")} for o in items],
                        "identity_short": limits.clip(items[0]["value"], 70) if items else ""})
    l2_only.sort(key=lambda d: (-d["frames"], d["mac"]))
    return {"devices": devices, "shared_macs": shared, "l2_only": l2_only, "limits_hit": facts.get("limits_hit", []),
            "snapshot": registry.info(), "caution": NOT_A_FACT}
