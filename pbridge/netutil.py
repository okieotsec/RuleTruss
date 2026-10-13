"""Address, port and protocol helpers shared by every adapter. Everything here is deterministic and bounded."""
import ipaddress

MAX_PORT = 65535
PROTO_NAMES = {"ip": "ip", "tcp": "tcp", "udp": "udp", "icmp": "icmp", "icmp6": "icmp6", "icmpv6": "icmp6",
               "ipv6-icmp": "icmp6", "sctp": "sctp", "gre": "gre", "esp": "esp", "ah": "ah", "ospf": "ospf",
               "eigrp": "eigrp", "pim": "pim", "igmp": "igmp", "vrrp": "vrrp"}
PROTO_NUMBERS = {0: "ip", 1: "icmp", 2: "igmp", 6: "tcp", 17: "udp", 41: "ipv6", 47: "gre", 50: "esp", 51: "ah",
                 58: "icmp6", 89: "ospf", 88: "eigrp", 103: "pim", 112: "vrrp", 132: "sctp"}

# Well-known service names used by the vendors' CLIs. This is a name to number table, not application identification.
PORT_NAMES = {
    "ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "domain": 53, "dns": 53, "tftp": 69, "http": 80,
    "www": 80, "pop3": 110, "ntp": 123, "netbios-ns": 137, "netbios-dgm": 138, "netbios-ssn": 139, "imap": 143,
    "snmp": 161, "snmptrap": 162, "ldap": 389, "https": 443, "smb": 445, "cifs": 445, "syslog": 514, "ldaps": 636,
    "radius": 1812, "radius-acct": 1813, "rdp": 3389, "sqlnet": 1521, "mysql": 3306, "postgresql": 5432,
    "modbus": 502, "bgp": 179, "isakmp": 500, "ipsec": 500, "kerberos": 88, "sunrpc": 111, "bootps": 67,
    "bootpc": 68, "echo": 7, "discard": 9, "daytime": 13, "tacacs": 49, "pptp": 1723, "sip": 5060, "h323": 1720,
    "lpd": 515, "nntp": 119, "rsh": 514, "ident": 113, "finger": 79, "gopher": 70, "ssh-alt": 2222,
}


class ParseProblem(ValueError):
    """Raised for input that cannot be understood. The message is safe to show to the user."""


def parse_ip_or_net(text, strict=False):
    """Return an ip_network for an address ('10.1.1.1' becomes /32) or CIDR text. Raises ParseProblem."""
    try:
        return ipaddress.ip_network(text.strip(), strict=strict)
    except ValueError as error:
        raise ParseProblem(f"not an address or network: {text[:60]!r}") from error


def net_from_mask(addr, mask):
    """Build a network from 'a.b.c.d' and a subnet mask ('255.255.255.0'). Non-contiguous masks are rejected."""
    try:
        return ipaddress.ip_network(f"{addr}/{mask}", strict=False)
    except ValueError as error:
        raise ParseProblem(f"bad address/mask: {addr} {mask}") from error


def net_from_wildcard(addr, wildcard):
    """Build a network from an IOS wildcard mask. Non-contiguous wildcards raise ParseProblem (not representable)."""
    try:
        wild = int(ipaddress.IPv4Address(wildcard))
        base = ipaddress.IPv4Address(addr)
    except ValueError as error:
        raise ParseProblem(f"bad address/wildcard: {addr} {wildcard}") from error
    mask = wild ^ 0xFFFFFFFF
    # A contiguous netmask looks like 1...10...0, so its inverse plus one is a power of two.
    if (wild + 1) & wild:
        raise ParseProblem(f"non-contiguous wildcard mask {wildcard} cannot be expressed as a network")
    return ipaddress.ip_network(f"{ipaddress.IPv4Address(int(base) & mask)}/{bin(mask).count('1')}", strict=False)


def proto_name(token):
    """Normalise a protocol keyword or number to the names used in the model, or None if it is not recognised."""
    token = token.strip().lower()
    if token in PROTO_NAMES:
        return PROTO_NAMES[token]
    if token.isdigit() and int(token) < 256:
        return PROTO_NUMBERS.get(int(token), f"proto:{int(token)}")
    return None


def port_number(token):
    """Port from a number or a well-known name; raises ParseProblem."""
    token = token.strip().lower()
    if token.isdigit() and int(token) <= MAX_PORT:
        return int(token)
    if token in PORT_NAMES:
        return PORT_NAMES[token]
    raise ParseProblem(f"unknown port or service name: {token[:40]!r}")


def merge_ranges(ranges):
    """Sort and merge overlapping or adjacent (lo, hi) ranges."""
    out = []
    for lo, hi in sorted(ranges):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


def parse_port_ranges(text):
    """'80', '80-90', '80,443,8000-8100' to a merged list of (lo, hi). Raises ParseProblem."""
    ranges = []
    for part in text.replace(" ", "").split(","):
        if not part:
            continue
        lo, _, hi = part.partition("-")
        low, high = port_number(lo), port_number(hi) if hi else port_number(lo)
        if low > high:
            raise ParseProblem(f"port range runs backwards: {part}")
        ranges.append((low, high))
    if not ranges:
        raise ParseProblem("empty port list")
    return merge_ranges(ranges)


def ranges_text(ranges):
    return ",".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in ranges)


def ranges_contain(ranges, port):
    return any(lo <= port <= hi for lo, hi in ranges)


def ranges_overlap(a, b):
    return any(x_lo <= y_hi and y_lo <= x_hi for x_lo, x_hi in a for y_lo, y_hi in b)


def ranges_subset(inner, outer):
    """True when every port in `inner` is inside `outer`."""
    return all(any(o_lo <= lo and hi <= o_hi for o_lo, o_hi in outer) for lo, hi in inner)


def is_private_or_local(ip_text):
    """True for RFC 1918, ULA, link-local, loopback and multicast style addresses (used to guess 'internal')."""
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    return ip.is_private or ip.is_link_local or ip.is_loopback or ip.is_multicast
