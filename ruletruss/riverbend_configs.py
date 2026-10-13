"""The five Riverbend device exports (all invented). Each has planted teaching points, listed in samples/riverbend/GUIDE.md."""

ASA = """: Saved
: Synthetic export for the fictional Riverbend plant. Not a real configuration.
ASA Version 9.16(4)
!
hostname rb-perimeter-fw
!
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.2 255.255.255.0
!
interface GigabitEthernet0/1
 nameif corp
 security-level 50
 ip address 10.10.0.1 255.255.0.0
!
interface GigabitEthernet0/2
 nameif dmz
 security-level 30
 ip address 10.40.0.1 255.255.255.0
!
object network VENDOR-NET
 subnet 198.51.100.0 255.255.255.0
object network JUMP-HOST
 host 10.40.0.10
 nat (dmz,outside) static 203.0.113.20
object network REPLICA
 host 10.40.0.20
object network PATCH-SRV
 host 10.40.0.30
object network XFER-SRV
 host 10.40.0.40
object network CORP-DNS
 host 10.10.1.10
object network CORP-NTP
 host 10.10.1.11
object network MS-UPDATE
 fqdn v4 download.updates.example
object-group network IT-ADMINS
 network-object host 10.10.9.5
 network-object host 10.10.9.6
object-group network CORP-VIEWERS
 network-object host 10.10.4.4
 network-object host 10.10.4.20
object-group network DMZ-SERVERS
 network-object object REPLICA
 network-object object PATCH-SRV
 network-object object XFER-SRV
!
access-list OUTSIDE-IN remark vendor remote support to the jump host (identity-based)
access-list OUTSIDE-IN extended permit tcp user-group RIVERBEND\\VendorSupport object VENDOR-NET object JUMP-HOST eq 3389
access-list OUTSIDE-IN extended permit tcp object VENDOR-NET object JUMP-HOST eq ssh
access-list OUTSIDE-IN remark an old vendor VPN range, still enabled
access-list OUTSIDE-IN extended permit tcp 192.0.2.0 255.255.255.0 object JUMP-HOST eq 3389
access-list OUTSIDE-IN extended deny ip any any log
access-list CORP-IN remark corporate viewers to the historian replica
access-list CORP-IN extended permit tcp object-group CORP-VIEWERS object REPLICA eq https
access-list CORP-IN remark IT administrators to the jump host
access-list CORP-IN extended permit tcp object-group IT-ADMINS object JUMP-HOST eq 3389
access-list CORP-IN extended permit tcp object-group IT-ADMINS object JUMP-HOST eq ssh
access-list CORP-IN remark temporary during the 2024 migration: all of corporate to the whole DMZ
access-list CORP-IN extended permit ip 10.10.0.0 255.255.0.0 10.40.0.0 255.255.255.0
access-list CORP-IN remark added later, but it can never match because of the line above
access-list CORP-IN extended deny tcp host 10.10.4.20 object JUMP-HOST eq 3389
access-list CORP-IN extended deny ip any any log
access-list DMZ-IN extended permit udp object-group DMZ-SERVERS object CORP-DNS eq domain
access-list DMZ-IN extended permit udp object PATCH-SRV object CORP-NTP eq ntp
access-list DMZ-IN extended permit tcp object PATCH-SRV object MS-UPDATE eq https
access-list DMZ-IN remark file transfer to anywhere, only in the maintenance window
access-list DMZ-IN extended permit tcp object XFER-SRV any eq 8080 time-range MAINTENANCE-WINDOW
access-list DMZ-IN extended deny ip any any log
access-group OUTSIDE-IN in interface outside
access-group CORP-IN in interface corp
access-group DMZ-IN in interface dmz
!
username netadmin password $1$notrealsalt$notarealhashvalue encrypted
snmp-server community notarealcommunitystring
"""


def pan_os():
    def addr(name, ip):
        return f'<entry name="{name}"><ip-netmask>{ip}</ip-netmask></entry>'

    def rule(name, src_zone, dst_zone, src, dst, service, action="allow", apps=("any",), extra=""):
        members = lambda tag, items: f"<{tag}>" + "".join(f"<member>{i}</member>" for i in items) + f"</{tag}>"  # noqa: E731
        return (f'<entry name="{name}">' + members("from", [src_zone]) + members("to", [dst_zone]) + members("source", [src])
                + members("destination", [dst]) + members("application", apps) + members("service", [service])
                + f"<action>{action}</action>{extra}</entry>")
    addresses = "".join([addr("scada1", "10.20.0.10"), addr("scada2", "10.20.0.11"), addr("historian", "10.20.0.20"), addr("eng1", "10.20.0.50"),
                         addr("eng2", "10.20.0.51"), addr("backup", "10.20.0.80"), addr("ops-net", "10.20.0.0/24"), addr("jump", "10.40.0.10"),
                         addr("replica", "10.40.0.20"), addr("patch", "10.40.0.30"), addr("xfer", "10.40.0.40"),
                         addr("jump-published", "10.40.0.25"), addr("corp-net", "10.10.0.0/16"),
                         '<entry name="vendor-portal"><fqdn>support.vendor.example</fqdn></entry>'])
    groups = ('<entry name="ops-eng"><static><member>eng1</member><member>eng2</member></static></entry>'
              '<entry name="ops-scada"><static><member>scada1</member><member>scada2</member></static></entry>'
              '<entry name="ops-servers"><static><member>ops-scada</member><member>historian</member><member>backup</member></static></entry>'
              '<entry name="contractors"><dynamic><filter>\'contractor\' and \'approved\'</filter></dynamic></entry>')
    services = ('<entry name="svc-sql"><protocol><tcp><port>1433</port></tcp></protocol></entry>'
                '<entry name="svc-wsus"><protocol><tcp><port>8530</port></tcp></protocol></entry>'
                '<entry name="svc-ssh"><protocol><tcp><port>22</port></tcp></protocol></entry>')
    rules = "".join([
        rule("jump-to-engineering", "dmz", "ops", "jump", "ops-eng", "application-default", apps=("ms-rdp", "ssh")),
        rule("jump-to-historian", "dmz", "ops", "jump", "historian", "service-https"),
        rule("historian-replication", "ops", "dmz", "historian", "replica", "svc-sql"),
        rule("ops-patching", "ops", "dmz", "ops-net", "patch", "svc-wsus"),
        rule("backup-transfer", "ops", "dmz", "backup", "xfer", "svc-ssh"),
        rule("contractor-laptops", "dmz", "ops", "contractors", "ops-eng", "any"),
        rule("ops-sql-anywhere-but-xfer", "ops", "dmz", "ops-net", "xfer", "svc-sql", extra="<negate-destination>yes</negate-destination>"),
        rule("ops-internal-log", "ops", "ops", "any", "any", "any", extra="<rule-type>intrazone</rule-type><log-end>yes</log-end>"),
        rule("legacy-opc-gateway", "dmz", "ops", "any", "any", "any", extra="<disabled>yes</disabled>"),
        rule("cleanup-deny", "any", "any", "any", "any", "any", action="deny", extra="<log-end>yes</log-end>"),
    ])
    nat = ('<entry name="publish-historian"><from><member>dmz</member></from><to><member>dmz</member></to><source><member>any</member></source>'
           '<destination><member>jump-published</member></destination>'
           '<destination-translation><translated-address>historian</translated-address></destination-translation></entry>')
    return f"""<config version="10.2.0" urldb="paloaltonetworks">
  <devices><entry name="localhost.localdomain">
    <deviceconfig><system><hostname>rb-ot-boundary</hostname><password>notarealpasswordhash</password></system></deviceconfig>
    <network><interface><ethernet>
      <entry name="ethernet1/1"><layer3><ip><entry name="10.40.0.2/24"/></ip></layer3></entry>
      <entry name="ethernet1/2"><layer3><ip><entry name="10.20.0.1/24"/></ip></layer3></entry>
    </ethernet></interface></network>
    <vsys><entry name="vsys1">
      <zone>
        <entry name="dmz"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
        <entry name="ops"><network><layer3><member>ethernet1/2</member></layer3></network></entry>
      </zone>
      <address>{addresses}</address><address-group>{groups}</address-group><service>{services}</service>
      <rulebase><security><rules>{rules}</rules></security><nat><rules>{nat}</rules></nat></rulebase>
    </entry></vsys>
  </entry></devices>
</config>
"""


FORTIOS = """#config-version=FGT80F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
config system global
    set hostname "rb-ops-field-fw"
    set admin-password ENC SH2notarealencryptedvalue
end
config system interface
    edit "ops"
        set vdom "root"
        set ip 10.20.0.3 255.255.255.0
        set type vlan
        set vlanid 20
    next
    edit "cell1"
        set vdom "root"
        set ip 10.30.1.1 255.255.255.0
        set type vlan
        set vlanid 11
    next
    edit "cell2"
        set vdom "root"
        set ip 10.30.2.1 255.255.255.0
        set type vlan
        set vlanid 12
    next
end
config system zone
    edit "field"
        set interface "cell1" "cell2"
    next
end
config firewall address
    edit "scada1"
        set subnet 10.20.0.10 255.255.255.255
    next
    edit "scada2"
        set subnet 10.20.0.11 255.255.255.255
    next
    edit "historian"
        set subnet 10.20.0.20 255.255.255.255
    next
    edit "eng1"
        set subnet 10.20.0.50 255.255.255.255
    next
    edit "eng2"
        set subnet 10.20.0.51 255.255.255.255
    next
    edit "hmi1"
        set subnet 10.20.0.60 255.255.255.255
    next
    edit "hmi2"
        set subnet 10.20.0.61 255.255.255.255
    next
    edit "netmon"
        set subnet 10.20.0.70 255.255.255.255
    next
    edit "ops-svc"
        set subnet 10.20.0.2 255.255.255.255
    next
    edit "cell1-net"
        set subnet 10.30.1.0 255.255.255.0
    next
    edit "cell2-net"
        set subnet 10.30.2.0 255.255.255.0
    next
    edit "plc-dosing"
        set subnet 10.30.2.30 255.255.255.255
    next
    edit "plc-treat1"
        set subnet 10.30.2.21 255.255.255.255
    next
    edit "vendor-telemetry"
        set type fqdn
        set fqdn "telemetry.vendor.example"
    next
end
config firewall addrgrp
    edit "grp-scada"
        set member "scada1" "scada2"
    next
    edit "grp-hmi"
        set member "hmi1" "hmi2"
    next
    edit "grp-masters"
        set member "grp-scada" "grp-hmi"
    next
    edit "grp-eng"
        set member "eng1" "eng2"
    next
    edit "field-nets"
        set member "cell1-net" "cell2-net"
    next
end
config firewall vip
    edit "hist-vip"
        set extip 10.20.0.100
        set extintf "ops"
        set mappedip "10.20.0.20"
    next
end
config firewall service custom
    edit "MODBUS"
        set tcp-portrange 502
    next
    edit "S7COMM"
        set tcp-portrange 102
    next
    edit "ENIP"
        set tcp-portrange 44818
        set udp-portrange 44818 2222
    next
end
config firewall policy
    edit 1
        set name "scada-modbus"
        set srcintf "ops"
        set dstintf "cell1"
        set action accept
        set srcaddr "grp-masters"
        set dstaddr "cell1-net"
        set schedule "always"
        set service "MODBUS"
    next
    edit 2
        set name "scada-s7"
        set srcintf "ops"
        set dstintf "cell2"
        set action accept
        set srcaddr "grp-scada"
        set dstaddr "cell2-net"
        set schedule "always"
        set service "S7COMM"
    next
    edit 3
        set name "eng-enip"
        set srcintf "ops"
        set dstintf "cell2"
        set action accept
        set srcaddr "grp-eng"
        set dstaddr "plc-dosing"
        set schedule "always"
        set service "ENIP"
    next
    edit 4
        set name "eng-s7"
        set srcintf "ops"
        set dstintf "cell2"
        set action accept
        set srcaddr "grp-eng"
        set dstaddr "cell2-net"
        set schedule "always"
        set service "S7COMM"
    next
    edit 5
        set name "eng-commissioning-anything"
        set srcintf "ops"
        set dstintf "field"
        set action accept
        set srcaddr "grp-eng"
        set dstaddr "field-nets"
        set schedule "always"
        set service "ALL"
        set comments "commissioning of the new filter bank; never removed"
    next
    edit 6
        set name "eng1-ssh"
        set srcintf "ops"
        set dstintf "cell2"
        set action accept
        set srcaddr "eng1"
        set dstaddr "cell2-net"
        set schedule "always"
        set service "SSH"
    next
    edit 7
        set name "netmon-snmp"
        set srcintf "ops"
        set dstintf "field"
        set action accept
        set srcaddr "netmon"
        set dstaddr "field-nets"
        set schedule "always"
        set service "SNMP"
    next
    edit 8
        set name "netmon-ping"
        set srcintf "ops"
        set dstintf "field"
        set action accept
        set srcaddr "netmon"
        set dstaddr "field-nets"
        set schedule "always"
        set service "PING"
    next
    edit 9
        set name "field-ntp"
        set srcintf "field"
        set dstintf "ops"
        set action accept
        set srcaddr "field-nets"
        set dstaddr "ops-svc"
        set schedule "always"
        set service "NTP"
    next
    edit 10
        set name "field-syslog"
        set srcintf "field"
        set dstintf "ops"
        set action accept
        set srcaddr "field-nets"
        set dstaddr "ops-svc"
        set schedule "always"
        set service "SYSLOG"
    next
    edit 11
        set name "plc-telemetry"
        set srcintf "cell2"
        set dstintf "ops"
        set action accept
        set srcaddr "plc-treat1"
        set dstaddr "vendor-telemetry"
        set schedule "always"
        set service "HTTPS"
        set nat enable
    next
    edit 12
        set name "contractors-business-hours"
        set srcintf "ops"
        set dstintf "cell1"
        set action accept
        set srcaddr "all"
        set dstaddr "cell1-net"
        set schedule "business-hours"
        set service "ALL"
        set groups "Contractors"
    next
    edit 13
        set name "temporary-commissioning"
        set srcintf "ops"
        set dstintf "field"
        set action accept
        set status disable
        set srcaddr "all"
        set dstaddr "all"
        set schedule "always"
        set service "ALL"
    next
    edit 14
        set name "cell1-to-historian"
        set srcintf "cell1"
        set dstintf "ops"
        set action accept
        set srcaddr "cell1-net"
        set dstaddr "hist-vip"
        set schedule "always"
        set service "HTTPS"
    next
    edit 15
        set name "no-action-set-by-mistake"
        set srcintf "ops"
        set dstintf "cell1"
        set srcaddr "hmi2"
        set dstaddr "cell1-net"
        set schedule "always"
        set service "HTTP"
    next
end
"""

IOS = """Building configuration...
!
version 17.9
hostname rb-cell3-router
!
enable secret 9 $9$notarealenablesecrethash
username netadmin privilege 15 secret 9 $9$notarealusersecret
!
ip access-list extended OPS-TO-CELL3
 remark DNP3 polling by the two SCADA servers
 10 permit tcp host 10.20.0.10 10.30.3.0 0.0.0.255 eq 20000
 20 permit tcp host 10.20.0.11 10.30.3.0 0.0.0.255 eq 20000
 remark remote shell from engineering workstation 1
 30 permit tcp host 10.20.0.50 10.30.3.0 0.0.0.255 eq 22
 40 permit udp host 10.20.0.70 10.30.3.0 0.0.0.255 eq snmp
 50 permit icmp 10.20.0.0 0.0.0.255 10.30.3.0 0.0.0.255 echo
 remark legacy telnet, return traffic via reflexive entries
 60 permit tcp any any eq telnet reflect TELNET-RETURN
 remark a mask written in the wrong notation (non-contiguous)
 70 permit ip 10.0.0.0 0.255.0.255 any
 80 deny ip any any log
ip access-list extended CELL3-IN
 remark RTU unsolicited reports to SCADA-1
 10 permit tcp 10.30.3.0 0.0.0.255 host 10.20.0.10 eq 20000
 remark replies to the polling above, matched with the established flag
 20 permit tcp 10.30.3.0 0.0.0.255 eq 20000 10.20.0.0 0.0.0.255 established
 30 permit udp 10.30.3.0 0.0.0.255 host 10.20.0.2 eq ntp
 40 permit udp 10.30.3.0 0.0.0.255 host 10.20.0.2 eq syslog
 50 permit udp 10.30.3.0 0.0.0.255 eq snmp host 10.20.0.70
 60 permit icmp 10.30.3.0 0.0.0.255 any echo-reply
 70 deny ip any any log
ipv6 access-list V6-CELL3
 deny ipv6 any any
!
interface Vlan20
 description operations side
 ip address 10.20.0.4 255.255.255.0
 ip access-group OPS-TO-CELL3 in
!
interface Vlan30
 description cell 3 distribution
 ip address 10.30.3.1 255.255.255.0
 ip access-group CELL3-IN in
 ipv6 traffic-filter V6-CELL3 in
!
snmp-server community notarealreadonlycommunity RO
"""

PFSENSE = """<?xml version="1.0"?>
<pfsense>
  <version>23.09</version>
  <system>
    <hostname>rb-vendor-access</hostname>
    <user><name>admin</name><bcrypt-hash>$2y$10$notarealhashnotarealhashnotarealhashnotarealhash</bcrypt-hash><password>notarealpassword</password></user>
  </system>
  <interfaces>
    <wan><if>igb0</if><ipaddr>203.0.113.40</ipaddr><subnet>24</subnet><descr>Vendor-facing</descr></wan>
    <lan><if>igb1</if><ipaddr>10.40.0.4</ipaddr><subnet>24</subnet><descr>DMZ</descr></lan>
  </interfaces>
  <aliases>
    <alias><name>VENDOR_NET</name><type>network</type><address>198.51.100.0/24</address></alias>
    <alias><name>JUMP</name><type>host</type><address>10.40.0.10</address></alias>
    <alias><name>REMOTE_PORTS</name><type>port</type><address>3389 22</address></alias>
    <alias><name>VENDOR_PORTAL</name><type>host</type><address>support.vendor.example</address></alias>
    <alias><name>KNOWN_BAD</name><type>urltable</type><address>https://lists.example.invalid/bad-hosts.txt</address></alias>
  </aliases>
  <filter>
    <rule><type>block</type><interface>wan</interface><ipprotocol>inet</ipprotocol><protocol>any</protocol><floating>yes</floating><quick/>
      <direction>in</direction><source><address>KNOWN_BAD</address></source><destination><any/></destination><descr>block known bad hosts</descr><tracker>2000001</tracker></rule>
    <rule><type>pass</type><interface>wan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><address>VENDOR_NET</address></source><destination><address>JUMP</address><port>REMOTE_PORTS</port></destination>
      <descr>vendor support to the jump host</descr><tracker>2000002</tracker></rule>
    <rule><type>pass</type><interface>wan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><address>VENDOR_PORTAL</address></source><destination><address>JUMP</address><port>3389</port></destination>
      <descr>vendor portal by name</descr><tracker>2000003</tracker></rule>
    <rule><type>pass</type><interface>wan</interface><ipprotocol>inet</ipprotocol><protocol>icmp</protocol><icmptype>echoreq</icmptype>
      <source><address>VENDOR_NET</address></source><destination><address>JUMP</address></destination><descr>vendor ping</descr><tracker>2000004</tracker></rule>
    <rule><type>pass</type><interface>lan</interface><ipprotocol>inet</ipprotocol><protocol>udp</protocol><statetype>none</statetype>
      <source><address>JUMP</address></source><destination><any/><port>123</port></destination><descr>NTP, no state kept</descr><tracker>2000005</tracker></rule>
    <rule><type>pass</type><interface>lan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol><sched>vendor-hours</sched>
      <source><address>JUMP</address></source><destination><any/><port>443</port></destination><descr>jump host to the Internet, working hours only</descr><tracker>2000006</tracker></rule>
    <rule><type>block</type><interface>lan</interface><ipprotocol>inet</ipprotocol><protocol>any</protocol><log/>
      <source><any/></source><destination><any/></destination><descr>block everything else</descr><tracker>2000007</tracker></rule>
  </filter>
  <nat>
    <rule><interface>wan</interface><protocol>tcp</protocol><source><any/></source><destination><network>wanip</network><port>3389</port></destination>
      <target>10.40.0.10</target><local-port>3389</local-port><descr>RDP to the jump host</descr></rule>
  </nat>
</pfsense>
"""

FILES = {
    "perimeter-asa.cfg": ASA, "it-ot-boundary-panos.xml": pan_os, "ops-field-fortios.conf": FORTIOS, "cell3-router-ios.cfg": IOS,
    "vendor-access-pfsense.xml": PFSENSE,
}


def configs():
    return {name: (value() if callable(value) else value) for name, value in FILES.items()}
