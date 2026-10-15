if ping -c 2 -W 2 10.0.0.10 >/dev/null 2>&1; then r=ALLOW; else r=DENY; fi; echo h-wifi,h-lan,icmp,$r
if nc -w 2 10.0.0.10 443 </dev/null 2>/dev/null | grep -q OPEN; then r=ALLOW; else r=DENY; fi; echo h-wifi,h-lan,tcp443,$r
if ping -c 2 -W 2 10.0.10.10 >/dev/null 2>&1; then r=ALLOW; else r=DENY; fi; echo h-wifi,h-cam,icmp,$r
if nc -w 2 10.0.10.10 443 </dev/null 2>/dev/null | grep -q OPEN; then r=ALLOW; else r=DENY; fi; echo h-wifi,h-cam,tcp443,$r
if ping -c 2 -W 2 198.51.100.10 >/dev/null 2>&1; then r=ALLOW; else r=DENY; fi; echo h-wifi,h-ext,icmp,$r
if nc -w 2 198.51.100.10 443 </dev/null 2>/dev/null | grep -q OPEN; then r=ALLOW; else r=DENY; fi; echo h-wifi,h-ext,tcp443,$r
