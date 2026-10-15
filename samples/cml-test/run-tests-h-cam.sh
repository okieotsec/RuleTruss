if ping -c 2 -W 2 10.0.0.10 >/dev/null 2>&1; then r=ALLOW; else r=DENY; fi; echo h-cam,h-lan,icmp,$r
if nc -w 2 10.0.0.10 443 </dev/null 2>/dev/null | grep -q OPEN; then r=ALLOW; else r=DENY; fi; echo h-cam,h-lan,tcp443,$r
if ping -c 2 -W 2 10.0.20.10 >/dev/null 2>&1; then r=ALLOW; else r=DENY; fi; echo h-cam,h-wifi,icmp,$r
if nc -w 2 10.0.20.10 443 </dev/null 2>/dev/null | grep -q OPEN; then r=ALLOW; else r=DENY; fi; echo h-cam,h-wifi,tcp443,$r
if ping -c 2 -W 2 198.51.100.10 >/dev/null 2>&1; then r=ALLOW; else r=DENY; fi; echo h-cam,h-ext,icmp,$r
if nc -w 2 198.51.100.10 443 </dev/null 2>/dev/null | grep -q OPEN; then r=ALLOW; else r=DENY; fi; echo h-cam,h-ext,tcp443,$r
