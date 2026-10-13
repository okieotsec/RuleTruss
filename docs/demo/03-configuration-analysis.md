# Configured policy (demo ASA)

> **CONFIGURED.** Read from the export; not evidence of what traffic exists.

| Pos | Rule | Action | From | Source | Destination | Service | Not evaluated |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | ENG-IN:1 | allow | eng | 10.20.1.15/32, 10.20.1.16/32 | 10.30.2.0/24 | tcp dport 502,44818 | - |
| 2 | ENG-IN:2 | allow | eng | 10.20.1.50/32 | 10.30.2.40/32 | udp dport 161 | - |
| 3 | ENG-IN:3 | allow | eng | 10.20.1.15/32 | 10.30.2.0/24 | icmp type 8 | - |
| 4 | ENG-IN:4 | allow | eng | 10.20.1.20/32 | 10.30.2.0/24 | tcp dport 22 | - |
| 5 | ENG-IN:5 | allow | eng | 10.20.0.0/16 | 10.30.2.0/24 | tcp | - |
| 6 | ENG-IN:6 | allow | eng | 10.20.1.99/32 | 10.30.2.41/32 | tcp dport 502 | - |
| 7 | ENG-IN:7 | deny | eng | any | any | any | - |
| 1 | PLC-IN:1 | allow | plc | 10.30.2.40/32 | 10.30.5.10/32 | tcp dport 4840 | - |
| 2 | PLC-IN:2 | allow | plc | 10.30.2.40/32 | 10.30.5.1/32 | udp dport 123 | - |
| 3 | PLC-IN:3 | deny | plc | any | any | any | - |
| 1 | HIST-IN:1 | allow | hist | 10.30.5.10/32 | 10.30.2.0/24 | tcp dport 502 | - |
| 2 | HIST-IN:2 | allow | hist | 10.30.5.10/32 | 10.30.2.0/24 | tcp dport 44818 | - |
| 3 | HIST-IN:3 | deny | hist | any | any | any | - |
| 1 | CORP-IN:1 | allow | corp | 10.10.0.0/16 | 10.30.5.10/32 | tcp dport 443 | - |
| 2 | CORP-IN:2 | allow | corp | any | any | tcp dport 3389 | schedule MAINTENANCE-WINDOW |
| 3 | CORP-IN:3 | deny | corp | any | any | any | - |

## Findings

- **redundant**: Rule ENG-IN:6 (allow) can never match: everything it covers is already handled by earlier rule ENG-IN:5 (allow).
- **broad**: Rule CORP-IN:2 allows traffic from any source to any destination on tcp dport 3389.
- **unevaluated**: Rule CORP-IN:2 has conditions this tool does not evaluate: schedule: MAINTENANCE-WINDOW.
