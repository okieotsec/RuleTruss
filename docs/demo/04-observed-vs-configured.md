# Observed traffic compared with configured permissions

> **OBSERVED** compared with **CONFIGURED**. An observed connection that the configuration would deny usually means the traffic does not cross this device or the zones you defined differ; it is not a finding about the device.

| Initiator | Responder | Service | Outcome | Matched rule | Reading |
| --- | --- | --- | --- | --- | --- |
| 10.10.4.4 | 10.30.2.40 | tcp/502 | deny | CORP-IN:3 | Observed traffic would be denied by this configuration. Either the traffic does not pass through this device, the capture was taken before enforcement, the export is not what is running, or the zones/subnets you defined do not match; the capture alone cannot tell which. |
| 10.10.4.4 | 10.30.5.10 | tcp/443 | allow | CORP-IN:1 | Observed traffic is permitted by the configured policy. |
| 10.20.1.15 | 10.20.1.2 | udp/53 | deny | ENG-IN:7 | Observed traffic would be denied by this configuration. Either the traffic does not pass through this device, the capture was taken before enforcement, the export is not what is running, or the zones/subnets you defined do not match; the capture alone cannot tell which. |
| 10.20.1.15 | 10.30.2.40 | icmp | allow | ENG-IN:3 | Observed traffic is permitted by the configured policy. |
| 10.20.1.15 | 10.30.2.40 | tcp/502 | allow | ENG-IN:1 | Observed traffic is permitted by the configured policy. |
| 10.20.1.15 | 10.30.2.40 | tcp/44818 | allow | ENG-IN:1 | Observed traffic is permitted by the configured policy. |
| 10.20.1.15 | 10.30.2.99 | tcp/8888 | allow | ENG-IN:5 | Observed traffic is permitted by the configured policy. |
| 10.20.1.16 | 10.30.2.40 | tcp/502 | allow | ENG-IN:1 | Observed traffic is permitted by the configured policy. |
| 10.20.1.50 | 10.30.2.40 | udp/161 | allow | ENG-IN:2 | Observed traffic is permitted by the configured policy. |
| 10.20.1.99 | 10.30.2.41 | tcp/502 | allow | ENG-IN:5 | Observed traffic is permitted by the configured policy. |
| 10.30.2.40 | 10.20.1.60 | udp/514 | deny | PLC-IN:3 | Observed traffic would be denied by this configuration. Either the traffic does not pass through this device, the capture was taken before enforcement, the export is not what is running, or the zones/subnets you defined do not match; the capture alone cannot tell which. |
| 10.30.2.40 | 10.30.5.1 | udp/123 | allow | PLC-IN:2 | Observed traffic is permitted by the configured policy. |
| 10.30.2.40 | 10.30.5.10 | tcp/4840 | allow | PLC-IN:1 | Observed traffic is permitted by the configured policy. |
| 10.30.2.40 | 198.51.100.7 | tcp/443 | deny | PLC-IN:3 | Observed traffic would be denied by this configuration. Either the traffic does not pass through this device, the capture was taken before enforcement, the export is not what is running, or the zones/subnets you defined do not match; the capture alone cannot tell which. |
| 10.30.5.10 | 10.30.2.40 | tcp/502 | allow | HIST-IN:1 | Observed traffic is permitted by the configured policy. |
| 2001:db8:20::15 | 2001:db8:30::40 | tcp/502 | indeterminate | - | Cannot be decided from the export: say which interface this traffic uses (inbound) |

## Allow rules no observed traffic matched

- ENG-IN:4: 10.20.1.20/32 to 10.30.2.0/24 on tcp dport 22
- ENG-IN:6: 10.20.1.99/32 to 10.30.2.41/32 on tcp dport 502
- HIST-IN:2: 10.30.5.10/32 to 10.30.2.0/24 on tcp dport 44818
- CORP-IN:2: any to any on tcp dport 3389
