# Architecture

## Technology choices, and why

| Choice | Reason |
| --- | --- |
| **Python 3.12+, standard library for everything except packet decoding** | Matches the sibling project's approach (no runtime dependencies beyond what is necessary), keeps the supply-chain surface tiny, and is readable to network engineers. The software bill of materials lists one component. |
| **dpkt** (BSD, pure Python) for PCAP/PCAPNG and link/IP/TCP/UDP/ICMP decoding | The brief asks for an established packet library rather than a hand-written decoder. dpkt only parses; it has no live capture, shell or network code. Scapy was rejected as larger and more capable than needed; tshark/Wireshark is not assumed to be installed. |
| **`http.server` with a hardened handler, vanilla JavaScript, no build step** | Self-hostable without Node, containers or a database; the browser code is a few hundred auditable lines served under a strict Content-Security-Policy with no third-party scripts, fonts or analytics. |
| **JSON files in a private data folder** | Local-first, inspectable, deletable. The data sizes (tens of thousands of flows, thousands of rules) do not need a database. |
| **A subprocess per uploaded file** | Parsing untrusted files is isolated, time-limited and memory-limited. |

Not chosen for the MVP: FastAPI/React (more dependencies for no gain here), a SQL database, an AI-first design.

## Data flow

```
 browser  --(token, same origin)-->  server.py  --->  service.py
                                        |                 |
   upload (streamed to a 0600 file)     |                 +-- store.py  (project folders, JSON, 0700/0600)
                                        v                 +-- analysis.py, evaluate.py (pure functions over the model)
                              isolate.py (subprocess)     +-- migrate/ (groups, directional plans, firewall translation, validation)
                                        |                 +-- exports.py (CSV and Markdown, escaped)
                                        v
                                worker.py (rlimits)  -->  adapters/ (config text and XML -> PolicySet)
                                                          capture/  (pcap/pcapng/Zeek -> Flow, direction, application)
```

1. **Import.** The upload is streamed to disk (never held in memory) and handed to `worker.py` in a fresh interpreter with a clean environment, an empty working folder,
   a wall-clock timeout and kernel limits on memory, CPU, output size, open files and core dumps. The worker looks at the *content* of the file to choose a reader. The
   result is written as JSON and read back with a size cap. A failure returns a short, safe message; a rejected upload is deleted.
2. **Ingest.** `capture/` turns packets into bidirectional flows, infers who initiated each (with a confidence and the evidence), and identifies applications from payload
   structure. `adapters/` parse each configuration format into the vendor-neutral `PolicySet`, resolving nested objects with depth and size limits.
3. **Explain.** `analysis.py` aggregates flows into communications, builds the inventory and matrix, writes the plain-language explanations, compares observed traffic with
   configured permissions through `evaluate.py`, and finds shadowed, redundant and conflicting rules.
4. **Migrate.** `migrate/directional.py` produces the preserve and narrow group-policy plans; `migrate/firewall.py` translates to ASA, IOS or FortiOS text;
   `migrate/validate.py` renders the result, parses it back and compares decisions with the source on sampled connections.
5. **Export.** `exports.py` writes worksheets, CSV and Markdown. Narrowed proposals cannot be exported until the observation limits are acknowledged.

## Module map

| Module | Role |
| --- | --- |
| `model.py` | Dataclasses and three-valued matching |
| `evaluate.py` | Ordered evaluation, ACL stages, ASA security levels, PAN-OS defaults, stateless replies |
| `adapters/{cisco,panos,fortios,pfsense}.py`, `registry.py`, `xmlsafe.py`, `common.py` | One adapter per source format; content-based detection; safe XML loading |
| `capture/{reader,flows,appid,zeek}.py` | Packet reading, flow assembly with direction inference, application identification, Zeek logs |
| `adapters/unifi.py` (+ `tools/unifi_export.py`, run separately) | UniFi zone-based firewall JSON to the neutral policy model |
| `capture/fingerprint.py`, `oui.py`, `oui_build.py`, `devices.py` | Passive device identification (`oui_build.py` is the only code that can use the network, on request, in its own process): bounded decoders for ARP/LLDP/DHCP/SNMP/Modbus/EtherNet/IP/HTTP/SSH, the IEEE prefix lookup, and the merge that attributes MACs to IPs with a stated confidence |
| `analysis.py` | Communications, inventory, matrix, explanations, comparison, rule analysis |
| `migrate/{groups,directional,firewall,validate}.py` | Group arithmetic, group-policy plans, destination translation, validation |
| `web/graph.js` | The relationship graph: force layout, pan/zoom/drag, resizable box, drill-down panel (data from `/graph` and `/graph/detail`) |
| `store.py`, `isolate.py`, `jobs.py`, `worker.py`, `server.py`, `service.py`, `exports.py`, `redact.py`, `limits.py`, `netutil.py` | Storage, isolation, HTTP, logic behind the pages, exports, credential redaction, limits, helpers |
| `web/` | The single-page interface |
| `synthetic.py`, `samples/`, `riverbend.py`, `riverbend_configs.py` | Synthetic packet builders, the small demonstration project, and the larger Riverbend example (captures, flow log, five device exports, context) |

## Threat model, in brief

Captures and configuration exports are untrusted files; the browser is not a trusted caller. The full model and tests are in [SECURITY_TEST_PLAN.md](../SECURITY_TEST_PLAN.md).
Highlights: hostile packets (truncated, lying lengths, compression loops) and hostile configs (entity expansion, group cycles and fan-out, huge files) end in a clean message within
limits; text from uploads is never executed, never put into HTML by the page, escaped in Markdown, and neutralised in CSV; credentials are redacted before anything is stored as
evidence; the server is loopback-only, token-protected, checks Host and Origin, and sends a strict Content-Security-Policy; the optional AI path is off by default, sends only parsed
statements marked as untrusted data, and refuses non-HTTP schemes and remote hosts unless asked.

## Optional AI assistance

Off by default. The page can show a *grounded prompt* built only from the tool's own parsed statements (not raw captures or configuration lines), which you can copy anywhere. Starting the
server with `--ai-endpoint URL` additionally lets the page send that prompt to a chat endpoint on this machine (a remote endpoint needs `--ai-allow-remote` and HTTPS). Replies are shown
as text labelled "AI-generated, unverified". The prompt tells the model that the data block is untrusted and may contain text that looks like instructions.
