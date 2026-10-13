# RuleTruss

*by OkieOTSec*

A local-first, self-hostable workbench that helps network and security people **understand existing communications** and **migrate security policy** between products, without buying any particular vendor's hardware.

It reads packet captures, flow logs and firewall / router / switch exports; explains in plain language who talks to whom, who started it, on what, and what the existing rules permit; compares the two; and produces **reviewable** proposals: directional group-policy worksheets and rules for another firewall. It never touches live equipment.

![Inventory](docs/images/inventory.png)

> Status: version 0.1.0, pre-release. The adapters are tested against synthetic fixtures, not against real exports from every software version (see [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md)). Nothing here is endorsed by or certified with any vendor.

## What it does

* **Explains communications.** Devices and subnets, a filterable communication list, a who-initiated-to-whom matrix, a directional graph. Every statement carries its evidence (packet numbers, config lines or rule ids) and its confidence. Example, as the application writes it:
  > 10.20.1.15 (labelled "Engineering workstation") initiated 1 TCP connection to 10.30.2.40 (labelled "PLC-1") on destination port 44818. EtherNet/IP was identified from packet decoding (decoded EtherNet/IP encapsulation header (command RegisterSession, length 4 matches the data, session 0x0) in packet 28).

  If only the port is known it says the protocol is *possible*. It never infers what a device is from its traffic, and never reads silence in a capture as absence.
* **Infers initiation honestly.** A TCP SYN gives high confidence; a mid-stream capture, one-way UDP or an ambiguous exchange gets medium, low or unknown, with the reasons. Replies are never counted as reverse initiation.
* **Reads configurations** from Cisco ASA, Cisco IOS/IOS-XE ACLs, Palo Alto PAN-OS, Fortinet FortiOS and pfSense/OPNsense into one vendor-neutral model, resolving nested objects, keeping provenance, and reporting (never ignoring) what it cannot evaluate: applications, identities, schedules, FQDN objects and more.
* **Compares observed with configured.** Which rule would permit or deny each observed connection, which allow rules matched nothing (not "unused"), and shadowed, redundant, conflicting and over-broad rules.
* **Proposes policies, in two clearly labelled workflows.** *Preserve* what is configured, or *propose narrower* permissions from what was observed (with the observation period, held-back uncertain directions, and an acknowledgement before export). Output is either **directional group policies** (From groups may *initiate* to To groups; the reverse is its own policy; a separate external-egress policy type), or **rules for another firewall** (Cisco ASA, Cisco IOS, FortiOS).
* **Never silently widens.** A condition the destination cannot express blocks the rule and says why, instead of becoming "any". Group aggregation that grants pairs nothing supported, lost restrictions, and deny rules that cannot be carried over are all counted in a verdict line.
* **Validates the migration** by rendering the destination text, parsing it back and comparing allow/deny decisions on sampled connections, classifying any difference, and printing why this does not prove equivalence.

## Supported formats

| Kind | Supported now | Not yet |
| --- | --- | --- |
| Packet captures | PCAP, PCAPNG (Ethernet, raw IP, Linux cooked, loopback; IPv4, IPv6, VLAN) | |
| Flow records | Zeek conn.log (TSV, JSON lines) | NetFlow/IPFIX, firewall traffic logs |
| Configuration sources | Cisco ASA, Cisco IOS/IOS-XE ACLs, PAN-OS XML, FortiOS CLI, pfSense and OPNsense config.xml | Cisco FTD, Juniper SRX, Check Point |
| Destination rules | Cisco ASA, Cisco IOS, FortiOS | PAN-OS, SRX, Check Point, pfSense |
| Directional group policy | Worksheets (Markdown, JSON, CSV) | Native import files (the model is this project's own, not any product's format) |

Details, the candidates considered and the versions the fixtures stand for: [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md). Official documents behind each vendor behaviour, and what could not be verified: [docs/SOURCES.md](docs/SOURCES.md).

## Setup

Needs Python 3.12 or newer, on Linux or macOS. One runtime dependency (dpkt), installed with hash checking.

```bash
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.txt
.venv/bin/python -m ruletruss          # prints an address with a one-time access token
```

Open the printed address (`http://127.0.0.1:8765/#token=...`) in your browser. Everything is stored in `~/.local/share/ruletruss` (change with `--data-dir`). Nothing leaves the machine. To try it with no files of your own, press **Create the Riverbend example** on the Import tab (see *Example data* below).

Options: `--port`, `--data-dir`, `--retention-days N` (delete old projects at start), `--ai-endpoint URL` (optional, off by default; see [SECURITY.md](SECURITY.md)). A container or reverse proxy is not needed, and the server refuses non-loopback addresses unless you pass `--allow-non-loopback`.

## Using it

1. **Import** captures and exports (drag and drop). Say where a capture was taken; the tool never guesses.
2. **Groups & labels:** define subnets (with the zone or interface name a rule would use), label devices, and define groups. Endpoints can be in several groups.
3. **Inventory, Communications, Graph:** read what was seen.
4. **Configuration and Compare:** read what is configured and how it meets what was seen.
5. **Migrate:** build directional group policies (preserve or narrower), or translate to another firewall and read the validation.
6. **Export:** worksheets and configuration text for review. Delete anything on **Data & privacy**.

## Example data

You do not need your own captures or exports to understand the design. Two synthetic data sets are included, all fictional:

* **[samples/riverbend/](samples/riverbend/)**: a fictional water-treatment plant with **three captures taken at different points** (a clean span, a sparse DMZ tap, a capture that started mid-conversation), a **Zeek flow log**, and **five device exports in five formats** (Cisco ASA, PAN-OS, FortiOS, Cisco IOS ACLs, pfSense), plus `context.json` (subnets, labels and groups). It is built to show every idea in the tool, including where the tool says *I cannot tell*. Start with **[samples/riverbend/GUIDE.md](samples/riverbend/GUIDE.md)**, which lists what to look for, where, and why it matters; each point in it is checked by an automated test. Load it with one button, or import the files by hand.
* **[samples/small/](samples/small/)**: one capture, one flow log and one configuration per format; quicker to read.

Regenerate both with `python tools/make_samples.py`.

## Walkthrough, with real outputs

[docs/WALKTHROUGH.md](docs/WALKTHROUGH.md) takes the synthetic sample from input files to explanations to exports, regenerated from the application code by `tools/make_demo.py`. The full output files are in [docs/demo/](docs/demo/); sample inputs are in [samples/small/](samples/small/).

| | |
| --- | --- |
| ![Communications](docs/images/comms.png) | ![Compare](docs/images/compare.png) |
| ![Graph](docs/images/graph.png) | ![Migrate](docs/images/migrate.png) |

## Architecture in one paragraph

A small Python server (standard library plus dpkt) serves a vanilla-JavaScript page under a strict Content-Security-Policy. Each upload is parsed in a separate, resource-limited process into the vendor-neutral model: *observed* flows, *configured* rules and *proposed* plans are kept in separate structures and labelled everywhere. Evaluation is three-valued, so "cannot tell" is never confused with "no". Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); the schema and the directional model: [docs/MODEL.md](docs/MODEL.md).

## Tests and validation

* **291 automated tests**, all passing (`python -m unittest discover -s tests -t .`, about 70 seconds): object and nested-group resolution, ordered rules and implicit deny, stateful replies versus reverse initiation, stateless return requirements, NAT address context, IPv6/UDP/ICMP, shadowed/conflicting/disabled rules, group aggregation, unsupported applications/identities/schedules, hostile files and resource limits, fuzzing, the server's access control, and the interface in a real headless browser (25 checks).
* **Migration validation evidence:** [docs/VALIDATION.md](docs/VALIDATION.md) lists every fixture translated to every other destination and compared on sampled connections, including the differences found and why.
* **Security testing** follows [SECURITY_TEST_PLAN.md](SECURITY_TEST_PLAN.md); reports are archived in [reports/](reports/). One runtime dependency, with an [SBOM](sbom/sbom.cdx.json).
* The browser tests and screenshots run in headless Chromium with no display, so no window ever opens on your desktop.

## Limitations and what is next

Read [docs/LIMITATIONS_AND_ROADMAP.md](docs/LIMITATIONS_AND_ROADMAP.md). The short version: application, identity and schedule conditions are reported but not evaluated; FQDN objects are not resolved; translations are proposals that have not been loaded onto a device; the validation uses this tool's own evaluator on both sides; observed traffic is not business need; and directional rules are not a complete zero trust architecture.

## Licence and brand

The code is MIT licensed ([LICENSE](LICENSE)). The OkieOTSec name and logo in `assets/brand/` and `ruletruss/web/brand/` are not part of that licence; see [assets/brand/README.md](assets/brand/README.md). A fork must use its own name and logo.
