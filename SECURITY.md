# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes (pre-release; no public release has been made) |

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, not in a public issue. Use the repository's private vulnerability reporting once it is published. Include the version
(`python -m ruletruss --version`), what you did, what you expected and what happened. A synthetic sample file that triggers the problem is the most useful thing to
send. **Never send real captures or real configuration exports.**

This is a small project maintained by one person on a best-effort basis. These are targets, not guarantees:

| Step | Target |
| --- | --- |
| Acknowledge your report | within 7 days |
| Confirm it by reproducing it, and tell you whether it is accepted | within 14 days |
| Fix a Critical or High issue in the supported version | within 30 days of confirmation |
| Fix a Medium issue | within 90 days of confirmation |
| Lower-severity issues | in a later release, or documented as accepted with the reason |

Severity follows the rubric in [SECURITY_TEST_PLAN.md](SECURITY_TEST_PLAN.md) section 7; a finding is fixed or accepted only after it has been reproduced. When a fix is released, the report is published as a GitHub security advisory and you are credited if you wish. There is no bug bounty.

## What the application connects to

Nothing, unless you ask. It makes **no outbound connection of its own**. There are two exceptions, both off until you act. (1) The **vendor-name download**: the *Download from the IEEE* button on Data & privacy starts a separate resource-limited process that fetches three public CSV files from `standards-oui.ieee.org` (HTTPS only, redirects only within `ieee.org`, size and time limits), keeps each prefix and organisation name, and sends nothing about you or your files; it is held back to once per five minutes. (2) The optional AI feature, which is off unless the server is started with `--ai-endpoint`; it then sends a prompt built
from parsed statements to that endpoint only, and refuses non-HTTP(S) schemes, and (without `--ai-allow-remote`) any host that is not this machine. There is no account, telemetry,
analytics, update check, font or script loaded from elsewhere.

A separate helper, `tools/unifi_export.py`, contacts a UniFi gateway only when you run it yourself, with read-only GET requests to the host you name; the RuleTruss server never does. It takes the API key from the environment or a file, can pin the gateway's certificate fingerprint, and writes its output readable by you only, without the key.

## What it listens on

A local HTTP server on `127.0.0.1` (default port 8765). Every API call needs a random access token that is printed when the server starts and exists only for that run. Requests whose
`Host` or `Origin` are not this server are refused, there is no CORS, and responses carry a strict Content-Security-Policy. Binding to any other address needs `--allow-non-loopback` and
is not recommended: there are no user accounts.

## What it reads and writes

* **Files you give it:** captures, flow logs and configuration exports. They are copied into a private data folder (default `~/.local/share/ruletruss`, or `--data-dir`), mode 0700,
  with files 0600. Each file is parsed in a separate, resource-limited process and never executed.
* **Credentials:** passwords, keys, pre-shared keys and SNMP community strings in exports are redacted from everything stored as evidence, shown, exported or sent to an AI endpoint. The
  original upload is kept as received until you delete it, so protect the data folder like the export itself.
* **Retention:** nothing is deleted automatically unless you start with `--retention-days N`. You can delete a file, a project or all data from the Data & privacy tab. Deletion overwrites
  file contents with zeros and then removes them, as a best effort. **That is not a guarantee** on SSDs, copy-on-write or journaling file systems, snapshots or backups.
* **Device identification** reads MAC addresses and text that devices send about themselves (LLDP, DHCP, SNMP, HTTP, SSH, Modbus, EtherNet/IP) from captures, in the parsing subprocess. That text is cut to printable ASCII of bounded length, is shown only as text, and is neutralised in CSV and escaped in Markdown. It is never trusted as fact and is labelled as self-reported. SNMP community strings are skipped, not stored. The IEEE vendor-name table is not shipped with RuleTruss: it is downloaded on request into the data folder (mode 0600), the downloaded CSV is parsed in the resource-limited process with every row validated and every name cleaned and clipped, and a damaged or oversized table is treated as absent. Without it the application works and simply shows no card-maker names.
* **Exports** are written by your browser to where you choose. CSV cells that a spreadsheet could run as formulas are neutralised, and text from uploads is escaped in Markdown.

## Known limitations

* The access token protects against other local users and web pages, not against someone who already controls your account or can read the terminal output.
* The size limits (file size, packets, flows, time, memory) are what stop a hostile file from exhausting the machine. They can be raised only at start-up, never through the API or by a file, each has a hard ceiling, and the analysis process receives them from the server rather than reading any setting of its own. A server started with large limits is exposed to correspondingly larger denial-of-service attempts from files you import, so raise them only as far as needed. Imports of big files run as background jobs (in memory, two at a time, cancellable), and an upload is refused if it would leave under 1 GB of disk free.
* Parsing runs in a subprocess with kernel resource limits on Linux and macOS; on Windows only the time limit applies (and Windows has not been tested).
* The XML loader uses the Python standard library after refusing any document with a DOCTYPE or entity declaration (see the accepted semgrep note in `reports/cp0-baseline`).
* The optional AI feature trusts the endpoint you configure with the parsed statements it is sent.

## How it is tested

See [SECURITY_TEST_PLAN.md](SECURITY_TEST_PLAN.md) and the archived reports under [reports/](reports/): static analysis (ruff, bandit, semgrep, CodeQL), secret scanning (gitleaks), dependency scanning
(pip-audit, osv-scanner), a review of every in-source suppression, an audit of the build workflows (zizmor), an SBOM ([sbom/sbom.cdx.json](sbom/sbom.cdx.json)), hostile-input and resource-limit tests, Hypothesis fuzzing, and tests of the server's access control. One runtime
dependency (dpkt) is pinned with hashes in `requirements.txt`. The same checks run in continuous integration and again every week once the repository is published.

The practices are mapped to the NIST Secure Software Development Framework and MITRE's Security Automation Framework in [docs/SECURITY_FRAMEWORKS.md](docs/SECURITY_FRAMEWORKS.md), including what is not yet done. That page is the developer's own assessment, not an audit or a certification. **No independent security review has been done yet**, and the local web server has not been scanned with a dynamic tool.
