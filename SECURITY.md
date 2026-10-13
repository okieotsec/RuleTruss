# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes (pre-release; no public release has been made) |

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, not in a public issue. Use the repository's private vulnerability reporting once it is published. Include the version
(`python -m pbridge --version`), what you did, what you expected and what happened. A synthetic sample file that triggers the problem is the most useful thing to
send. **Never send real captures or real configuration exports.**

## What the application connects to

Nothing. It makes **no outbound connection**. The one exception is the optional AI feature, which is off unless the server is started with `--ai-endpoint`; it then sends a prompt built
from parsed statements to that endpoint only, and refuses non-HTTP(S) schemes, and (without `--ai-allow-remote`) any host that is not this machine. There is no account, telemetry,
analytics, update check, font or script loaded from elsewhere.

## What it listens on

A local HTTP server on `127.0.0.1` (default port 8765). Every API call needs a random access token that is printed when the server starts and exists only for that run. Requests whose
`Host` or `Origin` are not this server are refused, there is no CORS, and responses carry a strict Content-Security-Policy. Binding to any other address needs `--allow-non-loopback` and
is not recommended: there are no user accounts.

## What it reads and writes

* **Files you give it:** captures, flow logs and configuration exports. They are copied into a private data folder (default `~/.local/share/policy-bridge`, or `--data-dir`), mode 0700,
  with files 0600. Each file is parsed in a separate, resource-limited process and never executed.
* **Credentials:** passwords, keys, pre-shared keys and SNMP community strings in exports are redacted from everything stored as evidence, shown, exported or sent to an AI endpoint. The
  original upload is kept as received until you delete it, so protect the data folder like the export itself.
* **Retention:** nothing is deleted automatically unless you start with `--retention-days N`. You can delete a file, a project or all data from the Data & privacy tab. Deletion overwrites
  file contents with zeros and then removes them, as a best effort. **That is not a guarantee** on SSDs, copy-on-write or journaling file systems, snapshots or backups.
* **Exports** are written by your browser to where you choose. CSV cells that a spreadsheet could run as formulas are neutralised, and text from uploads is escaped in Markdown.

## Known limitations

* The access token protects against other local users and web pages, not against someone who already controls your account or can read the terminal output.
* Parsing runs in a subprocess with kernel resource limits on Linux and macOS; on Windows only the time limit applies (and Windows has not been tested).
* The XML loader uses the Python standard library after refusing any document with a DOCTYPE or entity declaration (see the accepted semgrep note in `reports/cp0-baseline`).
* The optional AI feature trusts the endpoint you configure with the parsed statements it is sent.

## How it is tested

See [SECURITY_TEST_PLAN.md](SECURITY_TEST_PLAN.md) and the archived reports under [reports/](reports/): static analysis (ruff, bandit, semgrep), secret scanning (gitleaks), dependency scanning
(pip-audit, osv-scanner), an SBOM ([sbom/sbom.cdx.json](sbom/sbom.cdx.json)), hostile-input and resource-limit tests, Hypothesis fuzzing, and tests of the server's access control. One runtime
dependency (dpkt) is pinned with hashes in `requirements.txt`.
