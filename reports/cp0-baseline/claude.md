Reviewer: Claude Code (developer and reviewer)
Checkpoint / commit: CP0 baseline, run on the tree at commit 10005d2 (hostile-input and fuzz tests included)
Tools run (with versions): ruff 0.16.10, bandit 1.9.4, semgrep 1.180.0 (p/python, p/security-audit, metrics off), gitleaks (full history), pip-audit 2.10.1, osv-scanner 2.5.1. Raw output is in this folder.
Tools not run (and why): mitmproxy and a hostile TLS server (the application makes no outbound connection except the optional, default-off AI call, which is tested with a local fake endpoint); atheris coverage-guided fuzzing (Hypothesis property tests were used instead; see CP2).

Tool results
- ruff 0, bandit 0, gitleaks 0, pip-audit 0, osv-scanner 0 (one runtime dependency, dpkt 1.9.8).
- semgrep 3 (raw output kept in semgrep.json):

Finding S-01
- Title: stdlib XML parser flagged (use-defused-xml)
- Severity: Info after analysis (tool rated it ERROR)
- Location: pbridge/adapters/xmlsafe.py:3
- Description: xml.etree.ElementTree is used for PAN-OS and pfSense/OPNsense exports.
- Evidence / reproduction: tests/test_malicious.py (billion laughs, external entity, deep nesting, 10,000-deep, unclosed, 3 MB attribute) and tests/test_panos.py::XmlSafetyTests all end in a refusal or clean error. The loader rejects any DOCTYPE, ENTITY, ELEMENT or ATTLIST before parsing, bounds depth and element count, and runs in a subprocess limited to 2 GB of memory and 600 s.
- Recommended fix / decision: ACCEPTED with documented reasoning (avoids a third-party runtime dependency; defusedxml remains an option on the roadmap). Annotated in code with `nosemgrep` and the reason.
- Confidence: Confirmed

Finding S-02
- Title: dynamic urllib use (dynamic-urllib-use-detected)
- Severity: Low after analysis
- Location: pbridge/service.py:364 (optional AI endpoint)
- Description: urllib is called with a URL taken from the --ai-endpoint option.
- Evidence / reproduction: the scheme is restricted to http/https and non-local hosts need --ai-allow-remote and https before the call; tests/test_server.py::AiAssistanceTests tries file:, ftp:, gopher:, a remote https host and a remote http host. The option exists only on the command line of whoever starts the server; it is not reachable from the browser or from any uploaded file.
- Recommended fix / decision: ACCEPTED, annotated with the reason.
- Confidence: Confirmed

Finding S-03
- Title: 0o700 reported as widely permissive (insecure-file-permissions)
- Severity: Info (false positive)
- Location: pbridge/store.py:111
- Description: os.chmod(data_dir, 0o700) is owner-only; a directory needs the execute bit.
- Evidence: tests/test_server.py::AccessControlTests::test_the_data_folder_is_private asserts mode 0700; every stored file is 0600 (UploadAndDeletionTests).
- Recommended fix / decision: CLOSED as a false positive, annotated.
- Confidence: Confirmed
