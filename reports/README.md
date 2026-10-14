# Security reports

One folder per checkpoint, each with the raw tool output (`*.json`, `versions.txt`) and the reviewer's report (`claude.md`).

The project was first called Policy Bridge (package `pbridge`) and was renamed RuleTruss (package `ruletruss`) after `cp2-release-candidate`.
The `cp0`, `cp1` and `cp2` folders are kept exactly as they were produced, so file paths and names inside them use the old names.

`cp5-device-identification` covers passive device identification (MAC, OUI, self-reported identity).
`cp6-vendor-names` covers the move from a bundled IEEE snapshot to a user-requested download.
`cp7-large-captures` covers adjustable size limits, background imports and the stored-analysis size fix.
`cp8-unifi` covers the UniFi zone-based firewall import and its export helper.
`cp9-security-framework` covers the security process: NIST SSDF and MITRE SAF alignment, the suppression gate, CI hardening.
`cp10-interface-and-training` covers the interface rework, tab prerequisites and the training guide.
`cp11-unifi-asa-translation` covers the zone-pair to ASA translation redesign after an external review.
`cp12-batfish-cross-check` covers an independent check of that translation with Batfish in a locked-down container.
`cp13-fuzzing` covers the Atheris fuzzing of the configuration, capture, Zeek and UniFi translation parsers and the four bugs it found.
`cp14-zap-scan` covers the OWASP ZAP scan of the local web server in a networkless pod and the one gap it found.
`cp15-codex-review` covers a read-only review of the code by a different AI model (Codex): 17 findings, all confirmed by a failing test first and then fixed.
