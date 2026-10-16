# Checkpoint 20: the first release bundle, built and verified

Tag `v0.1.0` (annotated, pushed by the owner) on commit `056b1aa`. Release workflow run 38827619917.

## What ran

All steps passed: the tag check (the tag equals the version in the code), the hash-checked installs, the whole test suite on the runner, the bundle build (`git archive`), the provenance attestation,
and the upload of a `release-bundle` artifact (1.8 MB: `ruletruss-0.1.0.tar.gz`, `ruletruss-0.1.0.sbom.cdx.json`, `ruletruss-0.1.0.sha256`). No GitHub release has been created; the workflow cannot create one.

## Verification, done from a downloaded copy in a scratch folder

* `sha256sum -c ruletruss-0.1.0.sha256`: both files OK.
* `gh attestation verify ruletruss-0.1.0.tar.gz --repo okieotsec/RuleTruss`: exit status 0 (the command prints nothing when its output is not a terminal; `--format json` shows the detail). One attestation, SLSA provenance v1,
  covering the tarball and the SBOM; repository `okieotsec/RuleTruss`; ref `refs/tags/v0.1.0`; source commit `056b1aa2a815…`, which is the commit the tag points to; signer workflow `release.yml@refs/tags/v0.1.0`;
  GitHub-hosted runner; push trigger; issuer GitHub's token service. The tarball digest in the attestation equals the checksum of the downloaded file (`d1861ee062c0a9f3…`).

## What this shows and does not show

It shows that the file was produced by this repository's release workflow from that tag and commit, and was not altered afterwards. It does not show that the code is free of bugs or that anyone reviewed it
(no person has; two AI reviews and the scanners have). The `CHANGELOG.md` inside the bundle still says "0.1.0 (unreleased)", because it was tagged before the date was filled in; the next release should update the
date first. The workflow artifact expires after 90 days, so the verified files should be attached to a GitHub release (by the owner) to be downloadable later; the attestation stays valid for the same bytes.

## Tests and tools

`tools/security_checks.py` output beside this report; the full suite passed on the runner as part of the workflow and locally (567 tests).

## After the verification (same day)

At the owner's request the GitHub release and settings were done through the `gh` tool logged in as the owner's account:

* A ruleset for `v*` tags (no creation, update, deletion or force push except by the repository admin) and a ruleset for `main` (no deletion or force push, the seven CI and security checks required, admin bypass).
* The GitHub **pre-release** `v0.1.0` with the three verified files and notes that repeat the README's status; the files were then downloaded from the public release page and verified again (checksums OK, attestation exit status 0), and the tag still points to the verified commit.
* Topics, Wiki and Projects off, "require actions pinned to a commit SHA" on, Dependabot security updates on (private vulnerability reporting, secret scanning and push protection were already on).
* **Not done:** dismissing the two code-scanning alerts (#12, the `mcp` vulnerability that CI never reaches, and #8, code review with a single maintainer). The tool blocked the action, rightly: accepting a risk is the owner's decision. The reasons are written in `reports/cp19-first-github-run/claude.md`.
