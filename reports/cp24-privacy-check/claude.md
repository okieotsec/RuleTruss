# Checkpoint 24: a privacy check that runs before a push and in CI

## Findings

* **CP24-01 (process gap, fixed).** CP23 had to replace addresses that had already been published, because nothing checked what left the maintainer's machine. This checkpoint adds the check.
* **What it does.** `tools/privacy_check.py` looks at files, commit messages and commit data for three things: entries on a private deny-list (subnets, hostnames, names and similar), absolute home-directory paths that carry a user name, and a commit author or committer email that is not a GitHub noreply address. It reports only where a problem is and which kind, never the text that matched, because CI logs are public. A file path that itself contains private text is shown as a short id.
* **The deny-list is never in the repository.** It is a private file kept outside every repository (default location `$XDG_CONFIG_HOME/okieotsec/privacy-denylist.txt`), or the text of the CI secret `PRIVACY_DENYLIST`. One entry per line: a subnet or address, a word, or `re:` and a regular expression.
* **Where it runs.**
  * *Before a push:* `tools/install_privacy_hook.sh` installs a git pre-push hook that checks every commit about to be pushed.
  * *In CI:* a new step in the `lint` job runs `--tree`. With the secret set it applies the deny-list; where the secret is not available (pull requests from forks) it applies the built-in checks only.

## What is and is not proven

* 39 new tests use only invented values (a documentation-range subnet and a made-up word) and check that no output ever contains the matched text, that a staged diff is read correctly whatever the maintainer's git diff settings are, and that a private file name is hidden.
* The check was run against this repository's current tree and history with the real deny-list before it was added: the result was the work list that CP23 resolved. After CP23 the tree is clean.
* Not proven: the CI step with the secret set. The secret `PRIVACY_DENYLIST` has to be created by the repository owner; until then CI runs the built-in checks only.

## Tests and tools on the final tree

* Full suite: 651 tests, all passing, including the source hygiene tests (the new files build the text those tests forbid from pieces).
* `tools/security_checks.py` (output beside this report): ruff, bandit, semgrep, gitleaks, pip-audit and osv-scanner all 0 findings; suppression gate 0 findings against the updated baseline. SAF CLI not run.

## Suppressions added / removed, SSDF practices touched

Added 5 inline markers, all for the same reason, and recorded in `security/suppressions.baseline.json` (70 to 75): `subprocess.run` of `git` with a fixed argument list and no shell (`noqa: S603` and `nosec B603` in `tools/privacy_check.py`, `nosec B404` for the import, and `noqa: S603` on two calls in the tests). Every cause that could be removed was: SHA-1 became SHA-256, exceptions are re-raised with `from None`, the git path is looked up once instead of being a partial path. None removed. SSDF: PS.1 (protect repository content from unintended disclosure), PW.7 (reviewed suppressions), PW.8 (tests), PO.3 (a check built into the toolchain).

## Root causes and what keeps them from coming back

* **No check on what leaves the maintainer's machine** (CP23-01 and CP24-01). Prevention: the pre-push hook, with the same script in CI as a backstop.
* **Output that could leak what it detects** (found by the tests while building this: a file name containing private text was printed). Prevention: paths that match are shown as an id, and a test checks every kind of output for the matched text.
* **A change to the check itself could expose the CI secret.** Prevention: `/tools/privacy_check.py` and everything under `.github/` need the owner's review (CODEOWNERS), and the secret is passed only to that one step.

## Limits

* `git push --no-verify` skips the hook; CI is the backstop, and a push that reaches a public branch is already visible.
* Fork pull requests cannot read the secret, so they run the built-in checks only. That is accepted: a fork cannot contain details the maintainer has not already published.
* The deny-list is only as good as its entries; it finds what it is told about.
* No human has reviewed this change.
