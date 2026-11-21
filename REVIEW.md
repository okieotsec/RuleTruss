# Review log

This file records what the maintainer reviewed and tested by hand before each release, and the decisions made on security findings. It exists so that the statements in the README and `SECURITY.md` can be checked against something.

**What this is not.** It is a review by the maintainer, who is not independent of the project. It is not a third-party audit, and none has been done.

## How a review is done

* Changes written by the AI coding assistant are read as differences, with the assistant explaining each change until the maintainer understands what it does. The maintainer decides whether it is accepted.
* The maintainer runs the program by hand before a release, including testing the limits of its protections (for example size caps and malformed input), and checks that the output is what was intended.
* Every security finding (from scanners, from AI reviews, or found by hand) gets a determination from the maintainer: fixed, accepted with a reason, or false positive with a reason. Findings and determinations are tracked in a private DefectDojo instance; a summary goes in the table below for each release.
* Work is planned and tracked in a private Vikunja board, and the maintainer marks it complete.

## Release record

A structured record starts with the first release after October 2026. Earlier releases were reviewed and tested the same way, but nothing was written down at the time.

| Date | Release | What was read | What was tested by hand | Findings decided | Sign-off |
| --- | --- | --- | --- | --- | --- |
| | | | | | |

## Written later, from memory and chat history (November 2026)

These entries are reconstructed. They are not contemporaneous records, and they are not complete.

* 2026-10-13: tried to load a capture of about 3 GB, which tested the size limits in practice.
* 2026-10-14: questioned how the Configuration tab treated UniFi's predefined policies (Block Invalid Traffic, Allow All Traffic, Block All Traffic); the evaluation was corrected afterwards.
* 2026-10-15: took part in the test of the generated ASA configuration on a virtual ASA (see CP17).
* 2026-10-21: reviewed a scanner finding against the running program, tested the over-limit message, and decided it was a false positive with a stated reason (see CP14).
