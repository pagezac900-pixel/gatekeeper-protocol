# Prior Art Disclosure — The Gatekeeper Protocol

**Inventor:** Zac Page (Vertexpace)
**First public disclosure:** June 2026 (this repository, git commit history)
**Status:** Public technical disclosure establishing prior art.

This document is a defensive publication. It places the following inventions
into the public record so that the techniques described here cannot be validly
patented by any other party after this date. The git commit history of this
repository provides a cryptographically timestamped record of first disclosure.

---

## Invention — Cryptographically-enforced human authorization for AI actions

A method for proving that a specific human authorized a specific AI-proposed
action at a specific time, comprising:

1. **Proposal** — an AI system constructs a `PendingAction` containing a
   human-readable description and a content hash (BLAKE3) of the exact payload
   to be executed (e.g. code to compile, a command to run, data to process).

2. **Gate** — the proposed action and its payload hash are presented to a human,
   and execution is blocked until the human supplies an exact authorization
   token (the literal string "AUTHORIZE"). Any other input denies the action.
   This gate is not configurable away; it is structural.

3. **Signed proof** — upon authorization, the system emits an `AuthToken` — an
   Ed25519-signed record binding: the action's unique identifier, the payload
   hash, the approval timestamp, and the approver's public key. The signature
   makes the token unforgeable and independently verifiable.

4. **Verification** — any third party, with only the token and the original
   payload, can verify: that the signature is valid, that the payload hash
   matches (proving the human approved THIS exact payload, not a substitute),
   and that the approval falls within a configurable validity window.

5. **Tamper evidence** — every proposal and outcome (approved, denied) is
   recorded in a signed audit log, producing a defensible record of human
   oversight.

**Novel aspect:** Prior approaches to AI human oversight rely on UI affordances,
policy documents, or logging — none of which produce a cryptographic, third-party-
verifiable proof that a named human approved a specific AI action. This invention
makes "a human authorized this" a mathematically provable fact rather than an
assertion. It maps directly to regulatory requirements for human oversight of
AI systems (e.g. EU AI Act Article 14, NIST AI RMF, ISO/IEC 42001 §8.4).

---

## Reference Implementation (in this repository)

- `src/lib.rs` — the Rust library (GatekeeperSession, PendingAction, AuthToken)
- `src/bin/gatekeeper.rs` — command-line tool (propose / verify / audit)
- `python/` — Python bindings
- `COMPLIANCE.md` — mapping to AI-governance frameworks

Published under the MIT License on the date recorded in this repository's git
history. 15 tests pass, including signature verification, tamper detection, and
expiry enforcement.

---

*This disclosure is made to protect these inventions by placing them in the
public domain as prior art. Vertexpace asserts authorship and first disclosure.*
