# Gatekeeper Protocol SDK — Compliance & Legal Reference

**Version:** 0.1.0  
**Issued by:** Vertexpace  
**Classification:** Public  

---

## 1. Purpose

This document explains what the Gatekeeper Protocol SDK provides, what it proves cryptographically, what it does not prove, and how organisations can use it to satisfy human-oversight obligations under major AI governance frameworks.

---

## 2. What the SDK Does

The Gatekeeper Protocol SDK inserts a mandatory, human-in-the-loop gate between an AI system's proposal and its execution.

The flow is:

1. **Propose.** The AI system calls `GatekeeperSession::propose(description, payload)`. This computes a BLAKE3 hash of the exact payload (code, command, configuration, or any bytes) and assigns a 16-byte random action ID.

2. **Present.** `request_authorization()` prints a human-readable description and the full payload hash to the operator's terminal and blocks until the operator responds.

3. **Gate.** Only the string `AUTHORIZE` (exact, case-sensitive) causes the action to proceed. Any other input — including `DENY`, a blank line, or EOF — blocks the action.

4. **Sign.** On approval, an `AuthToken` is produced. The token is an Ed25519 signature over:  
   `action_id (16 B) ‖ payload_hash (32 B) ‖ approved_at (8 B, big-endian) ‖ approver_pubkey (32 B)`  
   Total signed message: 88 bytes.

5. **Verify.** Any party holding the original payload can call `verify(token, payload)` to confirm that (a) the signature is valid, (b) the payload hash matches, and (c) the approval timestamp is within 300 seconds of the current time.

6. **Audit.** Every decision — approved or denied — is appended to an in-memory audit log. The log can be exported as a signed JSON file whose integrity is protected by the same Ed25519 keypair.

### Cryptographic primitives

| Primitive | Library | Version |
|-----------|---------|---------|
| Ed25519 signing & verification | `ed25519-dalek` | 2.x |
| BLAKE3 payload hashing | `blake3` | 1.x |
| Nonce generation | `rand::rngs::OsRng` | 0.8.x |

These primitives match the `lumina-hive/dna` library used in the Lumina security stack, ensuring interoperability.

---

## 3. What an AuthToken Proves

An `AuthToken` is cryptographically binding evidence of the following facts:

| Claim | How it is enforced |
|-------|--------------------|
| A specific human typed `AUTHORIZE` | The token is only produced on that exact stdin input; the signing key never leaves the operator's process. |
| The human approved a specific payload | The BLAKE3 hash of the payload is embedded in the signed message; any byte change invalidates the token. |
| Approval occurred at a specific time | `approved_at` (Unix epoch seconds) is embedded in the signed message. |
| The approver holds a specific key | `approver_pubkey` is embedded in the signed message and verified against the Ed25519 signature. |
| The token has not been tampered with | Flipping any bit in `action_id`, `payload_hash`, `approved_at`, `approver_pubkey`, or `signature` causes `verify()` to return `false`. |

---

## 4. What an AuthToken Does Not Prove

Procurement and legal teams should note the following limitations:

| Limitation | Explanation |
|------------|-------------|
| Identity of the human operator | The token proves key possession, not identity. Bind the key to an identity through your organisation's PKI or certificate authority. |
| Authority of the approver | The SDK does not enforce role-based authorisation. Implement your own authorisation policy on top of the `approver_pubkey`. |
| Absence of coercion or error | The token proves `AUTHORIZE` was typed; it does not prove the operator read and understood the description. |
| Payload intelligibility | The human is shown the description and hash, not necessarily the full payload. For high-risk actions, pipe the payload to a human-readable renderer before calling `propose`. |
| Irrevocability | Tokens expire after 300 seconds by default. There is no revocation registry in v0.1; implement one at the application layer if required. |
| Non-repudiation at law | Cryptographic non-repudiation requires a legally-recognised binding between the key and a natural person. Consult your legal counsel. |

---

## 5. Regulatory Framework Alignment

### 5.1 EU AI Act — Article 14 (Human Oversight)

Article 14 of the EU AI Act requires that high-risk AI systems be designed and developed such that they can be effectively overseen by natural persons during their use. Specifically, Article 14(4) requires that natural persons can intervene and interrupt the AI system.

**How the Gatekeeper Protocol addresses Article 14:**

- **14(4)(a) — Understand capabilities and limitations:** The `description` field surfaces a human-readable summary of every proposed action before execution. Operators can use this to understand what the system is about to do.
- **14(4)(b) — Awareness of automation bias:** The blocking stdin gate makes each decision an active, deliberate act. There is no default-to-approve behaviour.
- **14(4)(c) — Correctly interpret output:** The payload hash gives the operator a tamper-evident fingerprint of the exact artefact being approved.
- **14(4)(d) — Decide not to use the system:** Any input other than `AUTHORIZE` blocks the action. The system cannot proceed without explicit human authorisation.
- **14(4)(e) — Intervene or interrupt:** The gate can be embedded at any point in an AI pipeline. Interruption is the default; approval is the exception.

The `AuditEntry` log with signed JSON export provides the documentation trail required for conformity assessments under Article 9 (risk management) and Article 12 (logging).

---

### 5.2 NIST AI Risk Management Framework (AI RMF)

#### GOVERN 1.2 — Accountability Structures

GOVERN 1.2 calls for clear accountability structures for AI risks, including documented roles and responsibilities for human oversight.

The Gatekeeper `approver_pubkey` creates a persistent, cryptographically-bound record of which key (and therefore which operator, when the key is linked to an identity) approved each action. Combined with the signed audit export, this supports the accountability documentation required by GOVERN 1.2.

#### MANAGE 2.4 — Interventions and Containment

MANAGE 2.4 addresses the ability to intervene, contain, and reverse AI system actions when risks are identified.

The Gatekeeper gate is the intervention point. Because the gate blocks execution, AI-proposed actions are naturally contained until human approval is granted. The 300-second token expiry means approvals cannot be pre-staged and reused hours later — reducing the window for stale or out-of-context authorisations.

---

### 5.3 ISO/IEC 42001:2023 — Clause 8.4 (Human Oversight)

ISO/IEC 42001 Clause 8.4 requires that organisations establish processes to ensure an appropriate level of human oversight for AI systems, commensurate with the level of risk.

The Gatekeeper Protocol provides a composable building block for Clause 8.4 compliance:

- **Process:** The `propose → request_authorization → verify` flow is a defined, repeatable process that can be integrated into any AI system's operational procedures.
- **Documentation:** The signed JSON audit export satisfies the documentation and record-keeping requirements implicit in Clause 8.4 and Clause 9 (performance evaluation).
- **Scalability:** Oversight intensity can be tuned: all actions, high-risk actions only, or statistical sampling — by choosing where in the AI pipeline to insert the gate.

---

## 6. Audit Trail Usage

The signed JSON audit file produced by `export_audit_json()` has the following structure:

```json
{
  "entries": [
    {
      "action": {
        "id":           "<hex>",
        "description":  "<human-readable description>",
        "payload_hash": "<blake3 hex>",
        "proposed_at":  1234567890
      },
      "outcome": {
        "outcome": "Approved",
        "token": { ... }
      },
      "recorded_at": 1234567891
    }
  ],
  "signer_pubkey": "<hex>",
  "signature":     "<hex>"
}
```

The `signature` field covers the UTF-8 bytes of the serialised `entries` array. Verifying the signature against `signer_pubkey` confirms that the log has not been modified after export.

**Recommended audit retention procedures:**

1. Export the audit JSON at the end of each session or operational period.
2. Store the file in an append-only log store (e.g., AWS CloudTrail, Azure Monitor, an immutable S3 bucket, or a WORM drive).
3. Retain the `signer_pubkey` separately from the audit file so that it can be used to re-verify the file's integrity at any future date.
4. For high-risk AI systems, timestamp the audit file with a qualified electronic timestamp service (RFC 3161) at time of export to establish a legally-defensible creation time.

---

## 7. Integration Guidance

### Minimum viable integration

```rust
let mut session = GatekeeperSession::new();
let action      = session.propose("Description of what AI will do", &payload_bytes);
let token       = session.request_authorization(&action)?;
// token is Some(AuthToken) only if operator typed AUTHORIZE
execute_if_authorised(token, &payload_bytes);
```

### Persistent key (recommended for production)

```rust
let mut session = GatekeeperSession::from_keyfile(Path::new("/etc/gatekeeper/session.key"))?;
```

A persistent key ensures that the `approver_pubkey` in every `AuthToken` is stable across process restarts, which is necessary for cross-session audit verification.

### Verify before acting (defence-in-depth)

Always call `verify(token, payload)` immediately before executing the action, even within the same process that issued the token. This ensures that in-memory corruption or replay attacks are caught.

---

## 8. Versioning and Stability

This document covers SDK version 0.1.0. The following are considered stable API surfaces:

- The `AuthToken` JSON schema (field names and encoding).
- The Ed25519 signing message format (88-byte layout documented in §2).
- The `AuditEntry` JSON schema.

The following may change in minor versions:

- The CLI argument format.
- The Python SDK's pure-Python fallback behaviour.
- Default token TTL (currently 300 seconds).

---

*Gatekeeper Protocol SDK is provided as infrastructure. It is the responsibility of the integrating organisation to ensure that the key management, identity binding, and operational procedures surrounding this SDK meet their specific regulatory obligations.*
